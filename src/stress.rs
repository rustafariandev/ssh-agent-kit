//! Stress tests: an agent used from many threads at once, with random mixes
//! of requests, watched for hangs and checked for the invariants it keeps
//! however requests interleave.
//!
//! Each test runs for `STRESS_MS` milliseconds (750 by default); raise it
//! for a soak. The seed is printed, and `STRESS_SEED` replays it (as far as
//! thread scheduling allows).

use crate::agent::tests::{ed25519, local_key, sign_body};
use crate::cert::CertKey;
use crate::testing::MemoryBackend;
use crate::{
    Agent, Backend, BoxError, Confirm, ConfirmRequest, Connection, Extension, ExtensionContext,
    ExtensionReply, KeyDecodeError, KeyDecoder, Lifecycle, Locker, PassphraseLock, Removed,
    SignerRef, SmartcardProvider, wire,
};
use ssh_encoding::{Decode, Encode};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Barrier, Mutex, OnceLock, Weak};
use std::thread::{JoinHandle, sleep};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// How long a worker may go without finishing an operation before the
/// watchdog calls it a deadlock.
const HANG_AFTER: Duration = Duration::from_secs(5);

fn run_for() -> Duration {
    let ms = std::env::var("STRESS_MS")
        .ok()
        .and_then(|ms| ms.parse().ok())
        .unwrap_or(750);
    Duration::from_millis(ms)
}

fn seed() -> u64 {
    let seed = std::env::var("STRESS_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });
    eprintln!("STRESS_SEED={seed}");
    seed
}

/// xorshift64, seeded through splitmix64 so nearby seeds diverge.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Rng((z ^ (z >> 31)) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Sleep up to `micros`, to shift where threads meet.
    fn pause(&mut self, micros: u64) {
        sleep(Duration::from_micros(self.next() % (micros + 1)));
    }
}

/// Sleep a little in user code, to widen the windows it is called in.
fn jitter() {
    static STATE: AtomicU64 = AtomicU64::new(1);
    let n = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, SeqCst);
    sleep(Duration::from_micros(Rng::new(n).next() % 300));
}

/// What a worker is given on each round: its random numbers, and where to
/// say what it is doing, for the watchdog to report if it never returns.
struct Step {
    rng: Rng,
    doing: Arc<Mutex<&'static str>>,
}

impl Step {
    fn doing(&self, op: &'static str) {
        *self.doing.lock().unwrap() = op;
    }
}

type Work = Box<dyn FnMut(&mut Step) + Send>;

fn worker(
    name: &'static str,
    work: impl FnMut(&mut Step) + Send + 'static,
) -> (&'static str, Work) {
    (name, Box::new(work))
}

struct Running {
    name: &'static str,
    doing: Arc<Mutex<&'static str>>,
    progress: Arc<AtomicU64>,
    thread: JoinHandle<()>,
    seen: u64,
    moved: Instant,
}

/// Run `workers` together for [`run_for`], each calling its work in a loop,
/// and fail if any panics or stops making progress for [`HANG_AFTER`].
fn stress(workers: Vec<(&'static str, Work)>) {
    stress_for(seed(), run_for(), workers);
}

/// [`stress`] with a given seed and duration.
fn stress_for(seed: u64, duration: Duration, workers: Vec<(&'static str, Work)>) {
    let stop = Arc::new(AtomicBool::new(false));
    let start = Arc::new(Barrier::new(workers.len() + 1));
    let mut running: Vec<Running> = workers
        .into_iter()
        .enumerate()
        .map(|(index, (name, mut work))| {
            let doing = Arc::new(Mutex::new("starting"));
            let progress = Arc::new(AtomicU64::new(0));
            let thread = {
                let (stop, start) = (Arc::clone(&stop), Arc::clone(&start));
                let mut step = Step {
                    rng: Rng::new(seed ^ (index as u64).wrapping_mul(0xA24B_AED4_963E_E407)),
                    doing: Arc::clone(&doing),
                };
                let progress = Arc::clone(&progress);
                std::thread::Builder::new()
                    .name(name.into())
                    .spawn(move || {
                        start.wait();
                        while !stop.load(SeqCst) {
                            work(&mut step);
                            progress.fetch_add(1, SeqCst);
                        }
                    })
                    .unwrap()
            };
            Running {
                name,
                doing,
                progress,
                thread,
                seen: 0,
                moved: Instant::now(),
            }
        })
        .collect();

    start.wait();
    let deadline = Instant::now() + duration;
    for worker in &mut running {
        worker.moved = Instant::now();
    }
    loop {
        sleep(Duration::from_millis(20));
        if Instant::now() >= deadline {
            stop.store(true, SeqCst);
        }
        let mut stuck = Vec::new();
        let mut done = true;
        for worker in &mut running {
            if worker.thread.is_finished() {
                // One that panicked stops the rest.
                stop.store(true, SeqCst);
                continue;
            }
            done = false;
            let progress = worker.progress.load(SeqCst);
            if progress != worker.seen {
                worker.seen = progress;
                worker.moved = Instant::now();
            } else if worker.moved.elapsed() > HANG_AFTER {
                stuck.push(format!(
                    "`{}` in `{}`",
                    worker.name,
                    worker.doing.lock().unwrap()
                ));
            }
        }
        if !stuck.is_empty() {
            stop.store(true, SeqCst);
            // The stuck threads are left behind: joining them would hang.
            panic!(
                "deadlock suspected, no progress for {HANG_AFTER:?}: {} (STRESS_SEED={seed})",
                stuck.join(", ")
            );
        }
        if done {
            break;
        }
    }
    for worker in running {
        if let Err(panic) = worker.thread.join() {
            eprintln!("worker `{}` panicked (STRESS_SEED={seed})", worker.name);
            std::panic::resume_unwind(panic);
        }
    }
}

/// Run `f` on a thread of its own and fail if it takes longer than
/// [`HANG_AFTER`].
fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || done.send(f()));
    finished
        .recv_timeout(HANG_AFTER)
        .unwrap_or_else(|_| panic!("deadlock suspected: {what} did not return"))
}

// Request bodies.

#[derive(Debug, Default, Clone, Copy)]
struct Limits {
    confirm: bool,
    lifetime: Option<u32>,
    hidden: bool,
}

const CONFIRM: Limits = Limits {
    confirm: true,
    lifetime: None,
    hidden: false,
};

const HIDDEN: Limits = Limits {
    confirm: false,
    lifetime: None,
    hidden: true,
};

fn constraints(limits: Limits, body: &mut Vec<u8>) {
    if let Some(secs) = limits.lifetime {
        wire::SSH_AGENT_CONSTRAIN_LIFETIME.encode(body).unwrap();
        secs.encode(body).unwrap();
    }
    if limits.confirm {
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(body).unwrap();
    }
    if limits.hidden {
        body.extend_from_slice(&wire::tests::destination_extension());
    }
}

fn blob(seed: u8) -> Vec<u8> {
    local_key(seed, "stress").1.to_bytes().unwrap()
}

/// `ssh-add` of the ed25519 key from `seed`, under `limits`.
fn add(seed: u8, limits: Limits) -> Vec<u8> {
    let (mut body, _) = local_key(seed, "stress");
    let mut constrained = Vec::new();
    constraints(limits, &mut constrained);
    if !constrained.is_empty() {
        body[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        body.extend_from_slice(&constrained);
    }
    body
}

fn remove(blob: &[u8]) -> Vec<u8> {
    let mut body = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
    blob.encode(&mut body).unwrap();
    body
}

fn remove_all() -> Vec<u8> {
    vec![wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]
}

fn list() -> Vec<u8> {
    vec![wire::SSH2_AGENTC_REQUEST_IDENTITIES]
}

fn sign(blob: &[u8]) -> Vec<u8> {
    sign_body(blob, b"stress")
}

fn lock(passphrase: &[u8]) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_LOCK];
    passphrase.encode(&mut body).unwrap();
    body
}

fn unlock(passphrase: &[u8]) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_UNLOCK];
    passphrase.encode(&mut body).unwrap();
    body
}

/// `ssh-add -s provider`, under `limits` and with `certs` attached.
fn smartcard(provider: &str, limits: Limits, certs: &[CertKey]) -> Vec<u8> {
    let mut constrained = Vec::new();
    constraints(limits, &mut constrained);
    if !certs.is_empty() {
        wire::SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut constrained)
            .unwrap();
        crate::cert::ASSOCIATED_CERTS
            .encode(&mut constrained)
            .unwrap();
        0u8.encode(&mut constrained).unwrap();
        let mut blobs = Vec::new();
        for cert in certs {
            cert.blob().encode(&mut blobs).unwrap();
        }
        blobs.encode(&mut constrained).unwrap();
    }
    let mut body = vec![match constrained.is_empty() {
        true => wire::SSH_AGENTC_ADD_SMARTCARD_KEY,
        false => wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
    }];
    provider.encode(&mut body).unwrap();
    "".encode(&mut body).unwrap();
    body.extend_from_slice(&constrained);
    body
}

fn smartcard_remove(provider: &str) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
    provider.encode(&mut body).unwrap();
    "".encode(&mut body).unwrap();
    body
}

fn extension(name: &str) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_EXTENSION];
    name.encode(&mut body).unwrap();
    body
}

fn signed(reply: &[u8]) -> bool {
    reply.first() == Some(&wire::SSH2_AGENT_SIGN_RESPONSE)
}

/// The key blobs in an identities answer.
fn listed(reply: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
    let mut rest = &reply[1..];
    let count = u32::decode(&mut rest).unwrap();
    (0..count)
        .map(|_| {
            let blob = Vec::<u8>::decode(&mut rest).unwrap();
            let _comment = String::decode(&mut rest).unwrap();
            blob
        })
        .collect()
}

// Test doubles.

/// Refuses every confirm prompt, counting them.
#[derive(Default)]
struct DenyConfirm(AtomicUsize);

impl Confirm for DenyConfirm {
    fn confirm(&self, _: &ConfirmRequest) -> Option<bool> {
        self.0.fetch_add(1, SeqCst);
        jitter();
        Some(false)
    }
}

/// Smartcard providers named by `cards`, each serving one key, which list
/// the keys they serve as a backend. Adding and removing take a moment.
struct Cards {
    keys: MemoryBackend,
    cards: Vec<(&'static str, SignerRef)>,
}

impl Cards {
    fn new(cards: &[(&'static str, u8)]) -> Arc<Self> {
        Arc::new(Cards {
            keys: MemoryBackend::default(),
            cards: cards
                .iter()
                .map(|&(name, seed)| (name, ed25519(seed, name)))
                .collect(),
        })
    }

    fn serves(&self, blob: &[u8]) -> bool {
        self.keys
            .identities()
            .iter()
            .any(|key| key.key_blob() == blob)
    }

    /// The backend stops serving `blob` on its own.
    fn drop_key(&self, blob: &[u8]) -> bool {
        Backend::remove(&self.keys, blob)
    }
}

impl SmartcardProvider for Cards {
    fn resolve(&self, provider: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
        jitter();
        self.cards
            .iter()
            .find(|(name, _)| name.as_bytes() == provider)
            .map(|(_, key)| key.clone())
            .ok_or_else(|| "no such card".into())
    }

    fn add(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        _: Option<u32>,
    ) -> Result<(), BoxError> {
        let key = self.resolve(provider, pin)?;
        jitter();
        let mut keys = self.keys.0.lock().unwrap();
        if !keys.iter().any(|k| k.key_blob() == key.key_blob()) {
            keys.push(key);
        }
        Ok(())
    }

    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
        let key = self.resolve(provider, &Zeroizing::new(Vec::new()))?;
        jitter();
        Ok(Removed {
            served: Backend::remove(&self.keys, &key.key_blob()),
            key_blob: Some(key.key_blob()),
        })
    }
}

impl Backend for Cards {
    fn identities(&self) -> Vec<SignerRef> {
        self.keys.identities()
    }

    fn remove_all(&self) {
        jitter();
        self.keys.remove_all();
    }
}

/// The agent a test double calls back into, set once it is built.
#[derive(Default)]
struct Back(OnceLock<Weak<Agent>>);

impl Back {
    fn set(&self, agent: &Arc<Agent>) {
        self.0.set(Arc::downgrade(agent)).unwrap();
    }

    fn agent(&self) -> Option<Arc<Agent>> {
        self.0.get().and_then(Weak::upgrade)
    }
}

type Hook = Box<dyn Fn(&Agent) + Send + Sync>;

/// Records the lifecycle events, and calls back into the agent from them.
#[derive(Default)]
struct Hooks {
    events: Mutex<Vec<&'static str>>,
    back: Back,
    on_unlocked: Option<Hook>,
    on_cleared: Option<Hook>,
}

impl Hooks {
    fn event(&self, event: &'static str, hook: &Option<Hook>) {
        self.events.lock().unwrap().push(event);
        if let (Some(hook), Some(agent)) = (hook, self.back.agent()) {
            hook(&agent);
        }
    }
}

impl Lifecycle for Hooks {
    fn locked(&self) {
        self.event("locked", &None);
    }

    fn unlocked(&self) {
        self.event("unlocked", &self.on_unlocked);
    }

    fn cleared(&self) {
        self.event("cleared", &self.on_cleared);
    }
}

// Hangs.

/// Every kind of request, from many threads, against an agent with a
/// backend, a smartcard provider, a confirm prompt, hooks and an extension.
#[test]
fn mixed_churn_never_hangs() {
    struct Echo;
    impl Extension for Echo {
        fn name(&self) -> &str {
            "echo@example.com"
        }
        fn handle(&self, _: &ExtensionContext, _: &[u8]) -> ExtensionReply {
            ExtensionReply::Success
        }
    }

    let cards = Cards::new(&[("card0", 0x20), ("card1", 0x21)]);
    let backend = Arc::new(MemoryBackend::new([ed25519(0x22, "backend")]));
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&backend) as _)
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _)
            .with_confirm(Arc::new(DenyConfirm::default()))
            .with_lifecycle(Arc::new(Hooks::default()))
            .with_unlock_backoff(Duration::from_millis(1))
            .with_extension(Echo),
    );
    let seeds = [0x23u8, 0x24, 0x25, 0x26];
    let blobs: Vec<Vec<u8>> = seeds
        .iter()
        .map(|&s| blob(s))
        .chain([blob(0x20), blob(0x21), blob(0x22)])
        .collect();

    let churn = |agent: Arc<Agent>, blobs: Vec<Vec<u8>>| {
        let mut connection = Connection::default();
        move |step: &mut Step| {
            let rng = &mut step.rng;
            let seed = *rng.pick(&seeds);
            let limits = Limits {
                confirm: rng.chance(30),
                lifetime: rng.chance(20).then_some(1),
                hidden: rng.chance(20),
            };
            let card = *rng.pick(&["card0", "card1"]);
            let body = match rng.below(14) {
                0 | 1 => {
                    step.doing("add");
                    add(seed, limits)
                }
                2 | 3 => {
                    step.doing("remove");
                    remove(step.rng.pick(&blobs))
                }
                4 => {
                    step.doing("remove all");
                    remove_all()
                }
                5..=7 => {
                    step.doing("sign");
                    sign(step.rng.pick(&blobs))
                }
                8 => {
                    step.doing("list");
                    list()
                }
                9 => {
                    step.doing("lock");
                    lock(b"pw")
                }
                10 => {
                    step.doing("unlock");
                    unlock(if step.rng.chance(70) { b"pw" } else { b"no" })
                }
                11 => {
                    step.doing("add smartcard");
                    smartcard(card, limits, &[])
                }
                12 => {
                    step.doing("remove smartcard");
                    smartcard_remove(card)
                }
                _ => {
                    step.doing("extension");
                    extension(if step.rng.chance(50) {
                        "echo@example.com"
                    } else {
                        "nope@example.com"
                    })
                }
            };
            if step.rng.chance(5) {
                connection = Connection::default();
            }
            agent.handle_in(&body, &mut connection);
        }
    };
    let mut workers: Vec<_> = (0..8)
        .map(|_| worker("churn", churn(Arc::clone(&agent), blobs.clone())))
        .collect();
    let ticker = Arc::clone(&agent);
    workers.push(worker("tick", move |step| {
        step.doing("purge");
        ticker.purge_expired();
        step.doing("identities");
        ticker.identities();
        step.rng.pause(1000);
    }));
    stress(workers);

    within("a final listing", move || {
        agent.unlock(b"pw");
        agent.handle(&list())
    });
}

/// The public key-change calls, which commit without a turn, racing the
/// same changes asked for over the protocol.
#[test]
fn public_mutators_race_with_requests() {
    let agent = Arc::new(Agent::new().with_confirm(Arc::new(DenyConfirm::default())));
    let (confirmed, hidden, plain) = (0x30u8, 0x31u8, 0x32u8);
    let key = ed25519(plain, "plain");
    let cert = crate::testing::certify(key.public_key().key_data());

    let mut workers = Vec::new();
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("requests", move |step| {
            let (op, body) = match step.rng.below(5) {
                0 => ("add -c", add(confirmed, CONFIRM)),
                1 => ("add -h", add(hidden, HIDDEN)),
                2 => (
                    "remove",
                    remove(&blob(*step.rng.pick(&[confirmed, hidden, plain]))),
                ),
                3 => ("remove all", remove_all()),
                _ => ("add", add(plain, Limits::default())),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    for _ in 0..2 {
        let (agent, key, cert) = (Arc::clone(&agent), key.clone(), cert.clone());
        workers.push(worker("public", move |step| match step.rng.below(5) {
            0 => {
                step.doing("add_key");
                agent.add_key(key.clone(), step.rng.chance(20).then_some(1));
            }
            1 => {
                step.doing("add_cert_key");
                agent.add_cert_key(key.clone(), cert.clone(), None);
            }
            2 => {
                step.doing("remove_cert");
                agent.remove_cert(cert.blob());
            }
            3 => {
                step.doing("release");
                agent.release(&key.key_blob(), step.rng.chance(50));
            }
            _ => {
                step.doing("remove_key");
                agent.remove_key(&blob(*step.rng.pick(&[confirmed, hidden, plain])));
            }
        }));
    }
    let signer = Arc::clone(&agent);
    workers.push(worker("sign -c", move |step| {
        step.doing("sign");
        assert!(
            !signed(&signer.handle(&sign(&blob(confirmed)))),
            "a confirm-constrained key signed"
        );
    }));
    let lister = Arc::clone(&agent);
    let mut poisoned = Connection::default();
    let _ = poisoned.bind(key.public_key().clone(), b"sid", b"not a signature", false);
    workers.push(worker("list hidden", move |step| {
        step.doing("list");
        let shown = listed(&lister.handle_in(&list(), &mut poisoned));
        assert!(
            !shown.contains(&blob(hidden)),
            "a destination-constrained key was listed"
        );
    }));
    stress(workers);
}

/// Extensions and key types registered while requests use them.
#[test]
fn runtime_registration_under_load() {
    struct Named(&'static str, Back);
    impl Extension for Named {
        fn name(&self) -> &str {
            self.0
        }
        fn handle(&self, _: &ExtensionContext, _: &[u8]) -> ExtensionReply {
            // Call back in, with no lock held.
            if let Some(agent) = self.1.agent() {
                agent.handle(&list());
            }
            ExtensionReply::Success
        }
    }
    struct Ed25519;
    impl KeyDecoder for Ed25519 {
        fn key_types(&self) -> &[&str] {
            &["ssh-ed25519"]
        }
        fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<SignerRef, KeyDecodeError> {
            crate::local::decode(key_type, reader).map(SignerRef::new)
        }
    }

    const NAMES: [&str; 3] = ["a@example.com", "b@example.com", "c@example.com"];
    let agent = Arc::new(Agent::new());
    let registered = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    {
        let (agent, registered) = (Arc::clone(&agent), Arc::clone(&registered));
        workers.push(worker("register", move |step| {
            let back = Back::default();
            back.set(&agent);
            let index = step.rng.below(NAMES.len());
            step.doing("register extension");
            agent.register_extension(Named(NAMES[index], back));
            registered.fetch_or(1 << index, SeqCst);
            step.doing("register key type");
            agent.register_key_type(Ed25519);
        }));
    }
    for _ in 0..4 {
        let (agent, registered) = (Arc::clone(&agent), Arc::clone(&registered));
        workers.push(worker("use", move |step| {
            let index = step.rng.below(NAMES.len());
            let was = registered.load(SeqCst) & (1 << index) != 0;
            step.doing("extension");
            let reply = agent.handle(&extension(NAMES[index]));
            if was {
                assert_eq!(reply, wire::success(), "a registered extension was lost");
            }
            step.doing("add");
            agent.handle(&add(0x40 + step.rng.below(4) as u8, Limits::default()));
            step.doing("remove");
            agent.handle(&remove(&blob(0x40 + step.rng.below(4) as u8)));
        }));
    }
    stress(workers);
}

/// A hook that runs during one turn and asks for the other, while another
/// thread holds that other turn and its hook asks for the first: a key
/// change's `cleared` hook locking the agent while an unlock's `unlocked`
/// hook adds a key.
#[test]
fn cross_turn_hooks_do_not_deadlock() {
    let hooks = Arc::new(Hooks {
        on_cleared: Some(Box::new(|agent: &Agent| {
            agent.lock(b"pw");
            agent.unlock(b"pw");
        })),
        on_unlocked: Some(Box::new(|agent: &Agent| {
            agent.handle(&add(0x50, Limits::default()));
        })),
        ..Hooks::default()
    });
    let agent = Arc::new(Agent::new().with_lifecycle(Arc::clone(&hooks) as _));
    hooks.back.set(&agent);
    cross_turns(agent);
}

/// As [`cross_turn_hooks_do_not_deadlock`], with the backend's
/// `remove_all` locking the agent.
#[test]
fn a_backend_clearing_may_lock() {
    struct Relocking(Back);
    impl Backend for Relocking {
        fn identities(&self) -> Vec<SignerRef> {
            Vec::new()
        }
        fn remove_all(&self) {
            if let Some(agent) = self.0.agent() {
                agent.lock(b"pw");
                agent.unlock(b"pw");
            }
        }
    }
    let backend = Arc::new(Relocking(Back::default()));
    let hooks = Arc::new(Hooks {
        on_unlocked: Some(Box::new(|agent: &Agent| {
            agent.handle(&add(0x51, Limits::default()));
        })),
        ..Hooks::default()
    });
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&backend) as _)
            .with_lifecycle(Arc::clone(&hooks) as _),
    );
    backend.0.set(&agent);
    hooks.back.set(&agent);
    cross_turns(agent);
}

/// As [`cross_turn_hooks_do_not_deadlock`], with a smartcard provider's
/// `add` locking the agent while an `unlocked` hook adds a smartcard key.
#[test]
fn a_provider_adding_may_lock() {
    struct Relocking(Arc<Cards>, Back);
    impl SmartcardProvider for Relocking {
        fn resolve(
            &self,
            provider: &[u8],
            pin: &Zeroizing<Vec<u8>>,
        ) -> Result<SignerRef, BoxError> {
            self.0.resolve(provider, pin)
        }
        fn add(
            &self,
            provider: &[u8],
            pin: &Zeroizing<Vec<u8>>,
            lifetime: Option<u32>,
        ) -> Result<(), BoxError> {
            if let Some(agent) = self.1.agent() {
                agent.lock(b"pw");
                agent.unlock(b"pw");
            }
            self.0.add(provider, pin, lifetime)
        }
        fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
            SmartcardProvider::remove(&*self.0, provider)
        }
    }
    let cards = Cards::new(&[("card", 0x52)]);
    let provider = Arc::new(Relocking(Arc::clone(&cards), Back::default()));
    let hooks = Arc::new(Hooks {
        on_unlocked: Some(Box::new(|agent: &Agent| {
            agent.handle(&smartcard("card", Limits::default(), &[]));
        })),
        ..Hooks::default()
    });
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&provider) as _)
            .with_lifecycle(Arc::clone(&hooks) as _),
    );
    provider.1.set(&agent);
    hooks.back.set(&agent);
    let changer = Arc::clone(&agent);
    stress(vec![
        worker("add smartcard", move |step| {
            step.doing("add smartcard");
            changer.handle(&smartcard("card", Limits::default(), &[]));
            step.doing("remove smartcard");
            changer.handle(&smartcard_remove("card"));
        }),
        worker("lock", move |step| {
            step.doing("lock");
            agent.lock(b"pw");
            step.doing("unlock");
            agent.unlock(b"pw");
        }),
    ]);
}

/// One thread clears the agent while another locks and unlocks it.
fn cross_turns(agent: Arc<Agent>) {
    let changer = Arc::clone(&agent);
    stress(vec![
        worker("remove all", move |step| {
            step.doing("add");
            changer.handle(&add(0x5f, Limits::default()));
            step.doing("remove all");
            changer.handle(&remove_all());
        }),
        worker("lock", move |step| {
            step.doing("lock");
            agent.lock(b"pw");
            step.doing("unlock");
            agent.unlock(b"pw");
        }),
    ]);
}

/// A locker slow to say whether it is locked, which every request and key
/// change asks, holds up neither reads nor changes for long.
#[test]
fn a_slow_locker_does_not_stall_requests() {
    #[derive(Default)]
    struct Slow(PassphraseLock);
    impl Locker for Slow {
        fn is_locked(&self) -> bool {
            jitter();
            self.0.is_locked()
        }
        fn lock(&self, passphrase: &[u8]) -> bool {
            jitter();
            self.0.lock(passphrase)
        }
        fn unlock(&self, passphrase: &[u8]) -> bool {
            jitter();
            self.0.unlock(passphrase)
        }
    }
    let agent = Arc::new(
        Agent::new()
            .with_locker(Arc::new(Slow::default()))
            .with_unlock_backoff(Duration::from_millis(1)),
    );
    let mut workers = Vec::new();
    for _ in 0..3 {
        let agent = Arc::clone(&agent);
        workers.push(worker("change", move |step| {
            let seed = 0x60 + step.rng.below(3) as u8;
            step.doing("add");
            agent.handle(&add(seed, Limits::default()));
            step.doing("remove");
            agent.handle(&remove(&blob(seed)));
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("read", move |step| {
            step.doing("list");
            agent.handle(&list());
            step.doing("identities");
            agent.identities();
        }));
    }
    workers.push(worker("lock", move |step| {
        step.doing("lock");
        agent.handle(&lock(b"pw"));
        step.rng.pause(500);
        step.doing("unlock");
        agent.handle(&unlock(b"pw"));
    }));
    stress(workers);
}

/// Clients over a real socket, with the server's ticker expiring keys,
/// connections dropped mid-frame and more than the server will take at
/// once; the server still shuts down promptly.
#[test]
fn server_churn_with_ticker() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let (listener, guard) = crate::bind_socket(&path).unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let agent = Arc::new(Agent::new());
    let server = {
        let (agent, shutdown) = (Arc::clone(&agent), Arc::clone(&shutdown));
        std::thread::spawn(move || {
            let _guard = guard;
            crate::serve(listener, agent, shutdown)
        })
    };

    let answered = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let (path, answered) = (path.clone(), Arc::clone(&answered));
        workers.push(worker("client", move |step| {
            step.doing("connect");
            let Ok(mut stream) = UnixStream::connect(&path) else {
                return;
            };
            // Longer than the watchdog, so a hang is reported as one.
            let timeout = Some(HANG_AFTER * 2);
            stream.set_read_timeout(timeout).unwrap();
            stream.set_write_timeout(timeout).unwrap();
            for _ in 0..=step.rng.below(5) {
                let seed = 0x70 + step.rng.below(4) as u8;
                let lifetime = Limits {
                    lifetime: Some(1),
                    ..Limits::default()
                };
                let (op, body) = match step.rng.below(5) {
                    0 => ("add -t", add(seed, lifetime)),
                    1 => ("remove", remove(&blob(seed))),
                    2 => ("sign", sign(&blob(seed))),
                    3 => ("list", list()),
                    _ => ("bad request", vec![0xee]),
                };
                step.doing(op);
                if step.rng.chance(5) {
                    // Drop the connection partway through a frame.
                    let _ = stream.write_all(&(body.len() as u32 + 8).to_be_bytes());
                    let _ = stream.write_all(&body);
                    return;
                }
                if wire::write_frame(&mut stream, &body).is_err() {
                    return; // Turned away at the connection cap.
                }
                match wire::read_frame(&mut stream) {
                    Ok(Some(_)) => answered.fetch_add(1, SeqCst),
                    Ok(None) => return,
                    Err(wire::FrameError::Io(e)) if e.kind() != std::io::ErrorKind::WouldBlock => {
                        return;
                    }
                    Err(e) => panic!("{op}: {e}"),
                };
            }
        }));
    }
    let hoard_path = path.clone();
    workers.push(worker("hoard", move |step| {
        step.doing("hoard connections");
        let held: Vec<_> = (0..140)
            .filter_map(|_| UnixStream::connect(&hoard_path).ok())
            .collect();
        step.rng.pause(20_000);
        drop(held);
        step.rng.pause(100_000);
    }));
    stress(workers);
    assert!(answered.load(SeqCst) > 0, "no request was answered");

    within("a request after the churn", {
        let path = path.clone();
        move || {
            let mut stream = UnixStream::connect(&path).unwrap();
            wire::write_frame(&mut stream, &list()).unwrap();
            wire::read_frame(&mut stream).unwrap().unwrap()
        }
    });
    shutdown.store(true, SeqCst);
    within("the server's shutdown", move || server.join().unwrap()).expect("the server failed");
}

// Invariants.

/// Keys only ever added with `ssh-add -c`, locally or from a smartcard,
/// never sign without a confirm, however adds, removals, re-serving and a
/// backend dropping a key interleave.
#[test]
fn confirm_keys_never_sign_unconfirmed() {
    let cards = Cards::new(&[("card0", 0x80), ("card1", 0x81)]);
    let confirm = Arc::new(DenyConfirm::default());
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _)
            .with_confirm(Arc::clone(&confirm) as _),
    );
    let local = [0x82u8, 0x83];
    let blobs: Vec<Vec<u8>> = [0x80, 0x81, 0x82, 0x83].map(blob).to_vec();

    let mut workers = Vec::new();
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("add", move |step| {
            let card = *step.rng.pick(&["card0", "card1"]);
            let (op, body) = match step.rng.below(2) {
                0 => ("add -c", add(*step.rng.pick(&local), CONFIRM)),
                _ => ("add smartcard -c", smartcard(card, CONFIRM, &[])),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    {
        let (agent, blobs) = (Arc::clone(&agent), blobs.clone());
        workers.push(worker("remove", move |step| {
            let card = *step.rng.pick(&["card0", "card1"]);
            let (op, body) = match step.rng.below(5) {
                0 => ("remove all", remove_all()),
                1 | 2 => ("remove smartcard", smartcard_remove(card)),
                _ => ("remove", remove(step.rng.pick(&blobs))),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    {
        let (agent, cards) = (Arc::clone(&agent), Arc::clone(&cards));
        workers.push(worker("backend drops", move |step| {
            let blob = &blobs[step.rng.below(2)];
            step.doing("drop and release");
            let served = cards.drop_key(blob);
            if served {
                agent.release(blob, served);
            }
            step.rng.pause(2000);
        }));
    }
    for _ in 0..3 {
        let agent = Arc::clone(&agent);
        workers.push(worker("sign", move |step| {
            let seed = 0x80 + step.rng.below(4) as u8;
            step.doing("sign");
            assert!(
                !signed(&agent.handle(&sign(&blob(seed)))),
                "key {seed:#x}, only added with -c, signed without a confirm"
            );
        }));
    }
    stress(workers);
}

/// Keys only ever added with `ssh-add -h` are never listed to, nor sign
/// for, a connection their constraint rules out.
#[test]
fn hidden_keys_stay_hidden() {
    let cards = Cards::new(&[("card", 0x90)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );
    assert_eq!(
        agent.handle(&smartcard("card", HIDDEN, &[])),
        wire::success()
    );
    // Index 0 is the smartcard key, 1 and 2 are added locally.
    let local = [0x91u8, 0x92];
    let hidden: Vec<Vec<u8>> = [0x90, 0x91, 0x92].map(blob).to_vec();

    let mut workers = Vec::new();
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("add", move |step| {
            let (op, body) = match step.rng.below(2) {
                0 => ("add -h", add(*step.rng.pick(&local), HIDDEN)),
                _ => ("add smartcard -h", smartcard("card", HIDDEN, &[])),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    {
        let (agent, hidden) = (Arc::clone(&agent), hidden.clone());
        workers.push(worker("remove", move |step| {
            let (op, body) = match step.rng.below(4) {
                0 => ("remove all", remove_all()),
                1 => ("remove smartcard", smartcard_remove("card")),
                _ => ("remove", remove(step.rng.pick(&hidden))),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    for _ in 0..3 {
        let (agent, hidden) = (Arc::clone(&agent), hidden.clone());
        let mut poisoned = Connection::default();
        let host = ed25519(0x9f, "host").public_key().clone();
        let _ = poisoned.bind(host, b"sid", b"not a signature", false);
        workers.push(worker("hidden connection", move |step| {
            step.doing("list");
            let shown = listed(&agent.handle_in(&list(), &mut poisoned));
            let leaked = hidden.iter().position(|blob| shown.contains(blob));
            assert_eq!(leaked, None, "hidden key {leaked:?} was listed");
            step.doing("identities_for");
            let shown = agent.identities_for(&poisoned);
            let leaked = hidden
                .iter()
                .position(|blob| shown.iter().any(|(b, _)| b == blob));
            assert_eq!(leaked, None, "hidden key {leaked:?} was listed");
            step.doing("sign");
            let index = step.rng.below(hidden.len());
            assert!(
                !signed(&agent.handle_in(&sign(&hidden[index]), &mut poisoned)),
                "hidden key {index} signed"
            );
        }));
    }
    stress(workers);
}

/// A request made wholly while the agent is locked is refused, or lists
/// nothing. The locker counts an odd epoch only between its lock returning
/// and its unlock starting; a request that saw the same odd epoch before
/// and after was made in that window.
#[test]
fn a_locked_agent_refuses_everything() {
    let cards = Cards::new(&[("card", 0xa0)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );
    let epoch = Arc::new(AtomicU64::new(0));
    let plain = 0xa1u8;
    assert_eq!(
        agent.handle(&add(plain, Limits::default())),
        wire::success()
    );

    let mut workers = Vec::new();
    for _ in 0..4 {
        let (agent, epoch) = (Arc::clone(&agent), Arc::clone(&epoch));
        workers.push(worker("request", move |step| {
            let (op, body) = match step.rng.below(7) {
                0 => ("list", list()),
                1 => ("sign", sign(&blob(*step.rng.pick(&[plain, 0xa0])))),
                2 => ("add", add(plain, Limits::default())),
                3 => ("remove", remove(&blob(plain))),
                4 => ("add smartcard", smartcard("card", Limits::default(), &[])),
                5 => ("remove smartcard", smartcard_remove("card")),
                _ => ("remove all", remove_all()),
            };
            step.doing(op);
            let before = epoch.load(SeqCst);
            let reply = agent.handle(&body);
            let after = epoch.load(SeqCst);
            if before == after && before % 2 == 1 {
                let refused = match op {
                    "list" => listed(&reply).is_empty(),
                    _ => reply == wire::failure(),
                };
                assert!(refused, "{op} was answered while locked: {reply:?}");
            }
        }));
    }
    workers.push(worker("locker", move |step| {
        step.doing("lock");
        assert!(agent.lock(b"pw"));
        epoch.fetch_add(1, SeqCst);
        step.rng.pause(3000);
        epoch.fetch_add(1, SeqCst);
        step.doing("unlock");
        assert!(agent.unlock(b"pw"));
        step.rng.pause(2000);
    }));
    stress(workers);
}

/// Locks and unlocks from many threads, right and wrong: the hooks hear
/// them strictly alternating, ending as the agent is.
#[test]
fn lock_hooks_alternate() {
    let hooks = Arc::new(Hooks::default());
    let agent = Arc::new(
        Agent::new()
            .with_lifecycle(Arc::clone(&hooks) as _)
            .with_unlock_backoff(Duration::from_millis(1)),
    );
    let workers = (0..6)
        .map(|_| {
            let agent = Arc::clone(&agent);
            worker("lock", move |step| {
                let passphrase: &[u8] = step.rng.pick(&[b"pw".as_slice(), b"other"]);
                match step.rng.below(4) {
                    0 => {
                        step.doing("lock request");
                        agent.handle(&lock(passphrase));
                    }
                    1 => {
                        step.doing("unlock request");
                        agent.handle(&unlock(passphrase));
                    }
                    2 => {
                        step.doing("lock");
                        agent.lock(passphrase);
                    }
                    _ => {
                        step.doing("unlock");
                        agent.unlock(passphrase);
                    }
                }
            })
        })
        .collect();
    stress(workers);

    let events = hooks.events.lock().unwrap();
    assert!(events.len() > 1, "the agent was never locked and unlocked");
    for (index, event) in events.iter().enumerate() {
        let expected = ["locked", "unlocked"][index % 2];
        assert_eq!(*event, expected, "hook {index} of {events:?}");
    }
    assert_eq!(events.last() == Some(&"locked"), agent.is_locked());
}

/// Certificates attached with `ssh-add -s` go with their key: a listing
/// never has the certificate without the key, and once the requests
/// settle, a key no longer served has no certificates.
#[test]
fn certificates_leave_with_their_key() {
    let cards = Cards::new(&[("card", 0xb0)]);
    let key = cards.cards[0].1.clone();
    let key_blob = key.key_blob();
    let cert = crate::testing::certify(key.public_key().key_data());
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );

    let seed = seed();
    let rounds = (run_for().as_millis() / 100).max(5);
    for round in 0..rounds {
        let mut workers = Vec::new();
        {
            let (agent, cert) = (Arc::clone(&agent), cert.clone());
            workers.push(worker("add smartcard", move |step| {
                step.doing("add smartcard");
                agent.handle(&smartcard(
                    "card",
                    Limits::default(),
                    std::slice::from_ref(&cert),
                ));
            }));
        }
        {
            let agent = Arc::clone(&agent);
            workers.push(worker("remove", move |step| {
                let (op, body) = match step.rng.below(4) {
                    0 => ("remove all", remove_all()),
                    _ => ("remove smartcard", smartcard_remove("card")),
                };
                step.doing(op);
                agent.handle(&body);
                step.rng.pause(500);
            }));
        }
        {
            let (agent, cards, key_blob) =
                (Arc::clone(&agent), Arc::clone(&cards), key_blob.clone());
            workers.push(worker("backend drops", move |step| {
                step.doing("drop and release");
                if cards.drop_key(&key_blob) {
                    agent.release(&key_blob, true);
                }
                step.rng.pause(2000);
            }));
        }
        for _ in 0..2 {
            let (agent, cert, key_blob) = (Arc::clone(&agent), cert.clone(), key_blob.clone());
            workers.push(worker("list", move |step| {
                step.doing("list");
                let shown = listed(&agent.handle(&list()));
                if shown.iter().any(|blob| blob == cert.blob()) {
                    assert!(
                        shown.contains(&key_blob),
                        "a certificate was listed without its key"
                    );
                }
            }));
        }
        stress_for(
            seed.wrapping_add(round as u64),
            Duration::from_millis(100),
            workers,
        );

        if !cards.serves(&key_blob) {
            assert!(
                agent.certificates_for(key.public_key()).is_empty(),
                "round {round}: a certificate outlived its key (STRESS_SEED={seed})"
            );
        }
    }
}
