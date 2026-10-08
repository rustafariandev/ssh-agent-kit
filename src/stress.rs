//! Stress tests: an agent used from many threads at once, with random mixes
//! of requests, watched for hangs and checked for the invariants it keeps
//! however requests interleave.
//!
//! Each test runs for `STRESS_MS` milliseconds (750 by default); raise it
//! for a soak. The seed is printed, and `STRESS_SEED` replays it (as far as
//! thread scheduling allows).

use crate::agent::tests::{
    REMEMBERED_CHANGES, ed25519, local_key, sign_body, store_sizes, turns_held,
};
use crate::cert::CertKey;
use crate::testing::MemoryBackend;
use crate::{
    Agent, Backend, BoxError, Confirm, ConfirmRequest, Connection, Extension, ExtensionContext,
    ExtensionReply, KeyDecodeError, KeyDecoder, Lifecycle, ListInfo, Locker, ManageInfo,
    PassphraseLock, Policy, Removed, SignInfo, Signer, SignerRef, SmartcardProvider, wire,
};
use ssh_encoding::{Decode, Encode};
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use std::cell::Cell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Barrier, Condvar, Mutex, OnceLock, Weak};
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

/// Send a key change until it goes through: under churn one may be
/// refused because the keys kept changing while it waited for its turn.
/// Returns how many times it was refused.
fn until_done(agent: &Agent, body: &[u8]) -> usize {
    for refused in 0..1000 {
        if agent.handle(body) == wire::success() {
            return refused;
        }
    }
    panic!("a key change was refused 1000 times in a row");
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

    within("clearing the agent", move || {
        agent.unlock(b"pw");
        assert_eq!(agent.handle(&remove_all()), wire::success());
        assert!(agent.identities().is_empty(), "keys outlived ssh-add -D");
        let (held, attached, remembered) = store_sizes(&agent);
        assert_eq!((held, attached), (0, 0), "the store kept entries");
        assert!(remembered <= REMEMBERED_CHANGES);
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
        sleep(Duration::from_millis(10));
        step.rng.pause(10_000);
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

/// Keys only ever added with `ssh-add -c -t 1` never sign without a
/// confirm, however their expiry, the ticker's purge and re-adds
/// interleave. Runs long enough for lifetimes to run out.
#[test]
fn expiring_confirm_keys_never_sign_unconfirmed() {
    let agent = Arc::new(Agent::new().with_confirm(Arc::new(DenyConfirm::default())));
    let seeds = [0xc0u8, 0xc1, 0xc2];
    let expiring = Limits {
        confirm: true,
        lifetime: Some(1),
        hidden: false,
    };

    // Re-adding a key renews its lifetime, so each key's adder waits it
    // out before adding the key again, at a different point each time.
    let mut workers = Vec::new();
    for seed in seeds {
        let agent = Arc::clone(&agent);
        workers.push(worker("add -c -t 1", move |step| {
            step.doing("add");
            agent.handle(&add(seed, expiring));
            sleep(Duration::from_millis(1000));
            step.rng.pause(300_000);
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("remove", move |step| {
            step.doing("remove");
            agent.handle(&remove(&blob(*step.rng.pick(&seeds))));
            step.rng.pause(2_000_000);
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("purge", move |step| {
            step.doing("purge");
            agent.purge_expired();
            step.rng.pause(5_000);
        }));
    }
    for _ in 0..3 {
        let agent = Arc::clone(&agent);
        workers.push(worker("sign", move |step| {
            let seed = *step.rng.pick(&seeds);
            step.doing("sign");
            assert!(
                !signed(&agent.handle(&sign(&blob(seed)))),
                "key {seed:#x}, only added with -c, signed without a confirm"
            );
        }));
    }
    stress_for(seed(), run_for().max(Duration::from_secs(3)), workers);
}

/// While a key is held with `ssh-add -c`, a backend serving the same key
/// does not sign with it unconfirmed, whatever other keys' changes land
/// meanwhile. One worker alone adds and removes the held copy, counting an
/// odd epoch while it is surely held; a sign made wholly within one must
/// fail. Outside them the backend's copy signs as it is, unconstrained.
#[test]
fn a_backend_copy_keeps_a_held_keys_confirm() {
    let key = ed25519(0xd0, "shared");
    let shared = key.key_blob();
    let cards = Cards::new(&[("other", 0xd1)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::new(MemoryBackend::new([key])))
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );
    let epoch = Arc::new(AtomicU64::new(0));
    let unconfirmed = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    {
        let (agent, epoch) = (Arc::clone(&agent), Arc::clone(&epoch));
        workers.push(worker("holder", move |step| {
            step.doing("add -c");
            until_done(&agent, &add(0xd0, CONFIRM));
            epoch.fetch_add(1, SeqCst);
            sleep(Duration::from_millis(10));
            step.rng.pause(10_000);
            epoch.fetch_add(1, SeqCst);
            step.doing("remove");
            until_done(&agent, &remove(&blob(0xd0)));
            step.rng.pause(2000);
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("churn", move |step| {
            let seed = 0xd2 + step.rng.below(3) as u8;
            let limits = *step.rng.pick(&[CONFIRM, HIDDEN, Limits::default()]);
            let (op, body) = match step.rng.below(4) {
                0 => ("add", add(seed, limits)),
                1 => ("remove", remove(&blob(seed))),
                2 => ("add smartcard", smartcard("other", limits, &[])),
                _ => ("remove smartcard", smartcard_remove("other")),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    for _ in 0..3 {
        let (agent, epoch) = (Arc::clone(&agent), Arc::clone(&epoch));
        let (shared, unconfirmed) = (shared.clone(), Arc::clone(&unconfirmed));
        workers.push(worker("sign", move |step| {
            step.doing("sign");
            let before = epoch.load(SeqCst);
            let reply = agent.handle(&sign(&shared));
            let after = epoch.load(SeqCst);
            if before == after && before % 2 == 1 {
                assert!(!signed(&reply), "the backend copy of a -c key signed");
            } else if signed(&reply) {
                unconfirmed.fetch_add(1, SeqCst);
            }
        }));
    }
    stress(workers);
    assert!(
        unconfirmed.load(SeqCst) > 0,
        "the unconstrained backend key never signed"
    );
}

/// Keys added with `ssh-add -c` answered yes, a policy auditing every
/// signature and a hook counting `ssh-add -D`: each signature made is
/// confirmed once and audited once, no other key is ever confirmed, and
/// the hook hears of every `-D` that succeeded, however requests race.
#[test]
fn every_signature_is_confirmed_and_audited_once() {
    #[derive(Default)]
    struct Counts(Mutex<HashMap<Vec<u8>, usize>>);
    impl Counts {
        fn add(&self, key: Vec<u8>) {
            *self.0.lock().unwrap().entry(key).or_default() += 1;
        }
        fn of(&self, key: &[u8]) -> usize {
            self.0.lock().unwrap().get(key).copied().unwrap_or(0)
        }
    }
    /// Answers yes, counting prompts by fingerprint.
    #[derive(Default)]
    struct Approve(Counts);
    impl Confirm for Approve {
        fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
            self.0.add(request.fingerprint.clone().into_bytes());
            jitter();
            Some(true)
        }
    }
    /// Counts signatures by key.
    #[derive(Default)]
    struct Audit(Counts);
    impl Policy for Audit {
        fn signed(&self, request: &SignInfo<'_>) {
            self.0.add(request.key.to_bytes().unwrap());
        }
    }
    #[derive(Default)]
    struct Cleared(AtomicUsize);
    impl Lifecycle for Cleared {
        fn cleared(&self) {
            self.0.fetch_add(1, SeqCst);
        }
    }

    let (approve, audit, cleared) = (
        Arc::new(Approve::default()),
        Arc::new(Audit::default()),
        Arc::new(Cleared::default()),
    );
    let agent = Arc::new(
        Agent::new()
            .with_confirm(Arc::clone(&approve) as _)
            .with_policy(Arc::clone(&audit) as _)
            .with_lifecycle(Arc::clone(&cleared) as _),
    );
    let confirmed = [0xe0u8, 0xe1];
    let plain = 0xe2u8;
    let signs = Arc::new(Counts::default());
    let clears = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    for _ in 0..2 {
        let (agent, clears) = (Arc::clone(&agent), Arc::clone(&clears));
        workers.push(worker("change", move |step| {
            let seed = *step.rng.pick(&confirmed);
            let (op, body) = match step.rng.below(8) {
                0 | 1 => ("add -c", add(seed, CONFIRM)),
                2 | 3 => ("add", add(plain, Limits::default())),
                4 | 5 => ("remove", remove(&blob(*step.rng.pick(&[seed, plain])))),
                _ => ("remove all", remove_all()),
            };
            step.doing(op);
            if agent.handle(&body) == wire::success() && op == "remove all" {
                clears.fetch_add(1, SeqCst);
            }
        }));
    }
    for _ in 0..4 {
        let (agent, signs) = (Arc::clone(&agent), Arc::clone(&signs));
        workers.push(worker("sign", move |step| {
            let key = blob(*step.rng.pick(&[confirmed[0], confirmed[1], plain]));
            step.doing("sign");
            if signed(&agent.handle(&sign(&key))) {
                signs.add(key);
            }
        }));
    }
    stress(workers);

    let fingerprint = |seed: u8| {
        let public = local_key(seed, "stress").1;
        public
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
            .into_bytes()
    };
    for seed in [confirmed[0], confirmed[1], plain] {
        let made = signs.of(&blob(seed));
        assert_eq!(audit.0.of(&blob(seed)), made, "key {seed:#x}: audited");
        let prompts = approve.0.of(&fingerprint(seed));
        let expected = if seed == plain { 0 } else { made };
        assert_eq!(prompts, expected, "key {seed:#x}: confirm prompts");
    }
    assert_eq!(cleared.0.load(SeqCst), clears.load(SeqCst), "cleared hooks");
}

/// The other side of `ssh-add -h`: a connection that never bound a
/// session, as for local use, is shown the keys whatever other keys'
/// changes land, though, as in OpenSSH, it never signs with them. One
/// worker alone adds and removes them, counting an odd epoch while they
/// are surely served.
#[test]
fn hidden_keys_are_shown_where_allowed() {
    let cards = Cards::new(&[("card", 0xf0), ("other", 0xf1)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );
    let local = 0xf2u8;
    let shown = [blob(0xf0), blob(local)];
    let epoch = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    {
        let (agent, epoch) = (Arc::clone(&agent), Arc::clone(&epoch));
        workers.push(worker("holder", move |step| {
            step.doing("add -h");
            until_done(&agent, &add(local, HIDDEN));
            step.doing("add smartcard -h");
            until_done(&agent, &smartcard("card", HIDDEN, &[]));
            epoch.fetch_add(1, SeqCst);
            sleep(Duration::from_millis(10));
            step.rng.pause(10_000);
            epoch.fetch_add(1, SeqCst);
            step.doing("remove");
            until_done(&agent, &remove(&blob(local)));
            step.doing("remove smartcard");
            until_done(&agent, &smartcard_remove("card"));
            step.rng.pause(1000);
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("churn", move |step| {
            let seed = 0xf3 + step.rng.below(3) as u8;
            let limits = *step.rng.pick(&[CONFIRM, HIDDEN, Limits::default()]);
            let (op, body) = match step.rng.below(4) {
                0 => ("add", add(seed, limits)),
                1 => ("remove", remove(&blob(seed))),
                2 => ("add smartcard", smartcard("other", limits, &[])),
                _ => ("remove smartcard", smartcard_remove("other")),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    for _ in 0..3 {
        let (agent, epoch, shown) = (Arc::clone(&agent), Arc::clone(&epoch), shown.clone());
        workers.push(worker("local connection", move |step| {
            let index = step.rng.below(shown.len());
            let (op, body) = match step.rng.below(2) {
                0 => ("list", list()),
                _ => ("sign", sign(&shown[index])),
            };
            step.doing(op);
            let before = epoch.load(SeqCst);
            let reply = agent.handle(&body);
            let after = epoch.load(SeqCst);
            if op == "sign" {
                assert!(
                    !signed(&reply),
                    "-h key {index} signed on an unbound connection"
                );
            } else if before == after && before % 2 == 1 {
                let listed = listed(&reply);
                for (index, blob) in shown.iter().enumerate() {
                    assert!(listed.contains(blob), "allowed key {index} not listed");
                }
            }
        }));
    }
    stress(workers);
}

/// Whether test doubles panic, and how often (per mille).
struct Panics {
    on: AtomicBool,
    per_mille: u64,
    count: AtomicUsize,
}

impl Panics {
    fn new(per_mille: u64) -> Arc<Self> {
        Arc::new(Panics {
            on: AtomicBool::new(true),
            per_mille,
            count: AtomicUsize::new(0),
        })
    }

    /// Panic now and then, while on.
    fn maybe(&self, what: &str) {
        static STATE: AtomicU64 = AtomicU64::new(7);
        let n = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, SeqCst);
        if self.on.load(SeqCst) && Rng::new(n).next() % 1000 < self.per_mille {
            self.count.fetch_add(1, SeqCst);
            panic!("stress: {what} panicked");
        }
    }
}

/// [`Cards`], every call of which may panic first.
struct PanickyCards(Arc<Cards>, Arc<Panics>);

impl Backend for PanickyCards {
    fn identities(&self) -> Vec<SignerRef> {
        self.1.maybe("Backend::identities");
        self.0.identities()
    }
    fn known(&self) -> Vec<SignerRef> {
        self.1.maybe("Backend::known");
        self.0.known()
    }
    fn remove(&self, key_blob: &[u8]) -> bool {
        self.1.maybe("Backend::remove");
        Backend::remove(&*self.0, key_blob)
    }
    fn remove_all(&self) {
        self.1.maybe("Backend::remove_all");
        self.0.remove_all();
    }
}

impl SmartcardProvider for PanickyCards {
    fn resolve(&self, provider: &[u8], pin: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
        self.1.maybe("SmartcardProvider::resolve");
        self.0.resolve(provider, pin)
    }
    fn add(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
    ) -> Result<(), BoxError> {
        self.1.maybe("SmartcardProvider::add");
        self.0.add(provider, pin, lifetime)?;
        self.1.maybe("SmartcardProvider::add, once added");
        Ok(())
    }
    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
        self.1.maybe("SmartcardProvider::remove");
        SmartcardProvider::remove(&*self.0, provider)
    }
}

/// Allows everything and refuses every confirm, unless it panics first.
struct PanickyUser(Arc<Panics>);

impl Policy for PanickyUser {
    fn allow_sign(&self, _: &SignInfo<'_>) -> bool {
        self.0.maybe("Policy::allow_sign");
        true
    }
    fn signed(&self, _: &SignInfo<'_>) {
        self.0.maybe("Policy::signed");
    }
    fn allow_list(&self, _: &ListInfo<'_>) -> bool {
        self.0.maybe("Policy::allow_list");
        true
    }
    fn allow_manage(&self, _: &ManageInfo<'_>) -> bool {
        self.0.maybe("Policy::allow_manage");
        true
    }
}

impl Confirm for PanickyUser {
    fn confirm(&self, _: &ConfirmRequest) -> Option<bool> {
        self.0.maybe("Confirm::confirm");
        Some(false)
    }
}

impl Lifecycle for PanickyUser {
    fn locked(&self) {
        self.0.maybe("Lifecycle::locked");
    }
    fn unlocked(&self) {
        self.0.maybe("Lifecycle::unlocked");
    }
    fn cleared(&self) {
        self.0.maybe("Lifecycle::cleared");
    }
}

/// [`PassphraseLock`], every call of which may panic first.
struct PanickyLock(PassphraseLock, Arc<Panics>);

impl Locker for PanickyLock {
    fn is_locked(&self) -> bool {
        self.1.maybe("Locker::is_locked");
        self.0.is_locked()
    }
    fn lock(&self, passphrase: &[u8]) -> bool {
        self.1.maybe("Locker::lock");
        self.0.lock(passphrase)
    }
    fn unlock(&self, passphrase: &[u8]) -> bool {
        self.1.maybe("Locker::unlock");
        self.0.unlock(passphrase)
    }
}

/// Every callback the agent makes panics now and then. A panic fails the
/// request it happened in and no more: no turn is left held, on the thread
/// or the agent, no `-c` key signs unconfirmed and no `-h` key is shown
/// to a connection it is hidden from, and once the panics stop every kind
/// of request works again.
#[test]
fn panicking_callbacks_leave_the_agent_working() {
    let panics = Panics::new(20);
    let cards = Cards::new(&[("card", 0xa8), ("hidden", 0xa9)]);
    let card = Arc::new(PanickyCards(Arc::clone(&cards), Arc::clone(&panics)));
    let user = Arc::new(PanickyUser(Arc::clone(&panics)));
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&card) as _)
            .with_smartcard(Arc::clone(&card) as _)
            .with_policy(Arc::clone(&user) as _)
            .with_confirm(Arc::clone(&user) as _)
            .with_lifecycle(Arc::clone(&user) as _)
            .with_locker(Arc::new(PanickyLock(
                PassphraseLock::default(),
                Arc::clone(&panics),
            )))
            .with_unlock_backoff(Duration::from_millis(1)),
    );
    // Only ever added with -c, or only ever with -h.
    let confirmed = [0xaau8, 0xab];
    let hidden = [0xacu8, 0xad];
    let hidden_blobs: Vec<Vec<u8>> = [0xa9, 0xac, 0xad].map(blob).to_vec();

    /// Run one request, a panic in which fails it and leaves no turn held.
    fn request(agent: &Agent, body: &[u8], connection: &mut Connection) -> Option<Vec<u8>> {
        let reply = catch_unwind(AssertUnwindSafe(|| agent.handle_in(body, connection))).ok();
        assert_eq!(turns_held(), 0, "a panic left a turn held");
        reply
    }

    let mut workers = Vec::new();
    for _ in 0..4 {
        let agent = Arc::clone(&agent);
        workers.push(worker("churn", move |step| {
            let (op, body) = match step.rng.below(11) {
                0 => ("add -c", add(*step.rng.pick(&confirmed), CONFIRM)),
                1 => ("add -h", add(*step.rng.pick(&hidden), HIDDEN)),
                2 => ("remove", remove(&blob(*step.rng.pick(&[0xaa, 0xab, 0xac])))),
                3 => ("remove all", remove_all()),
                4 => ("add smartcard -c", smartcard("card", CONFIRM, &[])),
                5 => ("add smartcard -h", smartcard("hidden", HIDDEN, &[])),
                6 => ("remove smartcard", smartcard_remove("card")),
                7 => ("remove hidden smartcard", smartcard_remove("hidden")),
                8 => ("lock", lock(b"pw")),
                9 => ("unlock", unlock(b"pw")),
                _ => ("list", list()),
            };
            step.doing(op);
            request(&agent, &body, &mut Connection::default());
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("sign -c", move |step| {
            let seed = *step.rng.pick(&[0xa8, 0xaa, 0xab]);
            step.doing("sign");
            let reply = request(&agent, &sign(&blob(seed)), &mut Connection::default());
            assert!(
                !reply.is_some_and(|r| signed(&r)),
                "key {seed:#x}, only added with -c, signed without a confirm"
            );
        }));
    }
    for _ in 0..2 {
        let (agent, hidden_blobs) = (Arc::clone(&agent), hidden_blobs.clone());
        let mut poisoned = Connection::default();
        let host = ed25519(0xaf, "host").public_key().clone();
        let _ = poisoned.bind(host, b"sid", b"not a signature", false);
        workers.push(worker("hidden connection", move |step| {
            step.doing("list");
            if let Some(reply) = request(&agent, &list(), &mut poisoned) {
                let shown = listed(&reply);
                let leaked = hidden_blobs.iter().position(|b| shown.contains(b));
                assert_eq!(leaked, None, "hidden key {leaked:?} was listed");
            }
            step.doing("sign");
            let index = step.rng.below(hidden_blobs.len());
            let reply = request(&agent, &sign(&hidden_blobs[index]), &mut poisoned);
            assert!(
                !reply.is_some_and(|r| signed(&r)),
                "hidden key {index} signed"
            );
        }));
    }
    stress(workers);
    assert!(panics.count.load(SeqCst) > 0, "nothing panicked");

    panics.on.store(false, SeqCst);
    within("requests once the panics stopped", move || {
        agent.unlock(b"pw");
        assert!(!agent.is_locked());
        assert_eq!(agent.handle(&remove_all()), wire::success());
        let plain = 0xae;
        assert_eq!(
            agent.handle(&add(plain, Limits::default())),
            wire::success()
        );
        assert!(signed(&agent.handle(&sign(&blob(plain)))));
        assert_eq!(
            agent.handle(&smartcard("card", Limits::default(), &[])),
            wire::success()
        );
        assert!(signed(&agent.handle(&sign(&blob(0xa8)))));
        assert_eq!(listed(&agent.handle(&list())).len(), 2);
        assert!(agent.lock(b"pw"));
        assert!(listed(&agent.handle(&list())).is_empty());
        assert_eq!(agent.handle(&unlock(b"pw")), wire::success());
        assert_eq!(agent.handle(&remove_all()), wire::success());
        assert!(agent.identities().is_empty());
        assert_eq!(turns_held(), 0);
    });
}

// Blocked and re-entrant callbacks.

/// Holds the threads that reach it until it opens.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
    reached: AtomicUsize,
}

impl Gate {
    fn wait(&self) {
        self.reached.fetch_add(1, SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.opened.wait(open).unwrap();
        }
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }

    /// Wait for `threads` to reach the gate.
    fn holds(&self, threads: usize) {
        let deadline = Instant::now() + HANG_AFTER;
        while self.reached.load(SeqCst) < threads {
            assert!(
                Instant::now() < deadline,
                "only {} of {threads} threads reached the gate",
                self.reached.load(SeqCst)
            );
            sleep(Duration::from_millis(1));
        }
    }
}

/// A key whose signatures wait at a gate, as for a touch.
struct GatedKey(SignerRef, Arc<Gate>);

impl Signer for GatedKey {
    fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        self.1.wait();
        self.0.sign(data, hash)
    }
}

/// The agent never blocks on a slow key: while signatures wait for a
/// touch, a confirm prompt for an answer and a provider for a PIN, every
/// other request carries on, including removing the keys they wait on,
/// `ssh-add -D` and locking. A provider slow to add a key, which it does in
/// the key change's turn, holds up only other key changes. Once the waits
/// end, the requests that waited return.
#[test]
fn a_blocked_callback_holds_up_only_its_own_request() {
    struct GatedConfirm(Arc<Gate>);
    impl Confirm for GatedConfirm {
        fn confirm(&self, _: &ConfirmRequest) -> Option<bool> {
            self.0.wait();
            Some(true)
        }
    }
    /// [`Cards`] whose `slow` card waits for a PIN, and whose `turn` card
    /// is slow to add.
    struct GatedCards {
        cards: Arc<Cards>,
        pin: Arc<Gate>,
        insert: Arc<Gate>,
    }
    impl SmartcardProvider for GatedCards {
        fn resolve(
            &self,
            provider: &[u8],
            pin: &Zeroizing<Vec<u8>>,
        ) -> Result<SignerRef, BoxError> {
            if provider == b"slow" {
                self.pin.wait();
            }
            self.cards.resolve(provider, pin)
        }
        fn add(
            &self,
            provider: &[u8],
            pin: &Zeroizing<Vec<u8>>,
            lifetime: Option<u32>,
        ) -> Result<(), BoxError> {
            if provider == b"turn" {
                self.insert.wait();
            }
            self.cards.add(provider, pin, lifetime)
        }
        fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
            SmartcardProvider::remove(&*self.cards, provider)
        }
    }

    let (touch, insert) = (Arc::new(Gate::default()), Arc::new(Gate::default()));
    let slow = SignerRef::new(GatedKey(ed25519(0x10, "slow"), Arc::clone(&touch)));
    let slow_blob = slow.key_blob();
    let cards = Cards::new(&[("card", 0x12), ("slow", 0x13), ("turn", 0x14)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::new(MemoryBackend::new([slow])))
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::new(GatedCards {
                cards,
                pin: Arc::clone(&touch),
                insert: Arc::clone(&insert),
            }))
            .with_confirm(Arc::new(GatedConfirm(Arc::clone(&touch))))
            .with_unlock_backoff(Duration::from_millis(1)),
    );
    let confirmed = 0x15u8;
    assert_eq!(agent.handle(&add(confirmed, CONFIRM)), wire::success());
    let request = |body: Vec<u8>| {
        let agent = Arc::clone(&agent);
        std::thread::spawn(move || agent.handle(&body))
    };
    let mut waiting = vec![
        request(sign(&slow_blob)),
        request(sign(&slow_blob)),
        request(sign(&blob(confirmed))),
        request(smartcard("slow", Limits::default(), &[])),
    ];
    touch.holds(waiting.len());

    // Never signed with here: the slow key, and the -c key, which waits.
    let others = [0x16u8, 0x17];
    let signable: Vec<Vec<u8>> = [0x12, 0x16, 0x17].map(blob).to_vec();
    let removable: Vec<Vec<u8>> = [0x10, 0x12, 0x15, 0x16, 0x17].map(blob).to_vec();
    let mut workers = Vec::new();
    for _ in 0..3 {
        let (agent, removable) = (Arc::clone(&agent), removable.clone());
        workers.push(worker("change", move |step| {
            let limits = *step.rng.pick(&[Limits::default(), HIDDEN]);
            let (op, body) = match step.rng.below(7) {
                0 | 1 => ("add", add(*step.rng.pick(&others), limits)),
                2 => ("remove", remove(step.rng.pick(&removable))),
                3 => ("remove all", remove_all()),
                4 => ("add smartcard", smartcard("card", limits, &[])),
                5 => ("remove smartcard", smartcard_remove("card")),
                _ => ("remove the slow card", smartcard_remove("slow")),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    for _ in 0..2 {
        let (agent, signable) = (Arc::clone(&agent), signable.clone());
        workers.push(worker("read", move |step| {
            step.doing("list");
            agent.handle(&list());
            step.doing("sign");
            agent.handle(&sign(step.rng.pick(&signable)));
            step.doing("identities");
            agent.identities();
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("lock", move |step| {
            step.doing("lock");
            agent.handle(&lock(b"pw"));
            step.rng.pause(500);
            step.doing("unlock");
            agent.handle(&unlock(b"pw"));
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("purge", move |step| {
            step.doing("purge");
            agent.purge_expired();
            step.rng.pause(1000);
        }));
    }
    stress(workers);

    // Now a key change waits in its turn as well.
    waiting.push(request(smartcard("turn", Limits::default(), &[])));
    insert.holds(1);
    let mut workers = Vec::new();
    for _ in 0..2 {
        let (agent, signable) = (Arc::clone(&agent), signable.clone());
        workers.push(worker("read", move |step| {
            step.doing("list");
            agent.handle(&list());
            step.doing("sign");
            agent.handle(&sign(step.rng.pick(&signable)));
            step.doing("certificates_for");
            agent.certificates_for(&local_key(0x16, "stress").1);
        }));
    }
    {
        let agent = Arc::clone(&agent);
        let key = ed25519(0x18, "library");
        let cert = crate::testing::certify(key.public_key().key_data());
        workers.push(worker("library", move |step| match step.rng.below(4) {
            0 => {
                step.doing("add_key");
                agent.add_key(key.clone(), None);
            }
            1 => {
                step.doing("add_cert_key");
                agent.add_cert_key(key.clone(), cert.clone(), None);
            }
            2 => {
                step.doing("remove_cert");
                agent.remove_cert(cert.blob());
            }
            _ => {
                step.doing("remove_key");
                agent.remove_key(&key.key_blob());
            }
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("lock", move |step| {
            step.doing("lock");
            agent.lock(b"pw");
            step.rng.pause(500);
            step.doing("unlock");
            agent.unlock(b"pw");
        }));
    }
    stress(workers);

    touch.open();
    insert.open();
    within("the requests that waited", move || {
        for request in waiting {
            request.join().unwrap();
        }
    });
}

thread_local! {
    /// Whether this thread is calling back into an agent from a
    /// [`Reentrant`] callback, whose own callbacks then do not.
    static CALLING_BACK: Cell<bool> = const { Cell::new(false) };
}

/// Calls back into the agent from every callback with a random request:
/// any change, lock or read, on the same thread. The request's own
/// callbacks do not call back again.
struct Reentrant {
    back: Back,
    on: AtomicBool,
    calls: AtomicUsize,
}

impl Reentrant {
    fn new() -> Arc<Self> {
        Arc::new(Reentrant {
            back: Back::default(),
            on: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        })
    }

    fn call_back(&self) {
        if !self.on.load(SeqCst) || CALLING_BACK.get() {
            return;
        }
        let Some(agent) = self.back.agent() else {
            return;
        };
        static STATE: AtomicU64 = AtomicU64::new(3);
        let mut rng = Rng::new(STATE.fetch_add(0x9E37_79B9_7F4A_7C15, SeqCst));
        let seed = 0x40 + rng.below(3) as u8;
        let limits = *rng.pick(&[Limits::default(), CONFIRM, HIDDEN]);
        CALLING_BACK.set(true);
        match rng.below(13) {
            0 => drop(agent.handle(&add(seed, limits))),
            1 => drop(agent.handle(&remove(&blob(seed)))),
            2 => drop(agent.handle(&remove_all())),
            3 => drop(agent.handle(&list())),
            4 => drop(agent.handle(&sign(&blob(seed)))),
            5 => drop(agent.handle(&lock(b"pw"))),
            6 => drop(agent.handle(&unlock(b"pw"))),
            7 => drop(agent.handle(&smartcard("card", limits, &[]))),
            8 => drop(agent.handle(&smartcard_remove("card"))),
            9 => drop(agent.release(&blob(0x43), rng.chance(50))),
            10 => drop(agent.lock(b"pw") && agent.unlock(b"pw")),
            11 => drop(agent.handle(&extension("reenter@example.com"))),
            _ => {
                agent.purge_expired();
                agent.identities();
            }
        }
        CALLING_BACK.set(false);
        self.calls.fetch_add(1, SeqCst);
    }
}

/// A key that calls back into the agent as it signs.
struct ReentrantKey(SignerRef, Arc<Reentrant>);

impl ReentrantKey {
    fn wrap(key: SignerRef, reentrant: &Arc<Reentrant>) -> SignerRef {
        SignerRef::new(ReentrantKey(key, Arc::clone(reentrant)))
    }
}

impl Signer for ReentrantKey {
    fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        self.1.call_back();
        self.0.sign(data, hash)
    }
}

/// [`Cards`], and the keys they serve, calling back into the agent.
struct ReentrantCards(Arc<Cards>, Arc<Reentrant>);

impl ReentrantCards {
    fn wrap(&self, keys: Vec<SignerRef>) -> Vec<SignerRef> {
        keys.into_iter()
            .map(|key| ReentrantKey::wrap(key, &self.1))
            .collect()
    }
}

impl Backend for ReentrantCards {
    fn identities(&self) -> Vec<SignerRef> {
        self.1.call_back();
        self.wrap(self.0.identities())
    }
    fn known(&self) -> Vec<SignerRef> {
        self.1.call_back();
        self.wrap(self.0.known())
    }
    fn remove(&self, key_blob: &[u8]) -> bool {
        self.1.call_back();
        Backend::remove(&*self.0, key_blob)
    }
    fn remove_all(&self) {
        self.1.call_back();
        self.0.remove_all();
    }
    fn purge_expired(&self) {
        self.1.call_back();
    }
}

impl SmartcardProvider for ReentrantCards {
    fn resolve(&self, provider: &[u8], pin: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
        self.1.call_back();
        let key = self.0.resolve(provider, pin)?;
        Ok(ReentrantKey::wrap(key, &self.1))
    }
    fn add(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
    ) -> Result<(), BoxError> {
        self.1.call_back();
        self.0.add(provider, pin, lifetime)
    }
    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
        self.1.call_back();
        SmartcardProvider::remove(&*self.0, provider)
    }
}

/// Allows everything, answers every confirm yes and hears every event,
/// calling back into the agent each time.
struct ReentrantUser(Arc<Reentrant>);

impl Policy for ReentrantUser {
    fn allow_sign(&self, _: &SignInfo<'_>) -> bool {
        self.0.call_back();
        true
    }
    fn signed(&self, _: &SignInfo<'_>) {
        self.0.call_back();
    }
    fn allow_list(&self, _: &ListInfo<'_>) -> bool {
        self.0.call_back();
        true
    }
    fn allow_manage(&self, _: &ManageInfo<'_>) -> bool {
        self.0.call_back();
        true
    }
}

impl Confirm for ReentrantUser {
    fn confirm(&self, _: &ConfirmRequest) -> Option<bool> {
        self.0.call_back();
        Some(true)
    }
}

impl Lifecycle for ReentrantUser {
    fn locked(&self) {
        self.0.call_back();
    }
    fn unlocked(&self) {
        self.0.call_back();
    }
    fn cleared(&self) {
        self.0.call_back();
    }
}

impl Extension for ReentrantUser {
    fn name(&self) -> &str {
        "reenter@example.com"
    }
    fn handle(&self, _: &ExtensionContext, _: &[u8]) -> ExtensionReply {
        self.0.call_back();
        ExtensionReply::Success
    }
}

impl KeyDecoder for ReentrantUser {
    fn key_types(&self) -> &[&str] {
        &["ssh-ed25519"]
    }
    fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<SignerRef, KeyDecodeError> {
        self.0.call_back();
        let key = crate::local::decode(key_type, reader).map(SignerRef::new)?;
        Ok(ReentrantKey::wrap(key, &self.0))
    }
}

/// [`PassphraseLock`], calling back into the agent first.
struct ReentrantLock(PassphraseLock, Arc<Reentrant>);

impl Locker for ReentrantLock {
    fn is_locked(&self) -> bool {
        self.1.call_back();
        self.0.is_locked()
    }
    fn lock(&self, passphrase: &[u8]) -> bool {
        self.1.call_back();
        self.0.lock(passphrase)
    }
    fn unlock(&self, passphrase: &[u8]) -> bool {
        self.1.call_back();
        self.0.unlock(passphrase)
    }
}

/// Every callback the agent makes, inside a turn or not, calls back into
/// it with any request, while requests of every kind race: each one
/// returns (refused, at worst), no turn is left held, and once the calling
/// back stops every kind of request works.
#[test]
fn every_callback_may_call_back_into_the_agent() {
    let reentrant = Reentrant::new();
    let cards = Arc::new(ReentrantCards(
        Cards::new(&[("card", 0x43), ("other", 0x44)]),
        Arc::clone(&reentrant),
    ));
    let user = ReentrantUser(Arc::clone(&reentrant));
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _)
            .with_policy(Arc::new(ReentrantUser(Arc::clone(&reentrant))))
            .with_confirm(Arc::new(ReentrantUser(Arc::clone(&reentrant))))
            .with_lifecycle(Arc::new(ReentrantUser(Arc::clone(&reentrant))))
            .with_locker(Arc::new(ReentrantLock(
                PassphraseLock::default(),
                Arc::clone(&reentrant),
            )))
            .with_extension(ReentrantUser(Arc::clone(&reentrant)))
            .with_key_type(user)
            .with_unlock_backoff(Duration::from_millis(1)),
    );
    reentrant.back.set(&agent);
    let blobs: Vec<Vec<u8>> = (0x40..=0x46).map(blob).collect();

    let mut workers = Vec::new();
    for _ in 0..6 {
        let (agent, blobs) = (Arc::clone(&agent), blobs.clone());
        let mut connection = Connection::default();
        workers.push(worker("churn", move |step| {
            let seed = 0x40 + step.rng.below(3) as u8;
            let limits = Limits {
                confirm: step.rng.chance(30),
                lifetime: step.rng.chance(10).then_some(1),
                hidden: step.rng.chance(20),
            };
            let card = *step.rng.pick(&["card", "other"]);
            let (op, body) = match step.rng.below(12) {
                0 | 1 => ("add", add(seed, limits)),
                2 => ("remove", remove(step.rng.pick(&blobs))),
                3 => ("remove all", remove_all()),
                4 | 5 => ("sign", sign(step.rng.pick(&blobs))),
                6 => ("list", list()),
                7 => ("lock", lock(b"pw")),
                8 => ("unlock", unlock(b"pw")),
                9 => ("add smartcard", smartcard(card, limits, &[])),
                10 => ("remove smartcard", smartcard_remove(card)),
                _ => ("extension", extension("reenter@example.com")),
            };
            step.doing(op);
            if step.rng.chance(5) {
                connection = Connection::default();
            }
            agent.handle_in(&body, &mut connection);
            assert_eq!(turns_held(), 0, "{op} left a turn held");
        }));
    }
    {
        let (agent, cards) = (Arc::clone(&agent), Arc::clone(&cards));
        workers.push(worker("backend drops", move |step| {
            let blob = blob(*step.rng.pick(&[0x43, 0x44]));
            step.doing("drop and release");
            let served = cards.0.drop_key(&blob);
            agent.release(&blob, served);
            assert_eq!(turns_held(), 0, "a release left a turn held");
            step.rng.pause(2000);
        }));
    }
    stress(workers);
    assert!(reentrant.calls.load(SeqCst) > 0, "nothing called back");

    reentrant.on.store(false, SeqCst);
    within("requests once the calling back stopped", move || {
        agent.unlock(b"pw");
        assert!(!agent.is_locked());
        assert_eq!(agent.handle(&remove_all()), wire::success());
        let plain = 0x45;
        assert_eq!(
            agent.handle(&add(plain, Limits::default())),
            wire::success()
        );
        assert!(signed(&agent.handle(&sign(&blob(plain)))));
        assert_eq!(
            agent.handle(&smartcard("card", Limits::default(), &[])),
            wire::success()
        );
        assert!(signed(&agent.handle(&sign(&blob(0x43)))));
        assert_eq!(listed(&agent.handle(&list())).len(), 2);
        assert_eq!(agent.handle(&lock(b"pw")), wire::success());
        assert_eq!(agent.handle(&unlock(b"pw")), wire::success());
        assert_eq!(agent.handle(&remove_all()), wire::success());
        assert!(agent.identities().is_empty());
        assert_eq!(turns_held(), 0);
    });
}

// Lost updates.

/// What a thread changes, it sees at once, whatever other threads change
/// meanwhile: a key it added is listed, once, and signs until it removes
/// it, as does a certificate it added, through the protocol or the
/// library's calls. Another change landing alongside never loses one.
#[test]
fn each_thread_sees_its_own_changes() {
    let cards = Cards::new(&[("card", 0x30)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _)
            .with_confirm(Arc::new(DenyConfirm::default())),
    );
    let shown = |agent: &Agent, blob: &[u8]| {
        listed(&agent.handle(&list()))
            .iter()
            .filter(|b| *b == blob)
            .count()
    };

    let mut workers = Vec::new();
    for seed in 0x31..=0x34u8 {
        let agent = Arc::clone(&agent);
        let key = ed25519(seed, "stress");
        let key_blob = key.key_blob();
        let cert = crate::testing::certify(key.public_key().key_data());
        workers.push(worker("owner", move |step| {
            if step.rng.chance(50) {
                step.doing("add");
                until_done(&agent, &add(seed, Limits::default()));
            } else {
                step.doing("add_key");
                agent.add_key(key.clone(), None);
            }
            step.doing("check the key is served");
            assert_eq!(shown(&agent, &key_blob), 1, "key {seed:#x}, just added");
            assert!(
                signed(&agent.handle(&sign(&key_blob))),
                "key {seed:#x}, just added, did not sign"
            );
            if step.rng.chance(50) {
                step.doing("add_cert_key");
                agent.add_cert_key(key.clone(), cert.clone(), None);
                assert_eq!(shown(&agent, cert.blob()), 1, "{seed:#x}'s certificate");
                assert!(
                    signed(&agent.handle(&sign(cert.blob()))),
                    "{seed:#x}'s certificate, just added, did not sign"
                );
                step.doing("remove_cert");
                assert!(agent.remove_cert(cert.blob()), "{seed:#x}'s certificate");
                assert_eq!(shown(&agent, cert.blob()), 0, "{seed:#x}'s certificate");
            }
            if step.rng.chance(50) {
                step.doing("remove");
                until_done(&agent, &remove(&key_blob));
            } else {
                step.doing("remove_key");
                assert!(agent.remove_key(&key_blob), "key {seed:#x} was gone");
            }
            step.doing("check the key is gone");
            assert_eq!(shown(&agent, &key_blob), 0, "key {seed:#x}, just removed");
            assert!(
                !signed(&agent.handle(&sign(&key_blob))),
                "key {seed:#x}, just removed, signed"
            );
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        workers.push(worker("churn", move |step| {
            let seed = 0x35 + step.rng.below(3) as u8;
            let limits = Limits {
                confirm: step.rng.chance(30),
                lifetime: step.rng.chance(20).then_some(1),
                hidden: step.rng.chance(30),
            };
            let (op, body) = match step.rng.below(5) {
                0 | 1 => ("add", add(seed, limits)),
                2 => ("remove", remove(&blob(seed))),
                3 => ("add smartcard", smartcard("card", limits, &[])),
                _ => ("remove smartcard", smartcard_remove("card")),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    {
        let (agent, cards) = (Arc::clone(&agent), Arc::clone(&cards));
        workers.push(worker("backend drops", move |step| {
            step.doing("drop and release");
            let card = blob(0x30);
            let served = cards.drop_key(&card);
            agent.release(&card, served);
            step.doing("purge");
            agent.purge_expired();
            step.rng.pause(1000);
        }));
    }
    {
        let agent = Arc::clone(&agent);
        workers.push(worker("list", move |step| {
            step.doing("list");
            let mut shown = listed(&agent.handle(&list()));
            let count = shown.len();
            shown.sort();
            shown.dedup();
            assert_eq!(shown.len(), count, "an identity was listed twice");
        }));
    }
    stress(workers);
}

// Session bindings.

/// `body`, an add or smartcard add with no constraints, restricted with
/// `ssh-add -h` to the host whose key is `host`.
fn to_host(mut body: Vec<u8>, host: &PublicKey) -> Vec<u8> {
    body[0] = match body[0] {
        wire::SSH2_AGENTC_ADD_IDENTITY => wire::SSH2_AGENTC_ADD_ID_CONSTRAINED,
        wire::SSH_AGENTC_ADD_SMARTCARD_KEY => wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
        other => panic!("not an unconstrained add: {other}"),
    };
    body.extend_from_slice(&wire::tests::destination_extension_to(host));
    body
}

/// A `session-bind@openssh.com` request binding `session_id` to `host`.
fn session_bind(host: &PrivateKey, session_id: &[u8]) -> Vec<u8> {
    let mut body = extension(crate::destination::SESSION_BIND);
    host.public_key()
        .to_bytes()
        .unwrap()
        .encode(&mut body)
        .unwrap();
    session_id.encode(&mut body).unwrap();
    let signature: Signature = signature::Signer::sign(host, session_id);
    let mut signed = Vec::new();
    signature.encode(&mut signed).unwrap();
    signed.encode(&mut body).unwrap();
    0u8.encode(&mut body).unwrap();
    body
}

/// What `ssh` asks the agent to sign to authenticate on `session_id`
/// with the ed25519 key `key_blob`.
fn userauth(session_id: &[u8], key_blob: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    session_id.encode(&mut data).unwrap();
    data.push(50);
    "ferris".encode(&mut data).unwrap();
    "ssh-connection".encode(&mut data).unwrap();
    "publickey".encode(&mut data).unwrap();
    data.push(1);
    "ssh-ed25519".encode(&mut data).unwrap();
    key_blob.encode(&mut data).unwrap();
    data
}

/// `ssh-add -h` keys under churn, seen from connections bound with
/// `session-bind@openssh.com`, and bound afresh now and then: one bound to
/// the host they are restricted to lists them and authenticates with them
/// whenever they are surely served; one bound to another host never does.
/// One worker alone adds and removes them, counting an odd epoch while
/// they are surely served.
#[test]
fn bound_connections_keep_to_their_destinations() {
    use ssh_key::private::Ed25519Keypair;
    let host = |seed: u8| PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
    let (allowed, refused) = (host(0x5a), host(0x5b));
    let cards = Cards::new(&[("card", 0x50), ("other", 0x51)]);
    let agent = Arc::new(
        Agent::new()
            .with_backend(Arc::clone(&cards) as _)
            .with_smartcard(Arc::clone(&cards) as _),
    );
    let local = 0x52u8;
    let restricted = [blob(0x50), blob(local)];
    let epoch = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    {
        let (agent, epoch) = (Arc::clone(&agent), Arc::clone(&epoch));
        let to = allowed.public_key().clone();
        workers.push(worker("holder", move |step| {
            step.doing("add -h");
            until_done(&agent, &to_host(add(local, Limits::default()), &to));
            step.doing("add smartcard -h");
            let card = smartcard("card", Limits::default(), &[]);
            until_done(&agent, &to_host(card, &to));
            epoch.fetch_add(1, SeqCst);
            sleep(Duration::from_millis(10));
            step.rng.pause(10_000);
            epoch.fetch_add(1, SeqCst);
            step.doing("remove");
            until_done(&agent, &remove(&blob(local)));
            step.doing("remove smartcard");
            until_done(&agent, &smartcard_remove("card"));
            step.rng.pause(1000);
        }));
    }
    for _ in 0..2 {
        let agent = Arc::clone(&agent);
        let to = refused.public_key().clone();
        workers.push(worker("churn", move |step| {
            let seed = 0x53 + step.rng.below(3) as u8;
            let limits = *step.rng.pick(&[CONFIRM, HIDDEN, Limits::default()]);
            let (op, body) = match step.rng.below(5) {
                0 => ("add", add(seed, limits)),
                1 => (
                    "add -h elsewhere",
                    to_host(add(seed, Limits::default()), &to),
                ),
                2 => ("remove", remove(&blob(seed))),
                3 => ("add smartcard", smartcard("other", limits, &[])),
                _ => ("remove smartcard", smartcard_remove("other")),
            };
            step.doing(op);
            agent.handle(&body);
        }));
    }
    let checked = Arc::new(AtomicUsize::new(0));
    for (index, permitted) in [true, true, false, false].into_iter().enumerate() {
        let (agent, epoch, restricted) =
            (Arc::clone(&agent), Arc::clone(&epoch), restricted.clone());
        let checked = Arc::clone(&checked);
        let host = if permitted { &allowed } else { &refused }.clone();
        let session_id = format!("session {index}").into_bytes();
        // Bound through the agent, as `ssh` does, racing the other requests.
        let bound = {
            let (agent, bind) = (Arc::clone(&agent), session_bind(&host, &session_id));
            move || {
                let mut connection = Connection::default();
                let reply = agent.handle_in(&bind, &mut connection);
                assert_eq!(reply, wire::success(), "session-bind refused");
                connection
            }
        };
        let mut connection = bound();
        workers.push(worker("bound connection", move |step| {
            if step.rng.chance(5) {
                step.doing("session-bind");
                connection = bound();
            }
            let key = step.rng.below(restricted.len());
            let (op, body) = match step.rng.below(2) {
                0 => ("list", list()),
                _ => (
                    "sign",
                    sign_body(&restricted[key], &userauth(&session_id, &restricted[key])),
                ),
            };
            step.doing(op);
            let before = epoch.load(SeqCst);
            let reply = agent.handle_in(&body, &mut connection);
            let after = epoch.load(SeqCst);
            let surely_served = before == after && before % 2 == 1;
            match (op, permitted) {
                ("list", true) if surely_served => {
                    checked.fetch_add(1, SeqCst);
                    let shown = listed(&reply);
                    for (key, blob) in restricted.iter().enumerate() {
                        assert!(shown.contains(blob), "-h key {key} not listed to its host");
                    }
                }
                ("sign", true) if surely_served => {
                    checked.fetch_add(1, SeqCst);
                    assert!(signed(&reply), "-h key {key} did not sign for its host");
                }
                ("list", false) => {
                    let shown = listed(&reply);
                    let leaked = restricted.iter().position(|b| shown.contains(b));
                    assert_eq!(leaked, None, "-h key listed to another host");
                }
                ("sign", false) => {
                    assert!(!signed(&reply), "-h key {key} signed for another host");
                }
                _ => {}
            }
        }));
    }
    stress(workers);
    assert!(
        checked.load(SeqCst) > 0,
        "the keys were never surely served to their host"
    );
}
