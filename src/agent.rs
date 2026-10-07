//! The agent itself: identity bookkeeping and request handling.
//!
//! # Concurrency
//!
//! The agent is shared between connection threads, and calls user code (a
//! [`Backend`], [`SmartcardProvider`], [`Policy`], [`Confirm`], [`Locker`]
//! or [`Lifecycle`]) that may call back into it. Four rules keep it from
//! taking part in a deadlock:
//!
//! 1. User code is never called while a lock is held, except the calls that
//!    must be ordered: a backend's `remove`/`remove_all`, a provider's
//!    `add`/`remove` and [`Lifecycle::cleared`] during a key change's turn
//!    (`changes`, see `Agent::prepared_turn`), and the [`Locker`] and the
//!    `locked`/`unlocked` hooks while the agent is locked or unlocked
//!    (`lock_state`), so the hooks hear of each in order. Everything else a
//!    change needs, from key lookups to the policy, runs first, against a
//!    snapshot. No lock is held through an unlock guess's delay.
//! 2. The closures given to `Agent::write` and the other `rcu` calls only
//!    change the value they are given: no I/O, no logging, no user code, no
//!    nested write. They may run more than once.
//! 3. At most one blocking lock is held at a time.
//! 4. Each call to user code made while a lock is held has a test that
//!    calls back into the agent from it and expects an answer, a refusal or
//!    otherwise, within a timeout rather than a hang.
//!
//! A key change or unlock asked for from a callback holding that same lock,
//! on the same thread, is refused rather than left waiting on itself
//! (`Holding`). One asked for on another thread while that thread holds a
//! lock the callback is waiting for is a cycle through user code that
//! the agent cannot see; rule 1 keeps it to the calls listed there.

use crate::backend::{Backend, Expiring, Lifecycle, SmartcardProvider};
use crate::cert::{AssociatedCerts, CertKey};
use crate::destination::{self, Connection, DestinationConstraint};
use crate::extension::{Extension, ExtensionContext};
use crate::keytype::{KeyDecoder, KeyRegistry, Registered};
use crate::lock::{Locker, PassphraseLock};
use crate::policy::{
    Confirm, ConfirmRequest, KeyChange, KeyConstraints, ListInfo, ManageInfo, Policy, SignInfo,
};
use crate::signer::{BoxError, SignerRef, VerifyError};
use crate::wire::{self, Request};
use arc_swap::ArcSwap;
use ssh_encoding::Decode;
use ssh_key::{HashAlg, PublicKey};
use std::cell::RefCell;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

/// Lock `mutex`, carrying on if a thread panicked while holding it: each
/// value guarded here is left consistent between statements, so a poisoned
/// lock still holds usable state.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug, Error)]
pub enum AgentError {
    /// A backend or a key could not sign or fetch; see
    /// [`AgentError::backend`] to look inside.
    #[error(transparent)]
    Backend(BoxError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("requested key is not served by this agent")]
    UnknownKey,
    #[error(
        "client asked for an ssh-rsa (SHA-1) signature, which is not supported; it must request rsa-sha2-256 or rsa-sha2-512"
    )]
    Sha1Requested,
    #[error(transparent)]
    Wire(#[from] wire::WireError),
    #[error("none of the certificates certifies the key")]
    NoMatchingCertificate,
    #[error("destination-constrained key refused on this connection")]
    DestinationRefused,
    #[error("the signature request could not be identified as an SSH userauth request")]
    UnidentifiedSignature,
    #[error("the user refused the use of the key")]
    ConfirmRefused,
    #[error("refused by the agent's policy")]
    PolicyRefused,
    #[error("this agent has no smartcard provider")]
    NoSmartcardProvider,
}

impl AgentError {
    /// The backend's own error, if this is one of type `E`.
    pub fn backend<E: std::error::Error + 'static>(&self) -> Option<&E> {
        match self {
            AgentError::Backend(e) => e.downcast_ref(),
            _ => None,
        }
    }
}

/// Agent state shared between connections.
///
/// Build one with [`Agent::new`] and the `with_*` methods, then serve it with
/// [`crate::serve`]. Keys come from three places:
///
/// - [`Backend`]s the agent's owner registers, such as a hardware token;
/// - `ssh-add FILE`, decoded by the [`KeyDecoder`]s in its registry and held
///   by the agent;
/// - `ssh-add -s PROVIDER`, through the [`SmartcardProvider`].
pub struct Agent {
    backends: Vec<Arc<dyn Backend>>,
    smartcard: Option<Arc<dyn SmartcardProvider>>,
    /// The keys, certificates and constraints the agent holds itself, as an
    /// immutable snapshot: a read loads it without locking, and a write
    /// publishes a changed copy (see [`Self::write`]).
    store: ArcSwap<Store>,
    /// Held through the commit of each key change a client asks for, the
    /// requests [`Request::changes_keys`] groups as writes (see
    /// [`Self::prepared_turn`]). A change that reaches a backend or provider
    /// publishes the store more than once, so two commits must not
    /// interleave.
    changes: Mutex<()>,
    /// Protocol extension handlers, by the name each gave when registered,
    /// replaced as a whole on each registration.
    extensions: ArcSwap<Vec<(String, Arc<dyn Extension>)>>,
    /// Key-type decoders for `ssh-add FILE`, matched by the request's key type.
    /// A request decodes with its own snapshot of them, so a decoder may call
    /// back into the agent.
    key_types: ArcSwap<KeyRegistry>,
    /// Asks the user about keys added with `ssh-add -c`; without one they
    /// never sign.
    confirm: Option<Arc<dyn Confirm>>,
    policy: Option<Arc<dyn Policy>>,
    lifecycle: Vec<Arc<dyn Lifecycle>>,
    locker: Arc<dyn Locker>,
    /// Lifetime applied to keys added without their own `ssh-add -t`, as
    /// `ssh-agent -t` does; `None` keeps them until removed.
    default_lifetime: Option<u32>,
    /// Held through each lock or unlock and its hooks, so the hooks hear of
    /// them in the order they happened, and through each unlock guess, so
    /// guesses are taken one at a time however many connections send them.
    /// Never held through a guess's delay (see [`Self::handle_unlock`]).
    lock_state: Mutex<LockState>,
    /// Delay added per recorded failure.
    unlock_backoff: Duration,
}

/// The constraints of an added key: `ssh-add -c` and `ssh-add -h`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KeyMeta {
    confirm: bool,
    destination: Vec<DestinationConstraint>,
}

impl KeyMeta {
    fn is_empty(&self) -> bool {
        !self.confirm && self.destination.is_empty()
    }
}

/// Delay per failed unlock, as in OpenSSH: 0.1 s more for each failure.
const UNLOCK_BACKOFF: Duration = Duration::from_millis(100);
/// Failures counted at most, so the delay tops out at 10 s.
const MAX_UNLOCK_FAILURES: u32 = 100;
/// Times a listing or a sign's key lookup is taken before giving up on
/// constraints that keep changing under it.
const LOOKUP_ATTEMPTS: usize = 3;

/// A certificate the agent lists, and the key that signs for it, as found
/// in a [`Store`].
struct CertIdentity<'a> {
    cert: &'a CertKey,
    comment: &'a str,
    signer: CertSigner<'a>,
}

enum CertSigner<'a> {
    /// The private key `ssh-add FILE` sent with the certificate, and the
    /// `ssh-add -c`/`-h` constraints the certificate was added with.
    Held {
        key: &'a SignerRef,
        meta: &'a KeyMeta,
    },
    /// The key `ssh-add -s PROVIDER CERT…` named; dropped with it, and
    /// constrained as it is.
    Provider(&'a SignerRef),
    /// Whichever key a backend serves that the certificate certifies, for a
    /// certificate loaded with [`Agent::with_certificates`].
    Served,
}

/// A key `ssh-add FILE` sent: served as an identity of its own, with
/// certificates, or both. Each identity keeps the `ssh-add -c`/`-h`
/// constraints and `ssh-add -t` lifetime it was added with.
#[derive(Clone)]
struct HeldEntry {
    key: SignerRef,
    /// The plain key's constraints, while it is served as an identity.
    own: Option<Expiring<KeyMeta>>,
    certs: Vec<Expiring<HeldCert>>,
}

#[derive(Clone)]
struct HeldCert {
    cert: CertKey,
    /// The comment sent with the certificate's key, which it is listed
    /// under: re-adding the key under another leaves it as it was.
    comment: String,
    meta: KeyMeta,
}

impl HeldEntry {
    /// The plain key's constraints, unless it is not served or has expired.
    fn own(&self) -> Option<&KeyMeta> {
        self.own.as_ref().filter(|e| !e.expired()).map(|e| &e.item)
    }

    fn is_empty(&self) -> bool {
        self.own.is_none() && self.certs.is_empty()
    }

    fn has_expired(&self) -> bool {
        self.own.as_ref().is_some_and(Expiring::expired) || self.certs.iter().any(Expiring::expired)
    }

    fn purge_expired(&mut self) {
        self.own = self.own.take().filter(|e| !e.expired());
        self.certs.retain(|e| !e.expired());
    }
}

/// What `ssh-add -s` attached to a backend key: its constraints, recorded
/// before the key is served and dropped after it goes, and the
/// certificates it was added with, which share them. The key itself lives
/// in a backend.
#[derive(Clone)]
struct ProviderEntry {
    key_blob: Vec<u8>,
    meta: KeyMeta,
    certs: Vec<Expiring<ProviderCert>>,
}

#[derive(Clone)]
struct ProviderCert {
    cert: CertKey,
    key: SignerRef,
}

impl ProviderEntry {
    fn is_empty(&self) -> bool {
        self.meta.is_empty() && self.certs.is_empty()
    }

    fn has_expired(&self) -> bool {
        self.certs.iter().any(Expiring::expired)
    }

    fn purge_expired(&mut self) {
        self.certs.retain(|e| !e.expired());
    }
}

/// A certificate [`Agent::with_certificates`] serves for a backend key,
/// listed under `comment`.
#[derive(Clone)]
struct ServedCert {
    cert: CertKey,
    comment: String,
}

/// An identity a listing found, before the policy is asked about it.
struct Listing {
    listed: wire::Listed,
    /// The key, or the key that signs for `cert`.
    key: SignerRef,
    cert: Option<CertKey>,
}

/// Where an identity's `ssh-add -c`/`-h` constraints are kept.
enum Constraints {
    /// On the entry `ssh-add FILE` added, as found in a snapshot.
    Own(KeyMeta),
    /// Those of the backend key that signs, by its blob (see
    /// [`Store::backend_meta`]); the key is looked up outside the snapshot.
    Provider(Vec<u8>),
}

/// What the agent holds itself. A published store is never changed: a
/// write changes a copy (see [`Agent::write`]), so an identity and its
/// constraints are always seen together. Each collection is shared between
/// copies until a write changes it, so a copy costs three reference counts.
///
/// Certificates are kept with the key that signs for them, so a key and
/// what was attached to it come and go together; only those
/// [`Agent::with_certificates`] serves, for keys no entry holds, stand
/// apart.
#[derive(Clone, Default)]
struct Store {
    /// Keys added at runtime with `ssh-add FILE`, with their certificates.
    held: Arc<Vec<HeldEntry>>,
    /// What `ssh-add -s` attached to backend keys, one entry per key.
    /// Replaced only when an entry changes, so a reader can tell from this
    /// `Arc` alone whether one did between two snapshots.
    provider: Arc<Vec<ProviderEntry>>,
    /// Certificates for backend keys, loaded with the agent.
    served: Arc<Vec<ServedCert>>,
}

impl Store {
    fn has_expired(&self) -> bool {
        self.held.iter().any(HeldEntry::has_expired)
            || self.provider.iter().any(ProviderEntry::has_expired)
    }

    /// Drop expired keys and certificates, constraints and all.
    /// Only a collection holding something expired is replaced, so readers
    /// comparing snapshots see the other unchanged.
    fn purge_expired(&mut self) {
        if self.held.iter().any(HeldEntry::has_expired) {
            let held = Arc::make_mut(&mut self.held);
            held.iter_mut().for_each(HeldEntry::purge_expired);
            held.retain(|e| !e.is_empty());
        }
        if self.provider.iter().any(ProviderEntry::has_expired) {
            let provider = Arc::make_mut(&mut self.provider);
            provider.iter_mut().for_each(ProviderEntry::purge_expired);
            provider.retain(|e| !e.is_empty());
        }
    }

    fn held_entry(&self, key_blob: &[u8]) -> Option<&HeldEntry> {
        self.held.iter().find(|e| e.key.key_blob() == key_blob)
    }

    /// The added key `key_blob` names and its constraints, unless it is not
    /// served as an identity of its own or has expired.
    fn held_key(&self, key_blob: &[u8]) -> Option<(&SignerRef, &KeyMeta)> {
        let entry = self.held_entry(key_blob)?;
        entry.own().map(|meta| (&entry.key, meta))
    }

    /// Every added key served as an identity of its own, in the order added.
    fn held_keys(&self) -> impl Iterator<Item = (&SignerRef, &KeyMeta)> {
        self.held
            .iter()
            .filter_map(|e| e.own().map(|meta| (&e.key, meta)))
    }

    /// The constraints the added certificate `blob` was added with, unless
    /// it is not served or has expired.
    fn held_cert_meta(&self, blob: &[u8]) -> Option<&KeyMeta> {
        self.held
            .iter()
            .flat_map(|e| &e.certs)
            .find(|c| c.item.cert.blob() == blob && !c.expired())
            .map(|c| &c.item.meta)
    }

    /// Every certificate served, unless its `ssh-add -t` lifetime has run
    /// out: those added with their key, then those `ssh-add -s` attached,
    /// then those loaded with the agent.
    fn certs(&self) -> impl Iterator<Item = CertIdentity<'_>> {
        let held = self.held.iter().flat_map(|entry| {
            entry
                .certs
                .iter()
                .filter(|e| !e.expired())
                .map(|e| CertIdentity {
                    cert: &e.item.cert,
                    comment: &e.item.comment,
                    signer: CertSigner::Held {
                        key: &entry.key,
                        meta: &e.item.meta,
                    },
                })
        });
        let provider = self.provider.iter().flat_map(|entry| {
            entry
                .certs
                .iter()
                .filter(|e| !e.expired())
                .map(|e| CertIdentity {
                    cert: &e.item.cert,
                    comment: e.item.key.comment(),
                    signer: CertSigner::Provider(&e.item.key),
                })
        });
        let served = self.served.iter().map(|c| CertIdentity {
            cert: &c.cert,
            comment: &c.comment,
            signer: CertSigner::Served,
        });
        held.chain(provider).chain(served)
    }

    /// The certificate whose blob is `blob`, unless its `ssh-add -t`
    /// lifetime has run out.
    fn cert(&self, blob: &[u8]) -> Option<CertIdentity<'_>> {
        self.certs().find(|c| c.cert.blob() == blob)
    }

    /// Serve `key` as an identity of its own under `meta`, replacing its
    /// constraints and lifetime if it is already served. Its certificates
    /// keep theirs.
    fn hold(&mut self, key: SignerRef, meta: KeyMeta, lifetime: Option<u32>) {
        let own = Some(Expiring::new(meta, lifetime));
        let blob = key.key_blob();
        let held = Arc::make_mut(&mut self.held);
        match held.iter_mut().find(|e| e.key.key_blob() == blob) {
            Some(entry) => {
                entry.key = key;
                entry.own = own;
            }
            None => held.push(HeldEntry {
                key,
                own,
                certs: Vec::new(),
            }),
        }
    }

    /// Serve `cert`, signed for by `key`, under `meta`, replacing the same
    /// certificate wherever it is served.
    fn hold_cert(&mut self, key: SignerRef, cert: CertKey, meta: KeyMeta, lifetime: Option<u32>) {
        self.take_cert(cert.blob());
        let comment = key.comment().to_owned();
        let added = Expiring::new(
            HeldCert {
                cert,
                comment,
                meta,
            },
            lifetime,
        );
        let blob = key.key_blob();
        let held = Arc::make_mut(&mut self.held);
        match held.iter_mut().find(|e| e.key.key_blob() == blob) {
            Some(entry) => entry.certs.push(added),
            None => held.push(HeldEntry {
                key,
                own: None,
                certs: vec![added],
            }),
        }
    }

    /// Stop serving the added key `key_blob` as an identity of its own. Its
    /// certificates stay. Returns whether it was served.
    fn remove_held(&mut self, key_blob: &[u8]) -> bool {
        if self.held_entry(key_blob).is_none_or(|e| e.own.is_none()) {
            return false;
        }
        let held = Arc::make_mut(&mut self.held);
        held.iter_mut()
            .filter(|e| e.key.key_blob() == key_blob)
            .for_each(|e| e.own = None);
        held.retain(|e| !e.is_empty());
        true
    }

    /// Stop serving the certificate whose blob is `blob`, wherever it is
    /// kept. Returns whether it was served.
    fn take_cert(&mut self, blob: &[u8]) -> bool {
        if self
            .held
            .iter()
            .any(|e| e.certs.iter().any(|c| c.item.cert.blob() == blob))
        {
            let held = Arc::make_mut(&mut self.held);
            held.iter_mut()
                .for_each(|e| e.certs.retain(|c| c.item.cert.blob() != blob));
            held.retain(|e| !e.is_empty());
            return true;
        }
        if self
            .provider
            .iter()
            .any(|e| e.certs.iter().any(|c| c.item.cert.blob() == blob))
        {
            let provider = Arc::make_mut(&mut self.provider);
            provider
                .iter_mut()
                .for_each(|e| e.certs.retain(|c| c.item.cert.blob() != blob));
            provider.retain(|e| !e.is_empty());
            return true;
        }
        if self.served.iter().any(|c| c.cert.blob() == blob) {
            Arc::make_mut(&mut self.served).retain(|c| c.cert.blob() != blob);
            return true;
        }
        false
    }

    fn provider_entry(&self, key_blob: &[u8]) -> Option<&ProviderEntry> {
        self.provider.iter().find(|e| e.key_blob == key_blob)
    }

    /// The constraints `ssh-add -s` recorded for the key `key_blob`, if any.
    fn provider_meta(&self, key_blob: &[u8]) -> Option<&KeyMeta> {
        self.provider_entry(key_blob)
            .map(|e| &e.meta)
            .filter(|meta| !meta.is_empty())
    }

    /// Record or clear the constraints of a key `ssh-add -s` added, which
    /// its certificates share.
    fn set_provider_meta(&mut self, key_blob: Vec<u8>, meta: KeyMeta) {
        match self.provider_entry(&key_blob) {
            Some(entry) if entry.meta == meta => {}
            Some(_) => {
                let provider = Arc::make_mut(&mut self.provider);
                provider
                    .iter_mut()
                    .filter(|e| e.key_blob == key_blob)
                    .for_each(|e| e.meta = meta.clone());
                provider.retain(|e| !e.is_empty());
            }
            None if meta.is_empty() => {}
            None => Arc::make_mut(&mut self.provider).push(ProviderEntry {
                key_blob,
                meta,
                certs: Vec::new(),
            }),
        }
    }

    /// Serve `certs` for the `ssh-add -s` key `key`, under its constraints,
    /// replacing each wherever it is served.
    fn attach_provider_certs(&mut self, key: &SignerRef, certs: &[CertKey], lifetime: Option<u32>) {
        for cert in certs {
            self.take_cert(cert.blob());
        }
        let attached = certs.iter().map(|cert| {
            Expiring::new(
                ProviderCert {
                    cert: cert.clone(),
                    key: key.clone(),
                },
                lifetime,
            )
        });
        let blob = key.key_blob();
        let provider = Arc::make_mut(&mut self.provider);
        match provider.iter_mut().find(|e| e.key_blob == blob) {
            Some(entry) => entry.certs.extend(attached),
            None => provider.push(ProviderEntry {
                key_blob: blob,
                meta: KeyMeta::default(),
                certs: attached.collect(),
            }),
        }
    }

    /// Stop serving `certs`, if `ssh-add -s` attached them to the key
    /// `key_blob`.
    fn detach_provider_certs(&mut self, key_blob: &[u8], certs: &[CertKey]) {
        let ours =
            |c: &Expiring<ProviderCert>| certs.iter().any(|cert| cert.blob() == c.item.cert.blob());
        if !self
            .provider_entry(key_blob)
            .is_some_and(|e| e.certs.iter().any(ours))
        {
            return;
        }
        let provider = Arc::make_mut(&mut self.provider);
        provider
            .iter_mut()
            .filter(|e| e.key_blob == key_blob)
            .for_each(|e| e.certs.retain(|c| !ours(c)));
        provider.retain(|e| !e.is_empty());
    }

    /// Forget what `ssh-add -s` attached to the key `key_blob`, which its
    /// backend stopped serving: its certificates and, once something was
    /// removed (`served` says whether the key itself was), its constraints.
    /// Returns whether any certificate was dropped.
    fn release(&mut self, key_blob: &[u8], served: bool) -> bool {
        let Some(entry) = self.provider_entry(key_blob) else {
            return false;
        };
        let dropped = !entry.certs.is_empty();
        if served || dropped {
            Arc::make_mut(&mut self.provider).retain(|e| e.key_blob != key_blob);
        }
        dropped
    }

    /// The constraints `constraints` points at, as of this snapshot.
    fn resolve(&self, constraints: Constraints) -> KeyMeta {
        match constraints {
            Constraints::Own(meta) => meta,
            Constraints::Provider(blob) => self.backend_meta(&blob),
        }
    }

    /// The constraints of the backend key `key_blob`: those it was added
    /// with by `ssh-add FILE` too, if it was, else those of `ssh-add -s`.
    /// A backend serving the same key does not lift its `-c`/`-h`.
    fn backend_meta(&self, key_blob: &[u8]) -> KeyMeta {
        match self.held_key(key_blob) {
            Some((_, meta)) => meta.clone(),
            None => self.provider_meta(key_blob).cloned().unwrap_or_default(),
        }
    }

    /// Whether a backend key's constraints may differ between this snapshot
    /// and `other`: false only when neither the added keys nor what
    /// `ssh-add -s` attached were replaced.
    fn backend_meta_may_differ(&self, other: &Store) -> bool {
        !(Arc::ptr_eq(&self.provider, &other.provider) && Arc::ptr_eq(&self.held, &other.held))
    }

    /// Whether this snapshot and `other` hold the same keys, certificates
    /// and constraints: true only when no collection was replaced.
    fn same_keys(&self, other: &Store) -> bool {
        Arc::ptr_eq(&self.held, &other.held)
            && Arc::ptr_eq(&self.provider, &other.provider)
            && Arc::ptr_eq(&self.served, &other.served)
    }

    fn clear(&mut self) {
        *self = Store::default();
    }
}

/// An agent's lock that is held while user code is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// `changes`, while a key change commits.
    Change,
    /// `lock_state`, while the agent is locked or unlocked.
    Lock,
}

/// Wrong unlock passphrases since the last good one, and when the next
/// guess may be checked: each failure delays the next by 0.1 s more.
#[derive(Debug, Default)]
struct LockState {
    failures: u32,
    next_guess: Option<Instant>,
}

thread_local! {
    /// The agents, by address, and their locks this thread holds.
    static HELD: RefCell<Vec<(usize, Turn)>> = const { RefCell::new(Vec::new()) };
}

/// Records, while it lives, that this thread holds `turn` of one agent, so
/// that a callback on this thread asking for it again is refused rather
/// than left waiting on itself.
struct Holding {
    agent: usize,
    turn: Turn,
}

impl Holding {
    /// Record `turn` of `agent`, unless this thread holds it already.
    fn enter(agent: &Agent, turn: Turn) -> Option<Holding> {
        let agent = std::ptr::from_ref(agent) as usize;
        let held = HELD.with(|held| held.borrow().contains(&(agent, turn)));
        if held {
            tracing::error!(
                ?turn,
                "refused: asked for from a callback of the same request, on the same \
                 thread, so it would wait on itself"
            );
            return None;
        }
        HELD.with(|held| held.borrow_mut().push((agent, turn)));
        Some(Holding { agent, turn })
    }
}

impl Drop for Holding {
    fn drop(&mut self) {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(at) = held.iter().rposition(|h| *h == (self.agent, self.turn)) {
                held.remove(at);
            }
        });
    }
}

/// This thread's turn to commit a key change to one agent.
struct ChangeTurn<'a> {
    _changes: MutexGuard<'a, ()>,
    _holding: Holding,
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    /// An agent with no keys yet: it serves what `ssh-add FILE` adds, in the
    /// built-in key types, until backends and the rest are registered.
    pub fn new() -> Self {
        Agent {
            backends: Vec::new(),
            smartcard: None,
            store: ArcSwap::from_pointee(Store::default()),
            changes: Mutex::new(()),
            extensions: ArcSwap::from_pointee(Vec::new()),
            key_types: ArcSwap::from_pointee(KeyRegistry::builtin()),
            confirm: None,
            policy: None,
            lifecycle: Vec::new(),
            locker: Arc::new(PassphraseLock::default()),
            default_lifetime: None,
            lock_state: Mutex::default(),
            unlock_backoff: UNLOCK_BACKOFF,
        }
    }

    /// Serve the identities of `backend`, listed before any added with
    /// `ssh-add FILE`, in registration order.
    pub fn with_backend(mut self, backend: Arc<dyn Backend>) -> Self {
        self.backends.push(backend);
        self
    }

    /// Answer `ssh-add -s`/`-e` with `provider`. Without one they fail.
    pub fn with_smartcard(mut self, provider: Arc<dyn SmartcardProvider>) -> Self {
        self.smartcard = Some(provider);
        self
    }

    /// Ask the user through `confirm` before each use of a key added with
    /// `ssh-add -c`.
    pub fn with_confirm(mut self, confirm: Arc<dyn Confirm>) -> Self {
        self.confirm = Some(confirm);
        self
    }

    /// Check every signature and key change against `policy`.
    pub fn with_policy(mut self, policy: Arc<dyn Policy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Tell `hook` when the agent is locked, unlocked or cleared.
    pub fn with_lifecycle(mut self, hook: Arc<dyn Lifecycle>) -> Self {
        self.lifecycle.push(hook);
        self
    }

    /// Keep the `ssh-add -x` lock with `locker` instead of a passphrase hash.
    pub fn with_locker(mut self, locker: Arc<dyn Locker>) -> Self {
        self.locker = locker;
        self
    }

    /// Give keys added without an `ssh-add -t` constraint a lifetime of
    /// `seconds`, as `ssh-agent -t` does. Zero or `None` means no default.
    pub fn with_default_lifetime(mut self, seconds: Option<u32>) -> Self {
        self.default_lifetime = seconds.filter(|secs| *secs > 0);
        self
    }

    /// Wait `backoff` longer after each wrong unlock passphrase (0.1 s by
    /// default, as in OpenSSH), up to 100 times that.
    pub fn with_unlock_backoff(mut self, backoff: Duration) -> Self {
        self.unlock_backoff = backoff;
        self
    }

    /// Register a protocol extension handler and return the agent, for the
    /// builder style of [`Self::new`]. A later registration under the same
    /// name wins.
    pub fn with_extension(self, extension: impl Extension + 'static) -> Self {
        self.register_extension(extension);
        self
    }

    /// Register a protocol extension handler, answering
    /// `SSH_AGENTC_EXTENSION` requests whose name it matches. A later
    /// registration under the same name wins.
    pub fn register_extension(&self, extension: impl Extension + 'static) {
        // Its name is read here, once, not in the `rcu`, which may run again.
        let name = extension.name().to_owned();
        let extension: Arc<dyn Extension> = Arc::new(extension);
        self.extensions.rcu(|current| {
            let mut extensions = Vec::clone(current);
            extensions.retain(|(registered, _)| *registered != name);
            extensions.push((name.clone(), Arc::clone(&extension)));
            extensions
        });
    }

    /// Register a key-type decoder for `ssh-add FILE` and return the agent,
    /// for the builder style of [`Self::new`]. A later registration under a
    /// name wins, so a built-in key type can be replaced as well as extended.
    pub fn with_key_type(self, decoder: impl KeyDecoder + 'static) -> Self {
        self.register_key_type(decoder);
        self
    }

    /// Register a key-type decoder, consulted for `SSH2_AGENTC_ADD_IDENTITY`
    /// requests whose key type it answers. A later registration under a name
    /// wins.
    pub fn register_key_type(&self, decoder: impl KeyDecoder + 'static) {
        // Its key types are read here, once, not in the `rcu`, which may
        // run again.
        let decoder = Registered::new(Arc::new(decoder));
        self.key_types.rcu(|current| {
            let mut registry = KeyRegistry::clone(current);
            registry.register_shared(decoder.clone());
            registry
        });
    }

    /// The lifetime keys get without their own `ssh-add -t`.
    pub fn default_lifetime(&self) -> Option<u32> {
        self.default_lifetime
    }

    /// Serve a key added with `ssh-add FILE`, with an optional lifetime from
    /// `ssh-add -t`. A key already served is replaced, so a fresh lifetime
    /// takes effect; it keeps the `ssh-add -c`/`-h` constraints it was
    /// added with.
    pub fn add_key(&self, key: SignerRef, lifetime: Option<u32>) {
        self.add_held(key, None, lifetime, None);
    }

    /// Serve `key` added with `ssh-add FILE`, or `cert` with it as its
    /// signer, constrained by `meta`, or without one by the constraints the
    /// identity already has. The constraints go on that identity alone: a
    /// key and its certificate are constrained separately.
    fn add_held(
        &self,
        key: SignerRef,
        cert: Option<CertKey>,
        lifetime: Option<u32>,
        meta: Option<KeyMeta>,
    ) {
        match cert {
            Some(cert) => {
                tracing::info!(
                    comment = key.comment(),
                    key_id = cert.certificate().key_id(),
                    "serving added certificate"
                );
                self.write(|store| {
                    let meta = meta
                        .clone()
                        .or_else(|| store.held_cert_meta(cert.blob()).cloned());
                    store.hold_cert(
                        key.clone(),
                        cert.clone(),
                        meta.unwrap_or_default(),
                        lifetime,
                    )
                });
            }
            None => {
                tracing::info!(comment = key.comment(), "serving added key");
                self.write(|store| {
                    let meta = meta
                        .clone()
                        .or_else(|| store.held_key(&key.key_blob()).map(|(_, m)| m.clone()));
                    store.hold(key.clone(), meta.unwrap_or_default(), lifetime)
                });
            }
        }
    }

    /// Serve certificates for backend keys. Each is listed, under its file's
    /// comment (else its key id), while a backend serves a key it certifies
    /// and it has not expired.
    pub fn with_certificates(self, certs: impl IntoIterator<Item = CertKey>) -> Self {
        let served: Vec<ServedCert> = certs
            .into_iter()
            .map(|cert| {
                let comment = match cert.comment() {
                    "" => cert.certificate().key_id().to_owned(),
                    comment => comment.to_owned(),
                };
                ServedCert { cert, comment }
            })
            .collect();
        self.write(|store| Arc::make_mut(&mut store.served).extend(served.iter().cloned()));
        self
    }

    /// Serve the certificate `ssh-add FILE` sent with its private key, with
    /// an optional lifetime from `ssh-add -t` (which ssh-add sets to the
    /// certificate's expiry on its own). The certificate is listed under the
    /// key's comment, and a certificate already served is replaced, keeping
    /// the `ssh-add -c`/`-h` constraints it was added with.
    pub fn add_cert_key(&self, key: SignerRef, cert: CertKey, lifetime: Option<u32>) {
        self.add_held(key, Some(cert), lifetime, None);
    }

    /// Stop serving the certificate whose blob is `blob`. Returns whether
    /// anything was removed.
    pub fn remove_cert(&self, blob: &[u8]) -> bool {
        self.write(|store| store.take_cert(blob))
    }

    /// Forget what the agent attached to a backend key that its backend
    /// stopped serving on its own: the certificates `ssh-add -s` attached to
    /// it and, once something was removed (`served` says whether the key
    /// itself was), its `ssh-add -c`/`-h` constraints. Returns whether any
    /// certificate was dropped.
    pub fn release(&self, key_blob: &[u8], served: bool) -> bool {
        self.write(|store| store.release(key_blob, served))
    }

    /// Stop serving the key added with `ssh-add FILE` whose public key blob is
    /// `key_blob`. Returns whether anything was removed.
    pub fn remove_key(&self, key_blob: &[u8]) -> bool {
        self.write(|store| store.remove_held(key_blob))
    }

    /// Whether `ssh-add -x` has locked the agent.
    pub fn is_locked(&self) -> bool {
        self.locker.is_locked()
    }

    /// Lock with `passphrase`; fails if already locked, as in OpenSSH. The
    /// [`Lifecycle::locked`] hooks run before any other lock or unlock, and
    /// one asked for from a hook, on the same thread, fails.
    pub fn lock(&self, passphrase: &[u8]) -> bool {
        let Some(_holding) = Holding::enter(self, Turn::Lock) else {
            return false;
        };
        let _state = lock(&self.lock_state);
        let locked = self.locker.lock(passphrase);
        if locked {
            self.lifecycle.iter().for_each(|hook| hook.locked());
        }
        locked
    }

    /// Unlock if `passphrase` is the one the agent was locked with, as
    /// [`Self::lock`] locks. Unlike `ssh-add -X`, a wrong passphrase is
    /// neither counted nor delayed: this is the owner's own call.
    pub fn unlock(&self, passphrase: &[u8]) -> bool {
        let Some(_holding) = Holding::enter(self, Turn::Lock) else {
            return false;
        };
        let _state = lock(&self.lock_state);
        let unlocked = self.locker.unlock(passphrase);
        if unlocked {
            self.lifecycle.iter().for_each(|hook| hook.unlocked());
        }
        unlocked
    }

    /// Drop identities whose lifetime has elapsed, in the backends too.
    /// Every read drops the agent's own expired identities as well.
    pub fn purge_expired(&self) {
        self.purge_backends();
        self.snapshot();
    }

    fn purge_backends(&self) {
        for backend in &self.backends {
            backend.purge_expired();
        }
    }

    /// The store as it is now. It never changes, however many writes follow.
    /// One holding expired identities is replaced by a copy without them
    /// first, so their secrets are freed as soon as anything reads.
    fn snapshot(&self) -> Arc<Store> {
        let current = self.store.load_full();
        if !current.has_expired() {
            return current;
        }
        self.write(|_| ());
        self.store.load_full()
    }

    /// Take the turn to commit a key change, waiting for any other
    /// connection's commit. Refused, with an error logged, when this thread
    /// already holds it, as a callback called during a commit would, since
    /// waiting would never end; and once the agent is locked, which it may
    /// have been while this change waited.
    fn take_turn(&self) -> Option<ChangeTurn<'_>> {
        let holding = Holding::enter(self, Turn::Change)?;
        let turn = ChangeTurn {
            _changes: lock(&self.changes),
            _holding: holding,
        };
        if self.is_locked() {
            tracing::warn!("refused: the agent is locked");
            return None;
        }
        Some(turn)
    }

    /// Prepare a key change, then take the turn to commit it. `prepare`
    /// runs with no lock held, against a snapshot: it looks keys up and asks
    /// the policy, user code that only reads, so none of it can wait on a
    /// commit. If the keys changed before the turn was taken, it runs again
    /// on the newer snapshot; if they keep changing, the change is refused.
    /// The commit, under the returned turn, makes only the calls that change
    /// a backend or provider, and the store writes.
    ///
    /// Only the store is compared. A change inside a backend or provider,
    /// such as a key it dropped on its own, is not seen, so what `prepare`
    /// learned from them may be out of date by the commit; each commit
    /// checks again what it relies on, such as a removal that finds no key
    /// failing, or a certificate taken back from a key no longer served.
    ///
    /// Fails with what `prepare` failed with, or with `None` when the turn
    /// was refused (see [`Self::take_turn`]) or the keys kept changing.
    fn prepared_turn<P, E>(
        &self,
        mut prepare: impl FnMut(&Store) -> Result<P, E>,
    ) -> Result<(P, ChangeTurn<'_>), Option<E>> {
        for _ in 0..LOOKUP_ATTEMPTS {
            let seen = self.snapshot();
            let prepared = prepare(&seen).map_err(Some)?;
            let turn = self.take_turn().ok_or(None)?;
            if self.snapshot().same_keys(&seen) {
                return Ok((prepared, turn));
            }
            tracing::debug!("keys changed while a key change was prepared");
        }
        tracing::warn!("keys kept changing; key change refused");
        Err(None)
    }

    /// Change the store: `change` runs on a copy of the current snapshot,
    /// with expired identities dropped, and the copy is published unless
    /// another write was published first, in which case `change` runs again
    /// on the newer snapshot. It may therefore run more than once, and must
    /// do nothing but change the store. Returns what the published run did.
    fn write<R>(&self, mut change: impl FnMut(&mut Store) -> R) -> R {
        let mut result = None;
        self.store.rcu(|current| {
            let mut next = Store::clone(current);
            next.purge_expired();
            result = Some(change(&mut next));
            next
        });
        result.expect("rcu runs the change at least once")
    }

    /// Public keys for every identity: each backend's, fetched as needed,
    /// then those added with `ssh-add FILE`.
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.purge_backends();
        let mut keys: Vec<PublicKey> = self
            .backends
            .iter()
            .flat_map(|b| b.identities())
            .map(|key| key.public_key().clone())
            .collect();
        keys.extend(
            self.snapshot()
                .held_keys()
                .map(|(key, _)| key.public_key().clone()),
        );
        keys
    }

    /// Every identity the agent lists: the public keys of [`Self::public_keys`]
    /// followed by the certificates whose key is served. A certificate past
    /// its validity is left out.
    pub fn identities(&self) -> Vec<wire::Listed> {
        self.identities_for(&Connection::default())
    }

    /// The identities listed on this connection. A destination-constrained
    /// key is left out when the connection's session bindings do not permit
    /// it, as OpenSSH's agent does, and so is one the policy hides
    /// ([`Policy::allow_list`]).
    ///
    /// The backends' keys are not in the store snapshot a listing reads, so
    /// a listing during which a listed key's constraints changed is taken
    /// again; if they keep changing, none is listed rather than one its
    /// constraints might hide. Other keys' constraints may change freely.
    /// The policy is asked once, about the listing finally taken.
    pub fn identities_for(&self, connection: &Connection) -> Vec<wire::Listed> {
        for _ in 0..LOOKUP_ATTEMPTS {
            let before = self.snapshot();
            let mut consulted = Vec::new();
            let listed = self.list_identities(&before, connection, &mut consulted);
            let after = self.snapshot();
            if !before.backend_meta_may_differ(&after)
                || consulted
                    .iter()
                    .all(|blob| before.backend_meta(blob) == after.backend_meta(blob))
            {
                return listed
                    .into_iter()
                    .filter(|c| {
                        self.listing_allowed(c.key.public_key(), c.cert.as_ref(), connection)
                    })
                    .map(|c| c.listed)
                    .collect();
            }
            tracing::debug!("key constraints changed during the listing");
        }
        tracing::warn!("key constraints kept changing; listing no identities");
        Vec::new()
    }

    /// One pass of [`Self::identities_for`] over `store`, which may be out
    /// of date by the time the backends answer: the identities whose
    /// constraints permit this connection, before the policy is asked. The
    /// backend keys whose constraints it read go in `consulted`.
    fn list_identities(
        &self,
        store: &Store,
        connection: &Connection,
        consulted: &mut Vec<Vec<u8>>,
    ) -> Vec<Listing> {
        let mut out = Vec::new();
        self.purge_backends();
        for key in self.backends.iter().flat_map(|b| b.identities()) {
            let blob = key.key_blob();
            let meta = store.resolve(Constraints::Provider(blob.clone()));
            consulted.push(blob);
            if permitted(&meta, connection) {
                out.push(Listing {
                    listed: wire::listed(key.public_key()),
                    key,
                    cert: None,
                });
            }
        }
        for (key, meta) in store.held_keys() {
            if permitted(meta, connection) {
                out.push(Listing {
                    listed: wire::listed(key.public_key()),
                    key: key.clone(),
                    cert: None,
                });
            }
        }
        for identity in store.certs() {
            if identity.cert.expired() {
                tracing::debug!(
                    key_id = identity.cert.certificate().key_id(),
                    "certificate has expired; not listed"
                );
                continue;
            }
            let Some((signer, constraints)) = self.cert_signer(&identity) else {
                continue;
            };
            if let Constraints::Provider(blob) = &constraints {
                consulted.push(blob.clone());
            }
            if permitted(&store.resolve(constraints), connection) {
                out.push(Listing {
                    listed: (identity.cert.blob().to_vec(), identity.comment.to_owned()),
                    key: signer,
                    cert: Some(identity.cert.clone()),
                });
            }
        }
        out
    }

    /// Whether the policy lets this connection see `key`, or `certificate`
    /// for it, in a listing.
    fn listing_allowed(
        &self,
        key: &PublicKey,
        certificate: Option<&CertKey>,
        connection: &Connection,
    ) -> bool {
        let request = ListInfo {
            key,
            certificate,
            connection,
        };
        let allowed = self.policy.as_ref().is_none_or(|p| p.allow_list(&request));
        if !allowed {
            tracing::debug!(key = key.comment(), "not listed: the policy hides it");
        }
        allowed
    }

    /// Certificates served for `key`, a backend or added key.
    pub fn certificates_for(&self, key: &PublicKey) -> Vec<CertKey> {
        self.snapshot()
            .certs()
            .filter(|c| c.cert.certifies(key) && !c.cert.expired())
            .map(|c| c.cert.clone())
            .collect()
    }

    /// The key that signs for a certificate, if it is served, and where the
    /// certificate's constraints are kept.
    fn cert_signer(&self, identity: &CertIdentity<'_>) -> Option<(SignerRef, Constraints)> {
        match identity.signer {
            CertSigner::Held { key, meta } => {
                Some(((*key).clone(), Constraints::Own(meta.clone())))
            }
            CertSigner::Provider(key) => {
                Some(((*key).clone(), Constraints::Provider(key.key_blob())))
            }
            CertSigner::Served => self
                .backends
                .iter()
                .flat_map(|b| b.known())
                .find(|key| identity.cert.certifies(key.public_key()))
                .map(|key| {
                    let blob = key.key_blob();
                    (key, Constraints::Provider(blob))
                }),
        }
    }

    /// The backend key whose public key blob is `key_blob`, if it is known.
    fn backend_key(&self, key_blob: &[u8]) -> Option<SignerRef> {
        self.backends
            .iter()
            .flat_map(|b| b.known())
            .find(|key| key.key_blob() == key_blob)
    }

    /// Handle one request body and produce the reply body.
    ///
    /// The lock is checked once: a locked agent lists no keys and serves
    /// only unlock and protocol extensions.
    ///
    /// This entry point gives the request a fresh [`Connection`], so its
    /// session bindings do not outlive it. A server should use
    /// [`Self::handle_in`] with one [`Connection`] per client connection.
    pub fn handle(&self, body: &[u8]) -> Vec<u8> {
        self.handle_in(body, &mut Connection::default())
    }

    /// Handle one request body on `connection`, which keeps the session
    /// bindings a client records with `session-bind@openssh.com` for the life
    /// of its connection.
    pub fn handle_in(&self, body: &[u8], connection: &mut Connection) -> Vec<u8> {
        let request = wire::parse_request_with(&self.key_types.load_full(), body);
        let request = match request {
            Ok(request) => request,
            Err(e) => {
                tracing::warn!(error = %e, "bad request");
                return wire::failure();
            }
        };
        if self.is_locked() {
            self.handle_locked(request, connection)
        } else {
            self.handle_unlocked(request, connection)
        }
    }

    /// Answer a request while `ssh-add -x` has locked the agent: no keys are
    /// listed, unlock and protocol extensions are served, and everything
    /// else is refused, including request types added later.
    fn handle_locked(&self, request: Request, connection: &mut Connection) -> Vec<u8> {
        match request {
            Request::RequestIdentities => {
                tracing::debug!("listing identities: agent is locked, none");
                wire::identities_answer(&[])
            }
            Request::RequestRsaIdentities => {
                tracing::debug!("SSH v1 identities request: answering with none");
                wire::rsa_identities_answer()
            }
            Request::Unlock(passphrase) => self.handle_unlock(&passphrase),
            Request::Extension { name, data } => self.handle_extension(&name, &data, connection),
            Request::Unsupported(kind) => {
                tracing::debug!(kind, "unsupported request");
                wire::failure()
            }
            other => {
                tracing::warn!(request = other.name(), "refused: agent is locked");
                wire::failure()
            }
        }
    }

    /// Whether the policy allows `change` on this connection.
    fn manage_allowed(&self, change: KeyChange<'_>, connection: &Connection) -> bool {
        let request = ManageInfo { change, connection };
        let allowed = self
            .policy
            .as_ref()
            .is_none_or(|p| p.allow_manage(&request));
        if !allowed {
            tracing::warn!("refused: the policy forbids this key change");
        }
        allowed
    }

    /// Answer a request while the agent is unlocked.
    ///
    /// Reads work on a store snapshot and never wait. Key changes are
    /// prepared without a lock and committed one at a time (see
    /// [`Self::prepared_turn`]).
    fn handle_unlocked(&self, request: Request, connection: &mut Connection) -> Vec<u8> {
        match request {
            Request::RequestIdentities => {
                let identities = self.identities_for(connection);
                tracing::debug!(count = identities.len(), "listing identities");
                wire::identities_answer(&identities)
            }
            Request::RequestRsaIdentities => {
                tracing::debug!("SSH v1 identities request: answering with none");
                wire::rsa_identities_answer()
            }
            Request::Sign {
                key_blob,
                data,
                flags,
            } => {
                tracing::debug!(len = data.len(), flags, "sign request");
                match self.sign(&key_blob, &data, flags, connection) {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!(error = %e, "sign request failed");
                        wire::failure()
                    }
                }
            }
            Request::Lock(passphrase) => {
                if self.lock(&passphrase) {
                    tracing::info!("agent locked");
                    wire::success()
                } else {
                    tracing::warn!("lock request refused: already locked");
                    wire::failure()
                }
            }
            Request::Unlock(passphrase) => self.handle_unlock(&passphrase),
            Request::AddIdentity {
                key,
                cert,
                lifetime,
                confirm,
                destination,
            } => {
                let lifetime = self.lifetime_for(lifetime);
                // The identity this add replaces: a certificate is
                // constrained apart from its key.
                let blob = match &cert {
                    Some(cert) => cert.blob().to_vec(),
                    None => key.key_blob(),
                };
                let prepared = self.prepared_turn(|store| {
                    let change = KeyChange::Add {
                        key: key.public_key(),
                        certificate: cert.as_deref(),
                        constraints: KeyConstraints {
                            lifetime,
                            confirm,
                            destination: &destination,
                        },
                    };
                    if !self.manage_allowed(change, connection) {
                        return Err(());
                    }
                    if !self.may_manage(store, &blob, connection) {
                        tracing::warn!("refused: key not permitted on this connection");
                        return Err(());
                    }
                    Ok(())
                });
                let Ok(((), _turn)) = prepared else {
                    return wire::failure();
                };
                let meta = KeyMeta {
                    confirm,
                    destination,
                };
                self.add_held(key, cert.map(|cert| *cert), lifetime, Some(meta));
                wire::success()
            }
            Request::RemoveIdentity { key_blob } => {
                let prepared = self.prepared_turn(|store| {
                    let target = self.lookup(store, &key_blob).ok().map(|(key, _)| key);
                    let change = KeyChange::Remove {
                        key_blob: &key_blob,
                        key: target.as_ref().map(|t| t.public_key()),
                    };
                    if !self.manage_allowed(change, connection) {
                        return Err(());
                    }
                    if !self.may_manage(store, &key_blob, connection) {
                        tracing::warn!("refused: key not permitted on this connection");
                        return Err(());
                    }
                    Ok(self.backend_key(&key_blob).is_some())
                });
                let Ok((from_backend, _turn)) = prepared else {
                    return wire::failure();
                };
                let removed = self.write(|store| {
                    if store.remove_held(&key_blob) {
                        Some("removed added key")
                    } else if store.take_cert(&key_blob) {
                        Some("removed certificate")
                    } else {
                        None
                    }
                });
                if let Some(removed) = removed {
                    tracing::info!("{removed}");
                    wire::success()
                } else if from_backend && self.backends.iter().any(|b| b.remove(&key_blob)) {
                    self.release(&key_blob, true);
                    tracing::info!("removed key");
                    wire::success()
                } else {
                    tracing::debug!("no such key to remove");
                    wire::failure()
                }
            }
            Request::RemoveAllIdentities => {
                let prepared = self.prepared_turn(|_| {
                    match self.manage_allowed(KeyChange::RemoveAll, connection) {
                        true => Ok(()),
                        false => Err(()),
                    }
                });
                let Ok(((), _turn)) = prepared else {
                    return wire::failure();
                };
                self.remove_all();
                // In the turn, so no other change lands between the keys
                // going and the hooks hearing of it.
                self.lifecycle.iter().for_each(|hook| hook.cleared());
                tracing::info!("removed every identity");
                wire::success()
            }
            // As OpenSSH refuses remote provider adds: a forwarded hop needs
            // only a key's name to re-add it, which would drop its
            // `ssh-add -c`/`-h` constraints.
            Request::AddSmartcardKey { .. } | Request::RemoveSmartcardKey { .. }
                if connection.bind_attempted() =>
            {
                tracing::warn!("refused: provider keys are managed only on a local connection");
                wire::failure()
            }
            Request::AddSmartcardKey {
                provider,
                pin,
                lifetime,
                confirm,
                destination,
                certs,
            } => {
                let meta = KeyMeta {
                    confirm,
                    destination,
                };
                match self.add_smartcard(&provider, &pin, lifetime, meta, certs, connection) {
                    Ok(()) => wire::success(),
                    Err(Some(e)) => {
                        tracing::warn!(error = %e, "cannot add provider key");
                        wire::failure()
                    }
                    Err(None) => wire::failure(),
                }
            }
            Request::RemoveSmartcardKey { provider } => {
                let prepared = self.prepared_turn(|_| {
                    let change = KeyChange::RemoveProvider {
                        provider: &provider,
                    };
                    match self.manage_allowed(change, connection) {
                        true => Ok(()),
                        false => Err(()),
                    }
                });
                let Ok(((), _turn)) = prepared else {
                    return wire::failure();
                };
                match self.remove_smartcard(&provider) {
                    Ok(true) => {
                        tracing::info!("removed provider key");
                        wire::success()
                    }
                    Ok(false) => {
                        tracing::debug!("no such provider key to remove");
                        wire::failure()
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "cannot remove provider key");
                        wire::failure()
                    }
                }
            }
            Request::Extension { name, data } => self.handle_extension(&name, &data, connection),
            Request::Unsupported(kind) => {
                tracing::debug!(kind, "unsupported request");
                wire::failure()
            }
        }
    }

    /// `ssh-add -s PROVIDER [CERT…]`: serve the key the provider names
    /// (unless `ssh-add -C` asked for its certificates only) and the given
    /// certificates that certify it; the others are skipped. Fails when only
    /// certificates were asked for and none certifies the key. The policy is
    /// asked once the key is fetched, so it can decide by the key.
    ///
    /// The key is fetched once, before the change is prepared, since that
    /// may ask for the PIN; only [`SmartcardProvider::add`] runs while the
    /// change holds its turn. Fails with `None` when the turn was refused.
    fn add_smartcard(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
        requested: KeyMeta,
        certs: Option<AssociatedCerts>,
        connection: &Connection,
    ) -> Result<(), Option<AgentError>> {
        let source = self
            .smartcard
            .as_ref()
            .ok_or(AgentError::NoSmartcardProvider)?;
        let lifetime = self.lifetime_for(lifetime);
        self.purge_backends();
        // Fetch the key first: its blob names the constraints.
        let key = source.resolve(provider, pin).map_err(AgentError::Backend)?;
        let blob = key.key_blob();
        let certs_only = certs.as_ref().is_some_and(|c| c.certs_only);
        let offered = certs.map(|c| c.certs).unwrap_or_default();
        let prepared = self.prepared_turn(|store| {
            let served = self.backend_key(&blob).is_some();
            // `ssh-add -C` adds certificates alone: for a key served under
            // constraints they share those, rather than replace them for the
            // key and every certificate it already has.
            let meta = match store.provider_meta(&blob) {
                Some(current) if certs_only && served => {
                    if *current != requested {
                        tracing::info!(
                            key = key.comment(),
                            "certificates take the served key's constraints"
                        );
                    }
                    current.clone()
                }
                _ => requested.clone(),
            };
            let change = KeyChange::AddProvider {
                provider,
                key: key.public_key(),
                certificates: &offered,
                certificates_only: certs_only,
                constraints: KeyConstraints {
                    lifetime,
                    confirm: meta.confirm,
                    destination: &meta.destination,
                },
            };
            if !self.manage_allowed(change, connection) {
                return Err(AgentError::PolicyRefused);
            }
            Ok((meta, served))
        });
        let ((meta, served), turn) = prepared?;
        let (matching, others): (Vec<_>, Vec<_>) = offered
            .into_iter()
            .partition(|c| c.certifies(key.public_key()));
        if !others.is_empty() {
            tracing::warn!(
                key = key.comment(),
                skipped = others.len(),
                "certificates for another key skipped"
            );
        }
        if matching.is_empty() && certs_only {
            return Err(Some(AgentError::NoMatchingCertificate));
        }
        self.publish_constrained(blob.clone(), meta.clone(), served, || {
            if !certs_only {
                source
                    .add(provider, pin, lifetime)
                    .map_err(AgentError::Backend)?;
            }
            Ok(())
        })?;
        if matching.is_empty() {
            return Ok(());
        }
        // Still in the turn, so another connection's `ssh-add -e` comes
        // after and its release takes them; once the key's constraints are
        // in place, so a certificate is never served under the ones it had
        // before; and only while they are: a backend that released the key
        // meanwhile took them with it.
        let attached = self.write(|store| {
            if !meta.is_empty() && store.provider_meta(&blob) != Some(&meta) {
                return false;
            }
            store.attach_provider_certs(&key, &matching, lifetime);
            true
        });
        drop(turn);
        if !attached {
            tracing::warn!(
                key = key.comment(),
                "key released while its certificates were added"
            );
            return Err(Some(AgentError::UnknownKey));
        }
        // A backend may drop the key on its own, outside any key change, so
        // check it is served once the turn is given up, and if not take back
        // what this change attached. `ssh-add -C` served no key of its own.
        if !certs_only && self.backend_key(&blob).is_none() {
            self.write(|store| store.detach_provider_certs(&blob, &matching));
            tracing::warn!(
                key = key.comment(),
                "key released while its certificates were added"
            );
            return Err(Some(AgentError::UnknownKey));
        }
        for cert in &matching {
            tracing::info!(
                key = key.comment(),
                key_id = cert.certificate().key_id(),
                "serving certificate"
            );
        }
        Ok(())
    }

    /// `ssh-add -e PROVIDER`: stop serving the key it names and the
    /// certificates attached to it. Returns whether anything was removed.
    fn remove_smartcard(&self, provider: &[u8]) -> Result<bool, AgentError> {
        let source = self
            .smartcard
            .as_ref()
            .ok_or(AgentError::NoSmartcardProvider)?;
        let removed = source.remove(provider).map_err(AgentError::Backend)?;
        let mut any = removed.served;
        if let Some(blob) = removed.key_blob {
            any |= self.release(&blob, removed.served);
        }
        Ok(any)
    }

    /// `ssh-add -X`: unlock if the passphrase matches. Fails when the agent
    /// is not locked.
    ///
    /// A wrong passphrase is answered only after a delay that grows by 0.1 s
    /// with each failure, up to 10 s, as OpenSSH does, so the passphrase
    /// cannot be guessed quickly through the socket. Guesses are checked one
    /// at a time, each no sooner than the last one's delay ends, however
    /// many connections send them; no lock is held through a delay.
    fn handle_unlock(&self, passphrase: &[u8]) -> Vec<u8> {
        loop {
            let Some(holding) = Holding::enter(self, Turn::Lock) else {
                return wire::failure();
            };
            let mut state = lock(&self.lock_state);
            let now = Instant::now();
            if let Some(wait) = state
                .next_guess
                .and_then(|at| at.checked_duration_since(now))
            {
                drop(state);
                drop(holding);
                std::thread::sleep(wait);
                continue;
            }
            // Checked here, in turn, so a second right passphrase that waited
            // behind the first is not counted as a wrong one.
            if !self.locker.is_locked() {
                tracing::warn!("unlock request refused: agent is not locked");
                return wire::failure();
            }
            if self.locker.unlock(passphrase) {
                *state = LockState::default();
                self.lifecycle.iter().for_each(|hook| hook.unlocked());
                tracing::info!("agent unlocked");
                return wire::success();
            }
            state.failures = (state.failures + 1).min(MAX_UNLOCK_FAILURES);
            let delay = self.unlock_backoff * state.failures;
            state.next_guess = Some(now + delay);
            tracing::warn!(
                failures = state.failures,
                ?delay,
                "unlock request refused: wrong passphrase"
            );
            drop(state);
            drop(holding);
            std::thread::sleep(delay);
            return wire::failure();
        }
    }

    /// Answer an `SSH_AGENTC_EXTENSION` request. The built-in
    /// `session-bind@openssh.com` and `query` extensions are answered here; any
    /// other name goes to the handler registered under it, locked or not, which
    /// sees the lock state through [`ExtensionContext`] and decides for itself.
    fn handle_extension(&self, name: &str, data: &[u8], connection: &mut Connection) -> Vec<u8> {
        match name {
            destination::QUERY => {
                tracing::debug!("extension query");
                return destination::query_reply();
            }
            destination::SESSION_BIND => {
                return match session_bind(data, connection) {
                    Ok(()) => {
                        tracing::debug!("session bound");
                        wire::success()
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "session bind refused");
                        wire::failure()
                    }
                };
            }
            _ => {}
        }
        let extension = self
            .extensions
            .load()
            .iter()
            .rev()
            .find(|(registered, _)| registered == name)
            .map(|(_, extension)| Arc::clone(extension));
        match extension {
            Some(extension) => {
                tracing::debug!(extension = %name, "extension request");
                let ctx = ExtensionContext::new(self.is_locked());
                extension.handle(&ctx, data).into_body()
            }
            None => {
                tracing::debug!(extension = %name, "unsupported extension request");
                wire::extension_failure()
            }
        }
    }

    /// The constraints of the identity whose blob is `key_blob`, served or
    /// not: a key `ssh-add -s` added keeps them before it is served. Only a
    /// certificate [`Self::with_certificates`] serves asks the backends.
    fn constraints_of(&self, store: &Store, key_blob: &[u8]) -> KeyMeta {
        let constraints = if let Some((_, meta)) = store.held_key(key_blob) {
            Constraints::Own(meta.clone())
        } else if let Some((_, constraints)) = store
            .cert(key_blob)
            .and_then(|identity| self.cert_signer(&identity))
        {
            constraints
        } else {
            Constraints::Provider(key_blob.to_vec())
        };
        store.resolve(constraints)
    }

    /// The lifetime of a key added with `lifetime` from `ssh-add -t`: the
    /// agent's default without one. A zero, which `ssh-add` never sends, also
    /// gets the default rather than escaping it.
    fn lifetime_for(&self, lifetime: Option<u32>) -> Option<u32> {
        lifetime.filter(|secs| *secs > 0).or(self.default_lifetime)
    }

    /// Record `meta` for the key `blob` before `publish` serves it, so a sign
    /// on another connection never finds the key without its constraints.
    /// If publishing fails, the key's previous constraints are put back.
    ///
    /// A key already served under constraints (`served` says whether a
    /// backend serves it, as the change was prepared) keeps them until
    /// `publish` succeeds, so constraints that would lift some never take effect
    /// while it runs (a PIN prompt, say) or after it fails. Once it succeeds
    /// they are recorded again, in case a backend released the key, and its
    /// constraints with it, while re-serving it.
    fn publish_constrained<T>(
        &self,
        blob: Vec<u8>,
        meta: KeyMeta,
        served: bool,
        publish: impl FnOnce() -> Result<T, AgentError>,
    ) -> Result<T, AgentError> {
        let (previous, deferred) = self.write(|store| {
            let previous = store.provider_meta(&blob).cloned();
            let deferred = served && previous.is_some();
            if !deferred {
                store.set_provider_meta(blob.clone(), meta.clone());
            }
            (previous, deferred)
        });
        let published = publish();
        if published.is_ok() {
            // Again, if not yet: a backend may have released the key, and its
            // constraints with it, while re-serving it.
            self.write(|store| store.set_provider_meta(blob.clone(), meta.clone()));
        } else if !deferred {
            // Unless something else, such as a backend's `release`, changed
            // them meanwhile.
            let ours = (!meta.is_empty()).then_some(&meta);
            let previous = previous.unwrap_or_default();
            self.write(|store| {
                if store.provider_meta(&blob) == ours {
                    store.set_provider_meta(blob.clone(), previous.clone());
                }
            });
        }
        published
    }

    /// Whether this connection may add, replace or remove the key with
    /// `key_blob` in `store`, which a destination constraint can forbid even
    /// though the key is served.
    fn may_manage(&self, store: &Store, key_blob: &[u8], connection: &Connection) -> bool {
        permitted(&self.constraints_of(store, key_blob), connection)
    }

    /// Drop every identity: the backends', the keys added with
    /// `ssh-add FILE` and every certificate. Backs `ssh-add -D`.
    fn remove_all(&self) {
        for backend in &self.backends {
            backend.remove_all();
        }
        self.write(Store::clear);
    }

    /// Sign `data` with the key `key_blob` names, as a sign request on
    /// `connection` would, and return the `SSH2_AGENT_SIGN_RESPONSE` body.
    /// `flags` are the request's `SSH_AGENT_RSA_SHA2_*` bits.
    pub fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
        connection: &Connection,
    ) -> Result<Vec<u8>, AgentError> {
        let (signer, meta) = self.constrained_signer(key_blob)?;
        self.check_destination(&meta, key_blob, data, connection)?;
        let info = SignInfo {
            key: signer.public_key(),
            data,
            connection,
        };
        // Before the confirm prompt, so the user is never asked about a
        // signature the policy would refuse anyway.
        if let Some(policy) = &self.policy
            && !policy.allow_sign(&info)
        {
            return Err(AgentError::PolicyRefused);
        }
        if meta.confirm {
            self.confirm_use(&signer, data)?;
        }
        let hash = match wire::rsa_hash(flags) {
            Some(hash) => hash,
            None if signer.public_key().algorithm().is_rsa() => {
                return Err(AgentError::Sha1Requested);
            }
            None => HashAlg::default(),
        };
        let sig = signer.sign(data, hash).map_err(AgentError::Backend)?;
        signer.verify(data, &sig).map_err(AgentError::Backend)?;
        if let Some(policy) = &self.policy {
            policy.signed(&info);
        }
        Ok(wire::sign_response(&sig))
    }

    /// Enforce the `ssh-add -h` constraint of the key a sign request names:
    /// a destination-constrained key signs only a userauth request on a
    /// connection whose session binding the constraint permits.
    fn check_destination(
        &self,
        meta: &KeyMeta,
        requested_blob: &[u8],
        data: &[u8],
        connection: &Connection,
    ) -> Result<(), AgentError> {
        if !meta.destination.is_empty() {
            let last = connection
                .bindings()
                .last()
                .ok_or(AgentError::DestinationRefused)?;
            let userauth = destination::parse_userauth_request_for(data, requested_blob)
                .ok_or(AgentError::UnidentifiedSignature)?;
            let forwarded = connection.bindings().len() > 1 && userauth.hostkey.is_none();
            let mismatch = userauth
                .hostkey
                .as_ref()
                .is_some_and(|hostkey| hostkey.key_data() != last.key.key_data());
            if userauth.session_id != last.session_id
                || forwarded
                || mismatch
                || !connection.permits(&meta.destination, Some(&userauth.user))
            {
                return Err(AgentError::DestinationRefused);
            }
        }
        Ok(())
    }

    /// `ssh-add -c`: ask the user to allow this one use of `signer`. Without
    /// a [`Confirm`] prompt, or without a yes, the signature is refused.
    fn confirm_use(&self, signer: &SignerRef, data: &[u8]) -> Result<(), AgentError> {
        let key = signer.public_key();
        let request = ConfirmRequest {
            identity: key.comment().to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            subject: wire::describe_data(data),
        };
        let answer = self.confirm.as_ref().and_then(|c| c.confirm(&request));
        if answer != Some(true) {
            return Err(AgentError::ConfirmRefused);
        }
        Ok(())
    }

    /// The key that signs for `key_blob`, with the constraints it signs
    /// under. An added key's or certificate's constraints come from the
    /// snapshot it was found in. A backend key's are read again once it is
    /// found, since it is looked up outside the snapshot: if they changed
    /// meanwhile the lookup is taken again, and if they keep changing the
    /// key is refused rather than signed with under ones it no longer has,
    /// or does not have yet. Other keys' constraints may change freely.
    fn constrained_signer(&self, key_blob: &[u8]) -> Result<(SignerRef, KeyMeta), AgentError> {
        for _ in 0..LOOKUP_ATTEMPTS {
            let before = self.snapshot();
            let (signer, blob) = match self.lookup(&before, key_blob)? {
                (signer, Constraints::Own(meta)) => return Ok((signer, meta)),
                (signer, Constraints::Provider(blob)) => (signer, blob),
            };
            let after = self.snapshot();
            let meta = after.backend_meta(&blob);
            if !before.backend_meta_may_differ(&after) || before.backend_meta(&blob) == meta {
                return Ok((signer, meta));
            }
            tracing::debug!("key constraints changed during the lookup");
        }
        tracing::warn!("key constraints kept changing; refusing the sign");
        Err(AgentError::UnknownKey)
    }

    /// The key that signs for `key_blob`: a backend's key, one added with
    /// `ssh-add FILE`, or the key a served certificate certifies. Expired
    /// identities are skipped.
    pub fn signer_for(&self, key_blob: &[u8]) -> Result<SignerRef, AgentError> {
        self.lookup(&self.snapshot(), key_blob)
            .map(|(signer, _)| signer)
    }

    /// [`Self::signer_for`], with the added keys and certificates of
    /// `store`, and where the identity's constraints are kept.
    fn lookup(
        &self,
        store: &Store,
        key_blob: &[u8],
    ) -> Result<(SignerRef, Constraints), AgentError> {
        self.purge_backends();
        if let Some(key) = self.backend_key(key_blob) {
            return Ok((key, Constraints::Provider(key_blob.to_vec())));
        }
        if let Some((key, meta)) = store.held_key(key_blob) {
            return Ok((key.clone(), Constraints::Own(meta.clone())));
        }
        match store.cert(key_blob) {
            Some(identity) if identity.cert.expired() => {
                tracing::warn!(
                    key_id = identity.cert.certificate().key_id(),
                    "certificate has expired"
                );
                Err(AgentError::UnknownKey)
            }
            Some(identity) => self.cert_signer(&identity).ok_or(AgentError::UnknownKey),
            None => Err(AgentError::UnknownKey),
        }
    }
}

/// Whether constraints `meta` let the key be shown on this connection.
fn permitted(meta: &KeyMeta, connection: &Connection) -> bool {
    meta.destination.is_empty() || connection.permits(&meta.destination, None)
}

/// Parse and record one `session-bind@openssh.com` request:
/// `hostkey`, `session identifier`, `signature`, `is_forwarding`.
fn session_bind(data: &[u8], connection: &mut Connection) -> Result<(), destination::BindError> {
    let mut reader = data;
    let hostkey_blob = Vec::<u8>::decode(&mut reader)?;
    let hostkey = PublicKey::from_bytes(&hostkey_blob)?;
    let session_id = Vec::<u8>::decode(&mut reader)?;
    let signature = Vec::<u8>::decode(&mut reader)?;
    let forwarding = u8::decode(&mut reader)?;
    if !reader.is_empty() {
        return Err(destination::BindError::TrailingData);
    }
    connection.bind(hostkey, &session_id, &signature, forwarding != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    /// Make the added key at `index` in `store` expire now, as if its
    /// `ssh-add -t` lifetime had run out.
    fn expire_own(store: &mut Store, index: usize) {
        let own = Arc::make_mut(&mut store.held)[index].own.as_mut();
        own.expect("the key is served").expires = Some(Instant::now());
    }

    fn local_key(seed: u8, comment: &str) -> (Vec<u8>, PublicKey) {
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let public = PublicKey::new(ssh_key::public::KeyData::Ed25519(pair.public), comment);
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    /// The failure count stops at its cap, and so does the delay.
    #[test]
    fn the_unlock_failure_count_saturates() {
        let agent = Agent::new().with_unlock_backoff(Duration::ZERO);
        assert!(agent.lock(b"hunter2"));
        agent.lock_state.lock().unwrap().failures = MAX_UNLOCK_FAILURES;
        let mut wrong = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter3".as_slice().encode(&mut wrong).unwrap();
        assert_eq!(agent.handle(&wrong), wire::failure());
        assert_eq!(
            agent.lock_state.lock().unwrap().failures,
            MAX_UNLOCK_FAILURES
        );
    }

    /// Each wrong unlock passphrase waits longer than the last; the right one
    /// answers at once and resets the count.
    #[test]
    fn wrong_unlock_passphrases_are_slowed_down() {
        let agent = Agent::new().with_unlock_backoff(Duration::from_millis(20));
        assert!(agent.lock(b"hunter2"));

        let mut wrong = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter3".as_slice().encode(&mut wrong).unwrap();
        for failures in 1..=3u32 {
            let started = Instant::now();
            assert_eq!(agent.handle(&wrong), wire::failure());
            assert!(started.elapsed() >= Duration::from_millis(20) * failures);
            assert_eq!(agent.lock_state.lock().unwrap().failures, failures);
        }

        let mut right = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut right).unwrap();
        assert_eq!(agent.handle(&right), wire::success());
        assert_eq!(agent.lock_state.lock().unwrap().failures, 0);
    }

    /// Guesses sent on parallel connections wait their turn, so more
    /// connections do not mean more guesses per second.
    #[test]
    fn parallel_unlock_guesses_are_taken_one_at_a_time() {
        let agent = Agent::new().with_unlock_backoff(Duration::from_millis(20));
        assert!(agent.lock(b"hunter2"));
        let agent = Arc::new(agent);

        let mut wrong = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter3".as_slice().encode(&mut wrong).unwrap();
        let started = Instant::now();
        let guesses: Vec<_> = (0..4)
            .map(|_| {
                let agent = Arc::clone(&agent);
                let wrong = wrong.clone();
                std::thread::spawn(move || agent.handle(&wrong))
            })
            .collect();
        for guess in guesses {
            assert_eq!(guess.join().unwrap(), wire::failure());
        }
        // 20 + 40 + 60 + 80 ms one after another.
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn local_key_lifetime_expires() {
        let agent = Agent::new();
        let (add, _) = local_key(0x11, "ferris@example.com");
        // A constrained add with a one-second lifetime.
        let mut constrained = add;
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        1u32.encode(&mut constrained).unwrap();
        assert_eq!(agent.handle(&constrained), wire::success());
        assert_eq!(agent.public_keys().len(), 1);

        let blob = agent.snapshot().held[0].key.key_blob();
        // Pretend the lifetime elapsed.
        agent.write(|store| expire_own(store, 0));
        // The first read frees the key, without a write or the server's tick.
        assert!(agent.signer_for(&blob).is_err());
        assert!(agent.snapshot().held.is_empty());
        assert!(agent.public_keys().is_empty());
    }

    /// `ssh-agent -t`, as [`Agent::with_default_lifetime`]: keys added
    /// without their own lifetime get the default, and an explicit `-t` wins.
    #[test]
    fn default_lifetime_applies_to_added_keys() {
        let agent = Agent::new().with_default_lifetime(Some(60));
        let (add, _) = local_key(0x12, "default@example.com");
        assert_eq!(agent.handle(&add), wire::success());
        let expires = agent.snapshot().held[0]
            .own
            .as_ref()
            .unwrap()
            .expires
            .expect("the default set a lifetime");
        assert!(expires > Instant::now() + Duration::from_secs(30));

        // An explicit `ssh-add -t` lifetime is used instead of the default.
        let agent = Agent::new().with_default_lifetime(Some(60));
        let (mut constrained, _) = local_key(0x13, "explicit@example.com");
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        1u32.encode(&mut constrained).unwrap();
        assert_eq!(agent.handle(&constrained), wire::success());
        let expires = agent.snapshot().held[0]
            .own
            .as_ref()
            .unwrap()
            .expires
            .expect("the explicit lifetime was set");
        assert!(expires < Instant::now() + Duration::from_secs(5));

        // A zero lifetime does not escape the default.
        let (mut zero, _) = local_key(0x14, "zero@example.com");
        zero[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut zero)
            .unwrap();
        0u32.encode(&mut zero).unwrap();
        assert_eq!(agent.handle(&zero), wire::success());
        let expires = agent.snapshot().held[1]
            .own
            .as_ref()
            .unwrap()
            .expires
            .expect("the default set a lifetime");
        assert!(expires > Instant::now() + Duration::from_secs(30));
    }

    /// A constraint given twice is refused, as OpenSSH refuses it.
    #[test]
    fn a_duplicate_constraint_is_refused() {
        let agent = Agent::new();
        let (mut add, _) = local_key(0x15, "twice@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::failure());
        assert!(agent.snapshot().held.is_empty());
    }

    /// An `ssh-add -c` key re-added while another connection removes it is
    /// never served without its constraint: with no confirm prompt it must
    /// never sign, however the requests interleave.
    #[test]
    fn a_racing_remove_never_strips_a_constraint() {
        let agent = Arc::new(Agent::new());
        let (mut add, public) = local_key(0x16, "racy@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        let blob = public.to_bytes().unwrap();
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        blob.encode(&mut remove).unwrap();
        let sign = sign_body(&blob, b"data");

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spawn = |body: Vec<u8>| {
            let agent = Arc::clone(&agent);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut signed = false;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    signed |= agent.handle(&body)[0] == wire::SSH2_AGENT_SIGN_RESPONSE;
                }
                signed
            })
        };
        let threads = [spawn(add.clone()), spawn(remove), spawn(sign.clone())];
        std::thread::sleep(Duration::from_secs(2));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for thread in threads {
            assert!(!thread.join().unwrap(), "a confirm-constrained key signed");
        }

        // Whatever the race left behind, a served key still needs confirming.
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.handle(&sign), wire::failure());
    }

    /// An `ssh-add -h` key re-added while another connection removes it is
    /// never listed to a connection its constraint hides it from.
    #[test]
    fn a_racing_remove_never_unhides_a_constrained_key() {
        let agent = Arc::new(Agent::new());
        let (mut add, public) = local_key(0x17, "hidden@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        add.extend_from_slice(&wire::tests::destination_extension());
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        public.to_bytes().unwrap().encode(&mut remove).unwrap();

        // A failed session bind leaves a connection that may see no
        // destination-constrained key.
        let mut poisoned = Connection::default();
        let _ = poisoned.bind(public.clone(), b"sid", b"not a signature", false);

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spawn = |body: Vec<u8>| {
            let agent = Arc::clone(&agent);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    agent.handle(&body);
                }
            })
        };
        let writers = [spawn(add), spawn(remove)];
        let started = Instant::now();
        let mut listed = 0;
        while started.elapsed() < Duration::from_secs(2) {
            listed += agent.identities_for(&poisoned).len();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(listed, 0, "a destination-constrained key was listed");
    }

    /// A key decoder may call back into the agent, here to register another
    /// key type, while it decodes a key.
    #[test]
    fn a_key_decoder_may_register_a_key_type() {
        struct Reentrant(Arc<std::sync::OnceLock<Arc<Agent>>>);
        impl KeyDecoder for Reentrant {
            fn key_types(&self) -> &[&str] {
                &["ssh-ed25519"]
            }
            fn decode(
                &self,
                key_type: &str,
                reader: &mut &[u8],
            ) -> Result<SignerRef, crate::KeyDecodeError> {
                let agent = self.0.get().expect("the agent is set");
                agent.register_key_type(Reentrant(Arc::clone(&self.0)));
                crate::local::decode(key_type, reader).map(SignerRef::new)
            }
        }

        let slot = Arc::new(std::sync::OnceLock::new());
        let agent = Arc::new(Agent::new().with_key_type(Reentrant(Arc::clone(&slot))));
        let _ = slot.set(Arc::clone(&agent));
        let (add, _) = local_key(0x18, "reentrant@example.com");
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(agent.handle(&add)));
        assert_eq!(
            answer.recv_timeout(Duration::from_secs(5)),
            Ok(wire::success()),
            "the add deadlocked"
        );
    }

    /// A backend that runs `during` once, the first time its keys are looked
    /// up, standing in for another connection's request landing midway.
    /// It answers with the keys it had before `during` ran, as a backend
    /// whose answer is already on its way does.
    struct Midway {
        keys: Arc<crate::testing::MemoryBackend>,
        during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl Backend for Midway {
        fn identities(&self) -> Vec<SignerRef> {
            let keys = self.keys.identities();
            let during = self.during.lock().unwrap().take();
            if let Some(during) = during {
                during();
            }
            keys
        }
    }

    /// Adding another key, constraints and all, while a sign looks its own
    /// key up does not fail the sign.
    #[test]
    fn an_unrelated_add_does_not_fail_a_sign() {
        let key = ed25519(0x19, "backend@example.com");
        let slot = Arc::new(std::sync::OnceLock::<std::sync::Weak<Agent>>::new());
        let (mut add, _) = local_key(0x1a, "other@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        let midway = {
            let slot = Arc::clone(&slot);
            Midway {
                keys: Arc::new(crate::testing::MemoryBackend::new([key.clone()])),
                during: Mutex::new(Some(Box::new(move || {
                    let agent = slot.get().unwrap().upgrade().unwrap();
                    assert_eq!(agent.handle(&add), wire::success());
                }))),
            }
        };
        let agent = Arc::new(Agent::new().with_backend(Arc::new(midway)));
        let _ = slot.set(Arc::downgrade(&agent));
        let reply = agent.handle(&sign_body(&key.key_blob(), b"data"));
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
    }

    /// An `ssh-add -h` constraint given to a backend's key while a listing
    /// asks the backends hides it from a connection the constraint rules
    /// out: the listing is taken again.
    #[test]
    fn a_constraint_added_midway_hides_the_key() {
        use crate::destination::ConstraintHop;
        let key = ed25519(0x1d, "backend@example.com");
        let slot = Arc::new(std::sync::OnceLock::<std::sync::Weak<Agent>>::new());
        let midway = {
            let slot = Arc::clone(&slot);
            let blob = key.key_blob();
            Midway {
                keys: Arc::new(crate::testing::MemoryBackend::new([key.clone()])),
                during: Mutex::new(Some(Box::new(move || {
                    let agent = slot.get().unwrap().upgrade().unwrap();
                    let hidden = KeyMeta {
                        confirm: false,
                        destination: vec![DestinationConstraint {
                            from: ConstraintHop {
                                username: None,
                                hostname: None,
                                hostkeys: Vec::new(),
                            },
                            to: ConstraintHop {
                                username: None,
                                hostname: Some("example.com".into()),
                                hostkeys: Vec::new(),
                            },
                        }],
                    };
                    agent.write(|store| store.set_provider_meta(blob.clone(), hidden.clone()));
                }))),
            }
        };
        let agent = Arc::new(Agent::new().with_backend(Arc::new(midway)));
        let _ = slot.set(Arc::downgrade(&agent));
        // A failed session bind leaves a connection that may see no
        // destination-constrained key.
        let mut poisoned = Connection::default();
        let _ = poisoned.bind(key.public_key().clone(), b"sid", b"not a signature", false);
        assert!(
            agent.identities_for(&poisoned).is_empty(),
            "a destination-constrained key was listed"
        );
    }

    /// Other keys' constraints changing on every pass do not empty a
    /// listing: only a listed key's own constraints send it round again.
    #[test]
    fn churn_elsewhere_does_not_empty_a_listing() {
        struct Churning {
            keys: crate::testing::MemoryBackend,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            seed: std::sync::atomic::AtomicU8,
        }
        impl Backend for Churning {
            fn identities(&self) -> Vec<SignerRef> {
                if let Some(agent) = self.agent.get().and_then(std::sync::Weak::upgrade) {
                    let seed = self.seed.fetch_add(1, Ordering::SeqCst);
                    let confirm = KeyMeta {
                        confirm: true,
                        destination: Vec::new(),
                    };
                    let other = ed25519(seed, "churn").key_blob();
                    agent.write(|store| store.set_provider_meta(other.clone(), confirm.clone()));
                }
                self.keys.identities()
            }
        }

        let key = ed25519(0x22, "backend@example.com");
        let backend = Arc::new(Churning {
            keys: crate::testing::MemoryBackend::new([key.clone()]),
            agent: std::sync::OnceLock::new(),
            seed: std::sync::atomic::AtomicU8::new(0x40),
        });
        let agent = Arc::new(Agent::new().with_backend(Arc::clone(&backend) as _));
        let _ = backend.agent.set(Arc::downgrade(&agent));
        assert!(
            agent.identities().contains(&wire::listed(key.public_key())),
            "the backend's key was not listed"
        );
    }

    /// An expired key's constraints go with it: re-added without them, it
    /// signs freely, while its certificate keeps its own.
    #[test]
    fn an_expired_keys_constraints_go_with_it() {
        let key = ed25519(0x23, "ferris@example.com");
        let cert = crate::testing::certify(key.public_key().key_data());
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let agent = Agent::new();
        agent.add_held(key.clone(), None, None, Some(confirm.clone()));
        agent.add_held(key.clone(), Some(cert.clone()), None, Some(confirm));

        agent.write(|store| expire_own(store, 0));
        agent.purge_expired();
        agent.add_key(key.clone(), None);
        let unbound = Connection::default();
        assert!(agent.sign(&key.key_blob(), b"data", 0, &unbound).is_ok());
        assert!(matches!(
            agent.sign(cert.blob(), b"data", 0, &unbound),
            Err(AgentError::ConfirmRefused)
        ));
    }

    /// A failed `ssh-add -s` puts the key's previous constraints back,
    /// unless something else changed them while the provider was adding it.
    #[test]
    fn a_failed_provider_add_restores_untouched_constraints() {
        use crate::destination::ConstraintHop;
        struct Failing {
            key: SignerRef,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            release: std::sync::atomic::AtomicBool,
        }
        impl SmartcardProvider for Failing {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                if self.release.load(Ordering::SeqCst)
                    && let Some(agent) = self.agent.get().and_then(std::sync::Weak::upgrade)
                {
                    agent.release(&self.key.key_blob(), true);
                }
                Err("the card was pulled".into())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                Ok(crate::Removed::default())
            }
        }

        let key = ed25519(0x24, "card");
        let provider = Arc::new(Failing {
            key: key.clone(),
            agent: std::sync::OnceLock::new(),
            release: Default::default(),
        });
        let agent = Arc::new(Agent::new().with_smartcard(Arc::clone(&provider) as _));
        let _ = provider.agent.set(Arc::downgrade(&agent));
        let previous = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let hidden = KeyMeta {
            confirm: false,
            destination: vec![DestinationConstraint {
                from: ConstraintHop {
                    username: None,
                    hostname: None,
                    hostkeys: Vec::new(),
                },
                to: ConstraintHop {
                    username: None,
                    hostname: Some("example.com".into()),
                    hostkeys: Vec::new(),
                },
            }],
        };
        let add = |meta: &KeyMeta| {
            let pin = Zeroizing::new(Vec::new());
            agent.add_smartcard(
                b"card",
                &pin,
                None,
                meta.clone(),
                None,
                &Connection::default(),
            )
        };
        agent.write(|store| store.set_provider_meta(key.key_blob(), previous.clone()));

        assert!(add(&hidden).is_err());
        assert_eq!(
            agent.snapshot().provider_meta(&key.key_blob()).cloned(),
            Some(previous.clone())
        );

        provider.release.store(true, Ordering::SeqCst);
        assert!(add(&hidden).is_err());
        assert_eq!(
            agent.snapshot().provider_meta(&key.key_blob()).cloned(),
            None
        );
    }

    /// A backend may tell the agent it dropped a key, with
    /// [`Agent::release`], while `ssh-add -d` removes that key from it.
    #[test]
    fn a_backend_may_release_during_a_removal() {
        struct Releasing {
            keys: crate::testing::MemoryBackend,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
        }
        impl Backend for Releasing {
            fn identities(&self) -> Vec<SignerRef> {
                self.keys.identities()
            }
            fn remove(&self, key_blob: &[u8]) -> bool {
                let removed = Backend::remove(&self.keys, key_blob);
                if let Some(agent) = self.agent.get().and_then(std::sync::Weak::upgrade) {
                    agent.release(key_blob, removed);
                }
                removed
            }
        }

        let key = ed25519(0x1f, "backend@example.com");
        let backend = Arc::new(Releasing {
            keys: crate::testing::MemoryBackend::new([key.clone()]),
            agent: std::sync::OnceLock::new(),
        });
        let agent = Arc::new(Agent::new().with_backend(Arc::clone(&backend) as _));
        let _ = backend.agent.set(Arc::downgrade(&agent));
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.key_blob().encode(&mut remove).unwrap();
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(agent.handle(&remove)));
        assert_eq!(
            answer.recv_timeout(Duration::from_secs(5)),
            Ok(wire::success()),
            "the removal deadlocked"
        );
    }

    /// A backend key removed, and its `ssh-add -s -c` constraint released,
    /// after a sign found it is not signed with unconstrained: the key is
    /// outside the snapshot, so its constraints are read again once it is
    /// found, and the sign looks again.
    #[test]
    fn a_provider_key_released_midway_is_not_signed_with() {
        let key = ed25519(0x25, "card");
        let keys = Arc::new(crate::testing::MemoryBackend::new([key.clone()]));
        let slot = Arc::new(std::sync::OnceLock::<std::sync::Weak<Agent>>::new());
        let midway = {
            let slot = Arc::clone(&slot);
            let keys = Arc::clone(&keys);
            let blob = key.key_blob();
            Midway {
                keys: Arc::clone(&keys),
                during: Mutex::new(Some(Box::new(move || {
                    let agent = slot.get().unwrap().upgrade().unwrap();
                    let served = Backend::remove(keys.as_ref(), &blob);
                    agent.release(&blob, served);
                }))),
            }
        };
        let agent = Arc::new(Agent::new().with_backend(Arc::new(midway)));
        let _ = slot.set(Arc::downgrade(&agent));
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        agent.write(|store| store.set_provider_meta(key.key_blob(), confirm.clone()));
        assert!(matches!(
            agent.sign(&key.key_blob(), b"data", 0, &Connection::default()),
            Err(AgentError::UnknownKey)
        ));
    }

    /// A sign reads an added key and its constraints from one snapshot, so
    /// re-adding the key with `ssh-add -c` while the sign asks the backends
    /// orders the re-add after it: that sign goes ahead, unconstrained as
    /// the key was, and every later one needs confirming.
    #[test]
    fn a_constraint_added_midway_applies_from_the_next_sign() {
        let (add, public) = local_key(0x1b, "midway@example.com");
        let blob = public.to_bytes().unwrap();
        let slot = Arc::new(std::sync::OnceLock::<std::sync::Weak<Agent>>::new());
        let mut constrained = add.clone();
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM
            .encode(&mut constrained)
            .unwrap();
        let midway = {
            let slot = Arc::clone(&slot);
            Midway {
                keys: Default::default(),
                during: Mutex::new(Some(Box::new(move || {
                    let agent = slot.get().unwrap().upgrade().unwrap();
                    assert_eq!(agent.handle(&constrained), wire::success());
                }))),
            }
        };
        let agent = Arc::new(Agent::new().with_backend(Arc::new(midway)));
        let _ = slot.set(Arc::downgrade(&agent));
        assert_eq!(agent.handle(&add), wire::success());
        // The first lookup re-adds the key with `-c`; with no confirm prompt
        // no later sign goes ahead.
        assert_eq!(
            agent.handle(&sign_body(&blob, b"data"))[0],
            wire::SSH2_AGENT_SIGN_RESPONSE
        );
        assert_eq!(agent.handle(&sign_body(&blob, b"data")), wire::failure());
    }

    /// A key and its certificate are constrained separately, as OpenSSH
    /// does: adding one with or without `ssh-add -c` leaves the other's
    /// constraint as it was, and removing one leaves the other's.
    #[test]
    fn a_key_and_its_certificate_keep_their_own_constraints() {
        let key = ed25519(0x1c, "ferris@example.com");
        let cert = crate::testing::certify(key.public_key().key_data());
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let agent = Agent::new();
        let unbound = Connection::default();
        let signs = |blob: &[u8]| agent.sign(blob, b"data", 0, &unbound).is_ok();

        agent.add_held(key.clone(), None, None, Some(confirm.clone()));
        agent.add_held(
            key.clone(),
            Some(cert.clone()),
            None,
            Some(KeyMeta::default()),
        );
        assert!(!signs(&key.key_blob()), "the key lost its constraint");
        assert!(signs(cert.blob()));

        agent.add_held(key.clone(), Some(cert.clone()), None, Some(confirm));
        agent.add_held(key.clone(), None, None, Some(KeyMeta::default()));
        assert!(signs(&key.key_blob()));
        assert!(!signs(cert.blob()), "the certificate lost its constraint");

        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.key_blob().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(!signs(cert.blob()), "the certificate lost its constraint");
    }

    fn ed25519(seed: u8, comment: &str) -> SignerRef {
        let pair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        crate::local::decode("ssh-ed25519", &mut body.as_slice())
            .map(SignerRef::new)
            .unwrap()
    }

    fn sign_body(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        blob.encode(&mut sign).unwrap();
        data.encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        sign
    }

    /// A backend's keys are listed first, sign, and go on `ssh-add -d`.
    #[test]
    fn backend_keys_are_listed_signed_and_removed() {
        use crate::testing::MemoryBackend;
        let key = ed25519(1, "backend@example.com");
        let backend = Arc::new(MemoryBackend::new([key.clone()]));
        let agent = Agent::new().with_backend(Arc::clone(&backend) as _);
        let (add, added) = local_key(2, "added@example.com");
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(
            agent.identities(),
            vec![wire::listed(key.public_key()), wire::listed(&added)]
        );

        let reply = agent.handle(&sign_body(&key.key_blob(), b"data"));
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);

        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.key_blob().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(backend.0.lock().unwrap().is_empty());
        assert_eq!(agent.identities().len(), 1);
    }

    /// A signer whose signature does not verify never gets it out.
    #[test]
    fn a_bad_signature_is_refused() {
        struct Liar(SignerRef);
        impl crate::Signer for Liar {
            fn public_key(&self) -> &PublicKey {
                self.0.public_key()
            }
            fn sign(&self, _data: &[u8], hash: HashAlg) -> Result<ssh_key::Signature, BoxError> {
                self.0.sign(b"something else", hash)
            }
        }
        let key = SignerRef::new(Liar(ed25519(1, "liar")));
        let agent =
            Agent::new().with_backend(Arc::new(crate::testing::MemoryBackend::new([key.clone()])));
        assert!(matches!(
            agent.sign(&key.key_blob(), b"data", 0, &Connection::default()),
            Err(AgentError::Backend(_))
        ));
    }

    /// A certificate signs under its key's `ssh-add -h` constraint, as the
    /// plain key does: the userauth request names it by its own blob.
    #[test]
    fn a_destination_constrained_certificate_signs() {
        use crate::destination::{ConstraintHop, HostKeySpec};
        use ssh_key::PrivateKey;
        use ssh_key::private::Ed25519Keypair;

        let host = PrivateKey::from(Ed25519Keypair::from_seed(&[2; 32]));
        let key = ed25519(1, "ferris@example.com");
        let cert = crate::testing::certify(key.public_key().key_data());
        let agent = Agent::new();
        let meta = KeyMeta {
            confirm: false,
            destination: vec![DestinationConstraint {
                from: ConstraintHop {
                    username: None,
                    hostname: None,
                    hostkeys: Vec::new(),
                },
                to: ConstraintHop {
                    username: None,
                    hostname: Some("example.com".into()),
                    hostkeys: vec![HostKeySpec {
                        key: host.public_key().clone(),
                        is_ca: false,
                    }],
                },
            }],
        };
        agent.add_held(key.clone(), None, None, Some(meta.clone()));
        agent.add_held(key.clone(), Some(cert.clone()), None, Some(meta));

        let session_id = b"session";
        let mut signature = Vec::new();
        signature::Signer::sign(&host, session_id)
            .encode(&mut signature)
            .unwrap();
        let mut connection = Connection::default();
        connection
            .bind(host.public_key().clone(), session_id, &signature, false)
            .unwrap();

        let userauth = |algorithm: &str, blob: &[u8]| {
            let mut data = Vec::new();
            session_id.as_slice().encode(&mut data).unwrap();
            data.push(50);
            "ferris".encode(&mut data).unwrap();
            "ssh-connection".encode(&mut data).unwrap();
            "publickey".encode(&mut data).unwrap();
            data.push(1);
            algorithm.encode(&mut data).unwrap();
            blob.encode(&mut data).unwrap();
            data
        };
        let for_cert = userauth("ssh-ed25519-cert-v01@openssh.com", cert.blob());
        let for_key = userauth("ssh-ed25519", &key.key_blob());
        assert!(agent.sign(cert.blob(), &for_cert, 0, &connection).is_ok());
        assert!(
            agent
                .sign(&key.key_blob(), &for_key, 0, &connection)
                .is_ok()
        );
        // The request must be for the identity asked to sign it.
        assert!(matches!(
            agent.sign(cert.blob(), &for_key, 0, &connection),
            Err(AgentError::UnidentifiedSignature)
        ));
        // An unbound connection still gets nothing from a constrained key.
        assert!(matches!(
            agent.sign(cert.blob(), &for_cert, 0, &Connection::default()),
            Err(AgentError::DestinationRefused)
        ));
    }

    /// `ssh-add -c` keys ask the confirm prompt each time; with none, or a
    /// "no", they do not sign.
    #[test]
    fn confirmed_keys_ask_each_time() {
        use crate::testing::RecordingConfirm;
        let (mut add, public) = local_key(1, "ferris@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        let blob = public.to_bytes().unwrap();

        let unasked = Agent::new();
        assert_eq!(unasked.handle(&add), wire::success());
        assert_eq!(unasked.handle(&sign_body(&blob, b"data")), wire::failure());

        let confirm = Arc::new(RecordingConfirm::answering([Some(true), Some(false)]));
        let agent = Agent::new().with_confirm(Arc::clone(&confirm) as _);
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.handle(&sign_body(&blob, b"data"))[0], 14);
        assert_eq!(agent.handle(&sign_body(&blob, b"data")), wire::failure());
        let requests = confirm.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].identity, "ferris@example.com");
    }

    /// A policy can veto signatures and key changes, and hears each signature.
    #[test]
    fn the_policy_vetoes_and_audits() {
        #[derive(Default)]
        struct OnlyTagged(Mutex<Vec<String>>);
        impl Policy for OnlyTagged {
            fn allow_sign(&self, request: &SignInfo<'_>) -> bool {
                request.data.starts_with(b"ok:")
            }
            fn signed(&self, request: &SignInfo<'_>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(request.key.comment().to_owned());
            }
            fn allow_manage(&self, request: &ManageInfo<'_>) -> bool {
                !request.connection.bind_attempted()
            }
        }
        let policy = Arc::new(OnlyTagged::default());
        let agent = Agent::new().with_policy(Arc::clone(&policy) as _);
        let (add, public) = local_key(1, "ferris@example.com");
        assert_eq!(agent.handle(&add), wire::success());
        let blob = public.to_bytes().unwrap();
        assert_eq!(agent.handle(&sign_body(&blob, b"no")), wire::failure());
        assert_eq!(agent.handle(&sign_body(&blob, b"ok: fine"))[0], 14);
        assert_eq!(*policy.0.lock().unwrap(), vec!["ferris@example.com"]);
        assert!(matches!(
            agent.sign(&blob, b"no", 0, &Connection::default()),
            Err(AgentError::PolicyRefused)
        ));
    }

    /// The policy is asked before the `ssh-add -c` prompt: the user is never
    /// asked about a signature the policy refuses, and is still asked about
    /// one it allows.
    #[test]
    fn the_policy_is_asked_before_the_confirm_prompt() {
        use crate::testing::RecordingConfirm;
        struct OnlyOk;
        impl Policy for OnlyOk {
            fn allow_sign(&self, request: &SignInfo<'_>) -> bool {
                request.data.starts_with(b"ok:")
            }
        }
        let confirm = Arc::new(RecordingConfirm::answering([Some(true)]));
        let agent = Agent::new()
            .with_policy(Arc::new(OnlyOk))
            .with_confirm(Arc::clone(&confirm) as _);
        let (mut add, public) = local_key(1, "ferris@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::success());
        let blob = public.to_bytes().unwrap();

        assert!(matches!(
            agent.sign(&blob, b"no", 0, &Connection::default()),
            Err(AgentError::PolicyRefused)
        ));
        assert!(confirm.requests.lock().unwrap().is_empty());

        assert!(
            agent
                .sign(&blob, b"ok: fine", 0, &Connection::default())
                .is_ok()
        );
        assert_eq!(confirm.requests.lock().unwrap().len(), 1);
    }

    /// A smartcard provider that serves one key, named `card`, and is the
    /// backend that lists it.
    struct Card(crate::testing::MemoryBackend, SignerRef);
    impl SmartcardProvider for Card {
        fn resolve(
            &self,
            provider: &[u8],
            _pin: &Zeroizing<Vec<u8>>,
        ) -> Result<SignerRef, BoxError> {
            match provider {
                b"card" => Ok(self.1.clone()),
                _ => Err("no such card".into()),
            }
        }
        fn add(
            &self,
            provider: &[u8],
            pin: &Zeroizing<Vec<u8>>,
            _lifetime: Option<u32>,
        ) -> Result<(), BoxError> {
            let key = self.resolve(provider, pin)?;
            self.0.0.lock().unwrap().push(key);
            Ok(())
        }
        fn remove(&self, provider: &[u8]) -> Result<crate::Removed, BoxError> {
            let key = self.resolve(provider, &Zeroizing::new(Vec::new()))?;
            Ok(crate::Removed {
                served: Backend::remove(&self.0, &key.key_blob()),
                key_blob: Some(key.key_blob()),
            })
        }
    }
    impl Backend for Card {
        fn identities(&self) -> Vec<SignerRef> {
            self.0.identities()
        }
    }

    /// `ssh-add -s`/`-e` reach the smartcard provider, which owns the key;
    /// without one they fail.
    #[test]
    fn smartcard_requests_reach_the_provider() {
        let card = Arc::new(Card(Default::default(), ed25519(7, "card")));
        let agent = Agent::new()
            .with_backend(Arc::clone(&card) as _)
            .with_smartcard(Arc::clone(&card) as _);
        let request = |kind: u8, provider: &[u8]| {
            let mut body = vec![kind];
            provider.encode(&mut body).unwrap();
            b"".as_slice().encode(&mut body).unwrap();
            body
        };
        let add = request(wire::SSH_AGENTC_ADD_SMARTCARD_KEY, b"card");
        let remove = request(wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY, b"card");
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.identities().len(), 1);
        assert_eq!(
            agent.handle(&request(wire::SSH_AGENTC_ADD_SMARTCARD_KEY, b"other")),
            wire::failure()
        );
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(agent.identities().is_empty());
        assert_eq!(agent.handle(&remove), wire::failure());

        assert_eq!(Agent::new().handle(&add), wire::failure());
    }

    /// A smartcard provider that waits, as on a PIN prompt, until told to
    /// go on: in its key lookup, before the change takes its turn, or with
    /// `in_add` in serving the key, while the change holds it.
    struct Prompting {
        key: SignerRef,
        in_add: bool,
        prompted: Mutex<std::sync::mpsc::Sender<()>>,
        answer: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Prompting {
        fn prompt(&self) {
            let _ = self.prompted.lock().unwrap().send(());
            let _ = self.answer.lock().unwrap().recv();
        }
    }
    impl SmartcardProvider for Prompting {
        fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
            if !self.in_add {
                self.prompt();
            }
            Ok(self.key.clone())
        }
        fn add(&self, _: &[u8], _: &Zeroizing<Vec<u8>>, _: Option<u32>) -> Result<(), BoxError> {
            if self.in_add {
                self.prompt();
            }
            Ok(())
        }
        fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
            Ok(crate::Removed::default())
        }
    }

    /// An agent with a [`Prompting`] provider, the `ssh-add -s` request for
    /// its key, word of the prompt starting, and the answer that ends it.
    fn prompting_agent(
        in_add: bool,
    ) -> (
        Arc<Agent>,
        Vec<u8>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (prompted, prompt) = std::sync::mpsc::channel();
        let (answer, answered) = std::sync::mpsc::channel();
        let provider = Prompting {
            key: ed25519(0x2a, "card"),
            in_add,
            prompted: Mutex::new(prompted),
            answer: Mutex::new(answered),
        };
        let agent = Arc::new(Agent::new().with_smartcard(Arc::new(provider)));
        let mut add_card = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
        b"card".as_slice().encode(&mut add_card).unwrap();
        b"".as_slice().encode(&mut add_card).unwrap();
        (agent, add_card, prompt, answer)
    }

    /// Listing and signing go on while a key change waits on the user,
    /// such as for a PIN: only other key changes wait for it.
    #[test]
    fn reads_do_not_wait_for_a_key_change() {
        use std::sync::mpsc;
        let (agent, add_card, prompt, answer) = prompting_agent(true);
        let (add, public) = local_key(0x2b, "held@example.com");
        assert_eq!(agent.handle(&add), wire::success());

        let change = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.handle(&add_card))
        };
        prompt.recv_timeout(Duration::from_secs(5)).unwrap();

        let (done, replies) = mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            let blob = public.to_bytes().unwrap();
            std::thread::spawn(move || {
                let listed = agent.identities().len();
                let signed = agent.handle(&sign_body(&blob, b"data"))[0];
                let _ = done.send((listed, signed));
            });
        }
        let replies = replies.recv_timeout(Duration::from_secs(5));
        answer.send(()).unwrap();
        assert_eq!(
            replies,
            Ok((1, wire::SSH2_AGENT_SIGN_RESPONSE)),
            "a read waited for the key change"
        );
        assert_eq!(change.join().unwrap(), wire::success());
    }

    /// A key change that waited for another, such as one held up by a PIN
    /// prompt, is refused if the agent was locked meanwhile.
    #[test]
    fn a_waiting_key_change_is_refused_once_locked() {
        let (agent, add_card, prompt, answer) = prompting_agent(true);
        let (add, _) = local_key(0x2c, "held@example.com");
        assert_eq!(agent.handle(&add), wire::success());

        let first = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.handle(&add_card))
        };
        prompt.recv_timeout(Duration::from_secs(5)).unwrap();
        let waiting = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]))
        };
        // Let the removal reach its turn's wait before the lock.
        std::thread::sleep(Duration::from_millis(100));
        assert!(agent.lock(b"hunter2"));
        answer.send(()).unwrap();

        assert_eq!(first.join().unwrap(), wire::success());
        assert_eq!(waiting.join().unwrap(), wire::failure());
        assert_eq!(
            agent.snapshot().held.len(),
            1,
            "a locked agent's keys were removed"
        );
    }

    /// Other connections' key changes go on while one waits for a PIN in
    /// its key lookup, which runs before the change takes its turn.
    #[test]
    fn key_changes_do_not_wait_for_a_pin_prompt() {
        let (agent, add_card, prompt, answer) = prompting_agent(false);
        let (add, _) = local_key(0x2d, "held@example.com");
        let prompting = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.handle(&add_card))
        };
        prompt.recv_timeout(Duration::from_secs(5)).unwrap();

        let (done, replies) = std::sync::mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let added = agent.handle(&add);
                let removed = agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]);
                let _ = done.send((added, removed));
            });
        }
        let replies = replies.recv_timeout(Duration::from_secs(5));
        answer.send(()).unwrap();
        assert_eq!(
            replies,
            Ok((wire::success(), wire::success())),
            "a key change waited for another's PIN prompt"
        );
        assert_eq!(prompting.join().unwrap(), wire::success());
    }

    /// `allow_manage` sees each change with its key: the key to add and its
    /// constraints, the served key a removal names, and the key a provider
    /// resolved. A refusal leaves the keys as they were.
    #[test]
    fn the_policy_sees_each_key_change() {
        #[derive(Default)]
        struct Record(Mutex<Vec<String>>, std::sync::atomic::AtomicBool);
        impl Policy for Record {
            fn allow_manage(&self, request: &ManageInfo<'_>) -> bool {
                let key = request.key().map_or("-", |k| k.comment()).to_owned();
                let line = match request.change {
                    KeyChange::Add {
                        certificate,
                        constraints,
                        ..
                    } => format!(
                        "add {key} cert={} life={:?} confirm={}",
                        certificate.is_some(),
                        constraints.lifetime,
                        constraints.confirm
                    ),
                    KeyChange::Remove { key_blob, .. } => {
                        format!("remove {key} ({} bytes)", key_blob.len())
                    }
                    KeyChange::RemoveAll => "remove-all".to_owned(),
                    KeyChange::AddProvider {
                        provider,
                        certificates_only,
                        ..
                    } => format!(
                        "add-provider {} -> {key} certs_only={certificates_only}",
                        String::from_utf8_lossy(provider)
                    ),
                    KeyChange::RemoveProvider { provider } => {
                        format!("remove-provider {}", String::from_utf8_lossy(provider))
                    }
                };
                self.0.lock().unwrap().push(line);
                !self.1.load(std::sync::atomic::Ordering::SeqCst)
            }
        }

        let policy = Arc::new(Record::default());
        let card = Arc::new(Card(Default::default(), ed25519(7, "card")));
        let agent = Agent::new()
            .with_default_lifetime(Some(600))
            .with_policy(Arc::clone(&policy) as _)
            .with_backend(Arc::clone(&card) as _)
            .with_smartcard(Arc::clone(&card) as _);

        let (mut add, public) = local_key(1, "ferris@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::success());
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        public.to_bytes().unwrap().encode(&mut remove).unwrap();
        let provider = |kind: u8| {
            let mut body = vec![kind];
            b"card".as_slice().encode(&mut body).unwrap();
            b"".as_slice().encode(&mut body).unwrap();
            body
        };

        // Refused: nothing changes.
        policy.1.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(agent.handle(&remove), wire::failure());
        assert_eq!(
            agent.handle(&provider(wire::SSH_AGENTC_ADD_SMARTCARD_KEY)),
            wire::failure()
        );
        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::failure()
        );
        assert_eq!(agent.public_keys(), vec![public.clone()]);

        // Allowed.
        policy.1.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            agent.handle(&provider(wire::SSH_AGENTC_ADD_SMARTCARD_KEY)),
            wire::success()
        );
        assert_eq!(
            agent.handle(&provider(wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY)),
            wire::success()
        );
        assert_eq!(agent.handle(&remove), wire::success());
        let mut unknown = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        b"not a key".as_slice().encode(&mut unknown).unwrap();
        assert_eq!(agent.handle(&unknown), wire::failure());
        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::success()
        );

        let blob_len = public.to_bytes().unwrap().len();
        assert_eq!(
            *policy.0.lock().unwrap(),
            vec![
                "add ferris@example.com cert=false life=Some(600) confirm=true".to_owned(),
                format!("remove ferris@example.com ({blob_len} bytes)"),
                "add-provider card -> card certs_only=false".to_owned(),
                "remove-all".to_owned(),
                "add-provider card -> card certs_only=false".to_owned(),
                "remove-provider card".to_owned(),
                format!("remove ferris@example.com ({blob_len} bytes)"),
                "remove - (9 bytes)".to_owned(),
                "remove-all".to_owned(),
            ]
        );
    }

    /// `allow_list` hides keys and certificates from a listing, from every
    /// source, and sees which identities are certificates. A hidden key can
    /// still sign: hiding is not refusing.
    #[test]
    fn the_policy_filters_the_listing() {
        #[derive(Default)]
        struct HideHidden(Mutex<Vec<(String, bool)>>);
        impl Policy for HideHidden {
            fn allow_list(&self, request: &ListInfo<'_>) -> bool {
                let comment = request.key.comment().to_owned();
                let shown = !comment.starts_with("hidden");
                self.0
                    .lock()
                    .unwrap()
                    .push((comment, request.certificate.is_some()));
                shown
            }
        }

        let policy = Arc::new(HideHidden::default());
        let hidden_backend = ed25519(2, "hidden-backend");
        let agent = Agent::new()
            .with_policy(Arc::clone(&policy) as _)
            .with_backend(Arc::new(crate::testing::MemoryBackend::new([
                ed25519(1, "backend"),
                hidden_backend.clone(),
            ])));
        let (add_shown, _) = local_key(3, "added");
        let (add_hidden, hidden) = local_key(4, "hidden-added");
        assert_eq!(agent.handle(&add_shown), wire::success());
        assert_eq!(agent.handle(&add_hidden), wire::success());
        let hidden_signer = agent.signer_for(&hidden.to_bytes().unwrap()).unwrap();
        let cert = crate::testing::certify(hidden.key_data());
        agent.add_cert_key(hidden_signer, cert.clone(), None);

        let listed: Vec<String> = agent.identities().into_iter().map(|(_, c)| c).collect();
        assert_eq!(listed, vec!["backend", "added"]);
        assert_eq!(
            *policy.0.lock().unwrap(),
            vec![
                ("backend".to_owned(), false),
                ("hidden-backend".to_owned(), false),
                ("added".to_owned(), false),
                ("hidden-added".to_owned(), false),
                ("hidden-added".to_owned(), true),
            ]
        );

        // Hidden, but not refused.
        assert!(
            agent
                .sign(
                    &hidden.to_bytes().unwrap(),
                    b"data",
                    0,
                    &Connection::default()
                )
                .is_ok()
        );
        assert!(
            agent
                .sign(
                    &hidden_backend.key_blob(),
                    b"data",
                    0,
                    &Connection::default()
                )
                .is_ok()
        );
        assert!(
            agent
                .sign(cert.blob(), b"data", 0, &Connection::default())
                .is_ok()
        );
    }

    /// Lifecycle hooks hear lock, unlock and `ssh-add -D`.
    #[test]
    fn lifecycle_hooks_hear_state_changes() {
        #[derive(Default)]
        struct Log(Mutex<Vec<&'static str>>);
        impl Lifecycle for Log {
            fn locked(&self) {
                self.0.lock().unwrap().push("locked");
            }
            fn unlocked(&self) {
                self.0.lock().unwrap().push("unlocked");
            }
            fn cleared(&self) {
                self.0.lock().unwrap().push("cleared");
            }
        }
        let log = Arc::new(Log::default());
        let agent = Agent::new().with_lifecycle(Arc::clone(&log) as _);
        assert!(agent.lock(b"pass"));
        assert!(!agent.lock(b"pass"));
        assert!(!agent.unlock(b"wrong"));
        assert!(agent.unlock(b"pass"));
        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::success()
        );
        assert_eq!(
            *log.0.lock().unwrap(),
            vec!["locked", "unlocked", "cleared"]
        );
    }

    /// An `ssh-add -h` certificate cannot be replaced, constraints and all,
    /// from a connection its constraint rules out, even when its plain key
    /// was never added.
    #[test]
    fn a_constrained_certificate_is_not_replaced_from_a_hidden_connection() {
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[0x30; 32]);
        let cert = crate::testing::certify(&ssh_key::public::KeyData::Ed25519(pair.public));
        let mut private = Vec::new();
        pair.encode(&mut private).unwrap();
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519-cert-v01@openssh.com".encode(&mut add).unwrap();
        add.extend_from_slice(&crate::testing::cert_body(&cert, &private, "cert"));
        let mut constrained = add.clone();
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        constrained.extend_from_slice(&wire::tests::destination_extension());

        let agent = Agent::new();
        assert_eq!(agent.handle(&constrained), wire::success());
        let mut poisoned = Connection::default();
        let _ = poisoned.bind(
            ed25519(0x33, "host").public_key().clone(),
            b"sid",
            b"not a signature",
            false,
        );
        assert_eq!(agent.handle_in(&add, &mut poisoned), wire::failure());
        assert!(
            agent.identities_for(&poisoned).is_empty(),
            "the certificate lost its constraint"
        );
    }

    /// A key a backend serves and `ssh-add -c` added too signs only with a
    /// confirmation, whichever copy is found first.
    #[test]
    fn a_backend_copy_keeps_the_added_keys_constraints() {
        let key = ed25519(0x31, "both@example.com");
        let agent =
            Agent::new().with_backend(Arc::new(crate::testing::MemoryBackend::new([key.clone()])));
        let (mut add, _) = local_key(0x31, "both@example.com");
        add[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::success());
        assert!(matches!(
            agent.sign(&key.key_blob(), b"data", 0, &Connection::default()),
            Err(AgentError::ConfirmRefused)
        ));
    }

    /// Re-adding a served `ssh-add -s -c` key without `-c` keeps the
    /// confirmation while the provider adds it, and lifts it only after.
    #[test]
    fn looser_provider_constraints_wait_for_the_add() {
        struct Checking {
            key: SignerRef,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            confirmed_during: std::sync::atomic::AtomicBool,
        }
        impl SmartcardProvider for Checking {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                let (_, meta) = agent.constrained_signer(&self.key.key_blob()).unwrap();
                self.confirmed_during.store(meta.confirm, Ordering::SeqCst);
                Ok(())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                Ok(crate::Removed::default())
            }
        }

        let key = ed25519(0x32, "card");
        let provider = Arc::new(Checking {
            key: key.clone(),
            agent: std::sync::OnceLock::new(),
            confirmed_during: Default::default(),
        });
        let agent = Arc::new(
            Agent::new()
                .with_backend(Arc::new(crate::testing::MemoryBackend::new([key.clone()])))
                .with_smartcard(Arc::clone(&provider) as _),
        );
        let _ = provider.agent.set(Arc::downgrade(&agent));
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        agent.write(|store| store.set_provider_meta(key.key_blob(), confirm.clone()));

        let pin = Zeroizing::new(Vec::new());
        agent
            .add_smartcard(
                b"card",
                &pin,
                None,
                KeyMeta::default(),
                None,
                &Connection::default(),
            )
            .unwrap();
        assert!(
            provider.confirmed_during.load(Ordering::SeqCst),
            "the confirmation was lifted before the add finished"
        );
        assert_eq!(
            agent.snapshot().provider_meta(&key.key_blob()).cloned(),
            None
        );
    }

    /// `ssh-add -C -s` without `-c` adds certificates to a key served with
    /// `-c`: they take its confirmation, and the key keeps it.
    #[test]
    fn certificates_alone_keep_the_served_keys_constraints() {
        let key = ed25519(0x34, "card");
        let cert = crate::testing::certify(key.public_key().key_data());
        let card = Arc::new(Card(Default::default(), key.clone()));
        let agent = Agent::new()
            .with_backend(Arc::clone(&card) as _)
            .with_smartcard(Arc::clone(&card) as _);
        let pin = Zeroizing::new(Vec::new());
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let unbound = Connection::default();
        agent
            .add_smartcard(b"card", &pin, None, confirm.clone(), None, &unbound)
            .unwrap();

        let certs = AssociatedCerts {
            certs_only: true,
            certs: vec![cert.clone()],
        };
        agent
            .add_smartcard(
                b"card",
                &pin,
                None,
                KeyMeta::default(),
                Some(certs),
                &unbound,
            )
            .unwrap();
        for blob in [key.key_blob(), cert.blob().to_vec()] {
            assert!(matches!(
                agent.sign(&blob, b"data", 0, &unbound),
                Err(AgentError::ConfirmRefused)
            ));
        }
    }

    /// A backend that releases an `ssh-add -s -c` key while it is added
    /// takes its constraints, so the key's certificates are not served
    /// without them.
    #[test]
    fn certificates_are_not_attached_to_a_released_key() {
        struct Releasing {
            key: SignerRef,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
        }
        impl SmartcardProvider for Releasing {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                agent.release(&self.key.key_blob(), true);
                Ok(())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                Ok(crate::Removed::default())
            }
        }

        let key = ed25519(0x35, "card");
        let cert = crate::testing::certify(key.public_key().key_data());
        let provider = Arc::new(Releasing {
            key: key.clone(),
            agent: std::sync::OnceLock::new(),
        });
        let agent = Arc::new(Agent::new().with_smartcard(Arc::clone(&provider) as _));
        let _ = provider.agent.set(Arc::downgrade(&agent));
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        // With constraints or without: a released key's certificates would
        // otherwise sign through a key no backend serves.
        for meta in [confirm, KeyMeta::default()] {
            let certs = AssociatedCerts {
                certs_only: false,
                certs: vec![cert.clone()],
            };
            let pin = Zeroizing::new(Vec::new());
            let added = agent.add_smartcard(
                b"card",
                &pin,
                None,
                meta,
                Some(certs),
                &Connection::default(),
            );
            assert!(matches!(added, Err(Some(AgentError::UnknownKey))));
            assert!(agent.snapshot().cert(cert.blob()).is_none());
        }
    }

    /// A backend may release a key, constraints and all, while re-serving
    /// it for `ssh-add -s -c`: once the add succeeds the key, and the
    /// certificates added with it, have the constraints again.
    #[test]
    fn a_key_released_while_re_served_keeps_its_constraints() {
        struct Reserving {
            keys: crate::testing::MemoryBackend,
            key: SignerRef,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
        }
        impl SmartcardProvider for Reserving {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                agent.release(&self.key.key_blob(), true);
                *self.keys.0.lock().unwrap() = vec![self.key.clone()];
                Ok(())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                Ok(crate::Removed::default())
            }
        }
        impl Backend for Reserving {
            fn identities(&self) -> Vec<SignerRef> {
                self.keys.identities()
            }
        }

        let key = ed25519(0x37, "card");
        let cert = crate::testing::certify(key.public_key().key_data());
        let provider = Arc::new(Reserving {
            keys: crate::testing::MemoryBackend::new([]),
            key: key.clone(),
            agent: std::sync::OnceLock::new(),
        });
        let agent = Arc::new(
            Agent::new()
                .with_backend(Arc::clone(&provider) as _)
                .with_smartcard(Arc::clone(&provider) as _),
        );
        let _ = provider.agent.set(Arc::downgrade(&agent));
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let certs = AssociatedCerts {
            certs_only: false,
            certs: vec![cert.clone()],
        };
        let pin = Zeroizing::new(Vec::new());
        let unbound = Connection::default();
        agent
            .add_smartcard(b"card", &pin, None, confirm, Some(certs), &unbound)
            .unwrap();
        for blob in [key.key_blob(), cert.blob().to_vec()] {
            assert!(matches!(
                agent.sign(&blob, b"data", 0, &unbound),
                Err(AgentError::ConfirmRefused)
            ));
        }
    }

    /// [`Agent::add_key`] and [`Agent::add_cert_key`] refresh an identity's
    /// lifetime without dropping the `ssh-add -c` it was added with.
    #[test]
    fn library_adds_keep_an_identitys_constraints() {
        let key = ed25519(0x38, "ferris@example.com");
        let cert = crate::testing::certify(key.public_key().key_data());
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        let agent = Agent::new();
        agent.add_held(key.clone(), None, None, Some(confirm.clone()));
        agent.add_held(key.clone(), Some(cert.clone()), None, Some(confirm));

        agent.add_key(key.clone(), Some(60));
        agent.add_cert_key(key.clone(), cert.clone(), Some(60));
        let unbound = Connection::default();
        for blob in [key.key_blob(), cert.blob().to_vec()] {
            assert!(matches!(
                agent.sign(&blob, b"data", 0, &unbound),
                Err(AgentError::ConfirmRefused)
            ));
        }
        assert!(
            agent.snapshot().held[0]
                .own
                .as_ref()
                .unwrap()
                .expires
                .is_some()
        );
    }

    /// A backend's release drops the certificates `ssh-add -s` attached to
    /// the key with its constraints, in one change.
    #[test]
    fn a_release_drops_a_keys_certificates_and_constraints_together() {
        let key = ed25519(0x36, "card");
        let cert = crate::testing::certify(key.public_key().key_data());
        let agent = Agent::new();
        let confirm = KeyMeta {
            confirm: true,
            destination: Vec::new(),
        };
        agent.write(|store| {
            store.set_provider_meta(key.key_blob(), confirm.clone());
            store.attach_provider_certs(&key, std::slice::from_ref(&cert), None);
        });
        let before = agent.snapshot();
        assert!(agent.release(&key.key_blob(), true));
        let after = agent.snapshot();
        assert!(
            before.cert(cert.blob()).is_some() && before.provider_meta(&key.key_blob()).is_some()
        );
        assert!(
            after.cert(cert.blob()).is_none() && after.provider_meta(&key.key_blob()).is_none()
        );
        assert!(after.provider.is_empty());
    }

    /// A key change asked for, on the same thread, from a callback the
    /// agent calls while committing a change (a backend's or provider's
    /// `add`, `remove` or `remove_all`) is refused rather than waiting on
    /// itself.
    #[test]
    fn a_key_change_from_inside_a_commit_is_refused() {
        struct Reenters {
            key: SignerRef,
            keys: crate::testing::MemoryBackend,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            replies: Mutex<Vec<(&'static str, Vec<u8>)>>,
        }
        impl Reenters {
            fn reenter(&self, from: &'static str) {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                let (add, _) = local_key(0x39, "inner@example.com");
                self.replies
                    .lock()
                    .unwrap()
                    .push((from, agent.handle(&add)));
            }
        }
        impl SmartcardProvider for Reenters {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                self.reenter("SmartcardProvider::add");
                *self.keys.0.lock().unwrap() = vec![self.key.clone()];
                Ok(())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                self.reenter("SmartcardProvider::remove");
                Ok(crate::Removed {
                    served: Backend::remove(&self.keys, &self.key.key_blob()),
                    key_blob: Some(self.key.key_blob()),
                })
            }
        }
        impl Backend for Reenters {
            fn identities(&self) -> Vec<SignerRef> {
                self.keys.identities()
            }
            fn remove(&self, key_blob: &[u8]) -> bool {
                self.reenter("Backend::remove");
                Backend::remove(&self.keys, key_blob)
            }
            fn remove_all(&self) {
                self.reenter("Backend::remove_all");
                self.keys.remove_all();
            }
        }

        let key = ed25519(0x3a, "card");
        let reenters = Arc::new(Reenters {
            key: key.clone(),
            keys: crate::testing::MemoryBackend::new([]),
            agent: std::sync::OnceLock::new(),
            replies: Mutex::default(),
        });
        let agent = Arc::new(
            Agent::new()
                .with_backend(Arc::clone(&reenters) as _)
                .with_smartcard(Arc::clone(&reenters) as _),
        );
        let _ = reenters.agent.set(Arc::downgrade(&agent));
        let provider_request = |kind: u8| {
            let mut body = vec![kind];
            b"card".as_slice().encode(&mut body).unwrap();
            b"".as_slice().encode(&mut body).unwrap();
            body
        };
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.key_blob().encode(&mut remove).unwrap();
        let requests = [
            provider_request(wire::SSH_AGENTC_ADD_SMARTCARD_KEY),
            remove,
            provider_request(wire::SSH_AGENTC_ADD_SMARTCARD_KEY),
            provider_request(wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY),
            vec![wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES],
        ];

        let (done, finished) = std::sync::mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let replies: Vec<_> = requests.iter().map(|r| agent.handle(r)).collect();
                let _ = done.send(replies);
            });
        }
        let outer = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("a key change from inside a commit deadlocked");
        assert!(outer.iter().all(|reply| *reply == wire::success()));
        let inner = reenters.replies.lock().unwrap().clone();
        let from: Vec<_> = inner.iter().map(|(from, _)| *from).collect();
        assert_eq!(
            from,
            [
                "SmartcardProvider::add",
                "Backend::remove",
                "SmartcardProvider::add",
                "SmartcardProvider::remove",
                "Backend::remove_all",
            ]
        );
        for (from, reply) in inner {
            assert_eq!(reply, wire::failure(), "{from} was let through");
        }
    }

    /// The policy's `allow_manage` runs before the change takes its turn, so
    /// a key change it asks for goes through; the `cleared` hook runs in the
    /// turn, so no other change lands before it, and one it asks for is
    /// refused rather than waiting on itself.
    #[test]
    fn a_key_change_from_the_policy_goes_through_and_from_cleared_is_refused() {
        struct Reenters {
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            /// Set once the policy has asked for its change: a policy that
            /// changed keys every time it was asked would send its own
            /// change round until refused.
            asked: std::sync::atomic::AtomicBool,
            replies: Mutex<Vec<(&'static str, Vec<u8>)>>,
        }
        impl Reenters {
            fn reenter(&self, from: &'static str, seed: u8) {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                let (add, _) = local_key(seed, "inner@example.com");
                self.replies
                    .lock()
                    .unwrap()
                    .push((from, agent.handle(&add)));
            }
        }
        impl Policy for Reenters {
            fn allow_manage(&self, request: &ManageInfo<'_>) -> bool {
                if matches!(request.change, KeyChange::RemoveAll)
                    && !self.asked.swap(true, Ordering::SeqCst)
                {
                    self.reenter("Policy::allow_manage", 0x3b);
                }
                true
            }
        }
        impl Lifecycle for Reenters {
            fn cleared(&self) {
                self.reenter("Lifecycle::cleared", 0x3c);
            }
        }

        let reenters = Arc::new(Reenters {
            agent: std::sync::OnceLock::new(),
            asked: Default::default(),
            replies: Mutex::default(),
        });
        let agent = Arc::new(
            Agent::new()
                .with_policy(Arc::clone(&reenters) as _)
                .with_lifecycle(Arc::clone(&reenters) as _),
        );
        let _ = reenters.agent.set(Arc::downgrade(&agent));
        let (done, finished) = std::sync::mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let _ = done.send(agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]));
            });
        }
        let outer = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("a key change from the policy or the cleared hook deadlocked");
        assert_eq!(outer, wire::success());
        let inner = reenters.replies.lock().unwrap().clone();
        assert_eq!(
            inner,
            [
                ("Policy::allow_manage", wire::success()),
                ("Lifecycle::cleared", wire::failure()),
            ]
        );
        // The policy's key went with `ssh-add -D`; the hook's was refused.
        assert!(agent.public_keys().is_empty());
    }

    /// A lock or unlock asked for from an `unlocked` hook, on the same
    /// thread, is refused rather than waiting on the unlock that called it.
    #[test]
    fn the_unlocked_hook_cannot_lock_again() {
        struct Relocks {
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            relocked: Mutex<Option<bool>>,
        }
        impl Lifecycle for Relocks {
            fn unlocked(&self) {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                *self.relocked.lock().unwrap() = Some(agent.lock(b"again"));
            }
        }

        let hook = Arc::new(Relocks {
            agent: std::sync::OnceLock::new(),
            relocked: Mutex::default(),
        });
        let agent = Arc::new(Agent::new().with_lifecycle(Arc::clone(&hook) as _));
        let _ = hook.agent.set(Arc::downgrade(&agent));
        assert!(agent.lock(b"hunter2"));
        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let _ = done.send(agent.handle(&unlock));
            });
        }
        let outer = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("the unlocked hook's lock deadlocked");
        assert_eq!(outer, wire::success());
        assert_eq!(*hook.relocked.lock().unwrap(), Some(false));
        assert!(!agent.is_locked());
    }

    /// A lock sent while an unlock's hooks run waits for them, so hooks
    /// hear of the unlock before the lock that followed it.
    #[test]
    fn lock_hooks_run_in_order() {
        use std::sync::mpsc::{Receiver, Sender, channel};
        struct Ordered {
            events: Mutex<Vec<&'static str>>,
            started: Mutex<Sender<()>>,
            go: Mutex<Receiver<()>>,
        }
        impl Lifecycle for Ordered {
            fn locked(&self) {
                self.events.lock().unwrap().push("locked");
            }
            fn unlocked(&self) {
                self.events.lock().unwrap().push("unlocked");
                let _ = self.started.lock().unwrap().send(());
                let _ = self.go.lock().unwrap().recv_timeout(Duration::from_secs(5));
                self.events.lock().unwrap().push("unlocked done");
            }
        }

        let (started, start) = channel();
        let (go, gone) = channel();
        let hook = Arc::new(Ordered {
            events: Mutex::default(),
            started: Mutex::new(started),
            go: Mutex::new(gone),
        });
        let agent = Arc::new(Agent::new().with_lifecycle(Arc::clone(&hook) as _));
        assert!(agent.lock(b"hunter2"));
        hook.events.lock().unwrap().clear();
        let unlocking = {
            let agent = Arc::clone(&agent);
            let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
            b"hunter2".as_slice().encode(&mut unlock).unwrap();
            std::thread::spawn(move || agent.handle(&unlock))
        };
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        let locking = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.lock(b"again"))
        };
        // Let the lock reach its wait before the hook goes on.
        std::thread::sleep(Duration::from_millis(100));
        go.send(()).unwrap();
        assert_eq!(unlocking.join().unwrap(), wire::success());
        assert!(locking.join().unwrap());
        assert_eq!(
            *hook.events.lock().unwrap(),
            ["unlocked", "unlocked done", "locked"]
        );
    }

    /// Two right passphrases sent at once unlock once: the second finds the
    /// agent unlocked and is refused as such, not counted as a wrong guess.
    #[test]
    fn a_second_right_unlock_is_not_a_wrong_guess() {
        use std::sync::mpsc::{Receiver, Sender, channel};
        struct Slow {
            inner: PassphraseLock,
            checking: Mutex<Sender<()>>,
            go: Mutex<Receiver<()>>,
        }
        impl Locker for Slow {
            fn is_locked(&self) -> bool {
                self.inner.is_locked()
            }
            fn lock(&self, passphrase: &[u8]) -> bool {
                self.inner.lock(passphrase)
            }
            fn unlock(&self, passphrase: &[u8]) -> bool {
                let _ = self.checking.lock().unwrap().send(());
                let _ = self.go.lock().unwrap().recv_timeout(Duration::from_secs(5));
                self.inner.unlock(passphrase)
            }
        }

        let (checking, check) = channel();
        let (go, gone) = channel();
        let agent = Arc::new(
            Agent::new()
                .with_locker(Arc::new(Slow {
                    inner: PassphraseLock::default(),
                    checking: Mutex::new(checking),
                    go: Mutex::new(gone),
                }))
                .with_unlock_backoff(Duration::from_secs(1)),
        );
        assert!(agent.lock(b"hunter2"));
        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        let send = |unlock: Vec<u8>| {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || agent.handle(&unlock))
        };
        let first = send(unlock.clone());
        check.recv_timeout(Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        let second = send(unlock);
        // Let the second reach its wait before the first is checked.
        std::thread::sleep(Duration::from_millis(100));
        go.send(()).unwrap();
        assert_eq!(first.join().unwrap(), wire::success());
        assert_eq!(second.join().unwrap(), wire::failure());
        assert_eq!(agent.lock_state.lock().unwrap().failures, 0);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the second was delayed"
        );
    }

    /// An `ssh-add -X` sent from inside the `Locker`'s own check, on the
    /// same thread, is refused rather than waiting on the attempt that
    /// called it.
    #[test]
    fn an_unlock_from_inside_the_locker_is_refused() {
        struct Reenters {
            inner: PassphraseLock,
            agent: std::sync::OnceLock<std::sync::Weak<Agent>>,
            reply: Mutex<Option<Vec<u8>>>,
        }
        impl Locker for Reenters {
            fn is_locked(&self) -> bool {
                self.inner.is_locked()
            }
            fn lock(&self, passphrase: &[u8]) -> bool {
                self.inner.lock(passphrase)
            }
            fn unlock(&self, passphrase: &[u8]) -> bool {
                let agent = self.agent.get().unwrap().upgrade().unwrap();
                let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
                passphrase.encode(&mut unlock).unwrap();
                *self.reply.lock().unwrap() = Some(agent.handle(&unlock));
                self.inner.unlock(passphrase)
            }
        }

        let locker = Arc::new(Reenters {
            inner: PassphraseLock::default(),
            agent: std::sync::OnceLock::new(),
            reply: Mutex::default(),
        });
        let agent = Arc::new(
            Agent::new()
                .with_locker(Arc::clone(&locker) as _)
                .with_unlock_backoff(Duration::ZERO),
        );
        let _ = locker.agent.set(Arc::downgrade(&agent));
        assert!(agent.lock(b"hunter2"));
        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let _ = done.send(agent.handle(&unlock));
            });
        }
        let outer = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("an unlock from inside the locker deadlocked");
        assert_eq!(outer, wire::success());
        assert_eq!(*locker.reply.lock().unwrap(), Some(wire::failure()));
    }

    /// A certificate is listed under the comment sent with it, whatever the
    /// key it signs with was added under, before or after.
    #[test]
    fn a_certificate_keeps_the_comment_it_was_added_with() {
        let cert = crate::testing::certify(ed25519(0x3d, "").public_key().key_data());
        let agent = Agent::new();
        agent.add_key(ed25519(0x3d, "old"), None);
        agent.add_cert_key(ed25519(0x3d, "new"), cert.clone(), None);
        agent.add_key(ed25519(0x3d, "newest"), None);
        let listed = agent.identities();
        let comment = |blob: &[u8]| {
            listed
                .iter()
                .find(|(b, _)| b == blob)
                .map(|(_, c)| c.clone())
        };
        assert_eq!(comment(cert.blob()).as_deref(), Some("new"));
        let key = ed25519(0x3d, "").key_blob();
        assert_eq!(comment(&key).as_deref(), Some("newest"));
    }

    /// An `ssh-add -e` sent while an `ssh-add -s` with certificates is
    /// still serving the key comes after the certificates go on, so it
    /// takes them with the key rather than leaving them signing through a
    /// key no backend serves. The backend answers the add's last look-up
    /// with the keys it served before the removal, as one whose answer was
    /// already on its way would.
    #[test]
    fn a_removal_during_a_provider_add_takes_its_certificates() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc::{Receiver, Sender, channel};
        struct Blocking {
            keys: crate::testing::MemoryBackend,
            key: SignerRef,
            added: AtomicBool,
            prompted: Mutex<Sender<()>>,
            answer: Mutex<Receiver<()>>,
            looking: Mutex<Sender<()>>,
            removed: Mutex<Receiver<()>>,
        }
        impl SmartcardProvider for Blocking {
            fn resolve(&self, _: &[u8], _: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
                Ok(self.key.clone())
            }
            fn add(
                &self,
                _: &[u8],
                _: &Zeroizing<Vec<u8>>,
                _: Option<u32>,
            ) -> Result<(), BoxError> {
                let _ = self.prompted.lock().unwrap().send(());
                let _ = self.answer.lock().unwrap().recv();
                *self.keys.0.lock().unwrap() = vec![self.key.clone()];
                self.added.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn remove(&self, _: &[u8]) -> Result<crate::Removed, BoxError> {
                Ok(crate::Removed {
                    served: Backend::remove(&self.keys, &self.key.key_blob()),
                    key_blob: Some(self.key.key_blob()),
                })
            }
        }
        impl Backend for Blocking {
            fn identities(&self) -> Vec<SignerRef> {
                self.keys.identities()
            }
            fn known(&self) -> Vec<SignerRef> {
                let keys = self.keys.identities();
                if self.added.swap(false, Ordering::SeqCst) {
                    let _ = self.looking.lock().unwrap().send(());
                    let _ = self
                        .removed
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5));
                }
                keys
            }
        }

        let key = ed25519(0x3e, "card");
        let cert = crate::testing::certify(key.public_key().key_data());
        let (prompted, prompt) = channel();
        let (answer, answered) = channel();
        let (looking, look) = channel();
        let (removed, removal) = channel();
        let card = Arc::new(Blocking {
            keys: crate::testing::MemoryBackend::new([]),
            key: key.clone(),
            added: AtomicBool::new(false),
            prompted: Mutex::new(prompted),
            answer: Mutex::new(answered),
            looking: Mutex::new(looking),
            removed: Mutex::new(removal),
        });
        let agent = Arc::new(
            Agent::new()
                .with_backend(Arc::clone(&card) as _)
                .with_smartcard(Arc::clone(&card) as _),
        );
        let adding = {
            let agent = Arc::clone(&agent);
            let cert = cert.clone();
            std::thread::spawn(move || {
                let certs = AssociatedCerts {
                    certs_only: false,
                    certs: vec![cert],
                };
                let pin = Zeroizing::new(Vec::new());
                let unbound = Connection::default();
                agent
                    .add_smartcard(
                        b"card",
                        &pin,
                        None,
                        KeyMeta::default(),
                        Some(certs),
                        &unbound,
                    )
                    .is_ok()
            })
        };
        prompt.recv_timeout(Duration::from_secs(5)).unwrap();
        let removing = {
            let agent = Arc::clone(&agent);
            let mut remove = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
            b"card".as_slice().encode(&mut remove).unwrap();
            std::thread::spawn(move || agent.handle(&remove))
        };
        // Let the removal reach its turn's wait before the add goes on.
        std::thread::sleep(Duration::from_millis(100));
        answer.send(()).unwrap();
        // The add's look-up after its turn waits until the removal is done.
        look.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(removing.join().unwrap(), wire::success());
        removed.send(()).unwrap();

        assert!(adding.join().unwrap());
        assert!(
            agent.snapshot().cert(cert.blob()).is_none(),
            "a certificate outlived its removed key"
        );
    }

    /// Extensions and key types are matched by the names they gave when
    /// registered: requests never call back into them to ask again.
    #[test]
    fn handlers_are_asked_their_names_once() {
        use crate::extension::ExtensionReply;
        use std::sync::atomic::AtomicUsize;
        struct Named(AtomicUsize);
        impl Extension for Named {
            fn name(&self) -> &str {
                self.0.fetch_add(1, Ordering::SeqCst);
                "named@example.com"
            }
            fn handle(&self, _: &ExtensionContext, _: &[u8]) -> ExtensionReply {
                ExtensionReply::Success
            }
        }
        struct Typed(Arc<AtomicUsize>);
        impl KeyDecoder for Typed {
            fn key_types(&self) -> &[&str] {
                self.0.fetch_add(1, Ordering::SeqCst);
                &["ssh-ed25519"]
            }
            fn decode(
                &self,
                key_type: &str,
                reader: &mut &[u8],
            ) -> Result<SignerRef, crate::KeyDecodeError> {
                crate::local::decode(key_type, reader).map(SignerRef::new)
            }
        }

        let named = Arc::new(Named(AtomicUsize::new(0)));
        struct Shared(Arc<Named>);
        impl Extension for Shared {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn handle(&self, ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply {
                self.0.handle(ctx, data)
            }
        }
        let typed = Arc::new(AtomicUsize::new(0));
        let agent = Agent::new()
            .with_extension(Shared(Arc::clone(&named)))
            .with_key_type(Typed(Arc::clone(&typed)));
        let mut request = vec![wire::SSH_AGENTC_EXTENSION];
        "named@example.com".encode(&mut request).unwrap();
        for seed in 0x40..0x43 {
            assert_eq!(agent.handle(&request), wire::success());
            let (add, _) = local_key(seed, "typed@example.com");
            assert_eq!(agent.handle(&add), wire::success());
        }
        assert_eq!(named.0.load(Ordering::SeqCst), 1);
        assert_eq!(typed.load(Ordering::SeqCst), 1);
    }
}
