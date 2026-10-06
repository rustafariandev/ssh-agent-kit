//! The agent itself: identity bookkeeping and request handling.

use crate::backend::{Backend, Expiring, Lifecycle, SmartcardProvider};
use crate::cert::{AssociatedCerts, CertKey};
use crate::destination::{self, Connection, DestinationConstraint};
use crate::extension::{Extension, ExtensionContext};
use crate::keytype::{KeyDecoder, KeyRegistry};
use crate::lock::{Locker, PassphraseLock};
use crate::policy::{
    Confirm, ConfirmRequest, KeyChange, KeyConstraints, ListInfo, ManageInfo, Policy, SignInfo,
};
use crate::signer::{BoxError, SignerRef, VerifyError};
use crate::wire::{self, Request};
use arc_swap::ArcSwap;
use ssh_encoding::Decode;
use ssh_key::{HashAlg, PublicKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
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
    /// Held through each key change a client asks for, the requests
    /// [`Request::changes_keys`] groups as writes. A change that reaches a
    /// backend or provider publishes the store more than once, so two
    /// changes must not interleave.
    changes: Mutex<()>,
    /// Protocol extension handlers, matched by name, replaced as a whole on
    /// each registration.
    extensions: ArcSwap<Vec<Arc<dyn Extension>>>,
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
    /// Wrong unlock passphrases since the last good one, which slow down
    /// each further failure (see [`Self::handle_unlock`]).
    unlock_failures: AtomicU32,
    /// Held through each unlock attempt and its delay, so guesses are taken
    /// one at a time however many connections send them.
    unlock_turn: Mutex<()>,
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

/// A certificate the agent lists, and the key that signs for it.
#[derive(Clone)]
struct CertIdentity {
    cert: CertKey,
    comment: String,
    signer: CertSigner,
}

#[derive(Clone)]
enum CertSigner {
    /// The private key `ssh-add FILE` sent with the certificate.
    Held(SignerRef),
    /// The key `ssh-add -s PROVIDER CERT…` named; dropped with it.
    Provider(SignerRef),
    /// Whichever key a backend serves that the certificate certifies, for a
    /// certificate loaded with [`Agent::with_certificates`].
    Served,
}

/// The identity for a certificate `ssh-add FILE` sent with its key `key`,
/// listed under the key's comment.
fn held_cert(key: SignerRef, cert: CertKey) -> CertIdentity {
    let comment = key.comment().to_owned();
    tracing::info!(
        comment,
        key_id = cert.certificate().key_id(),
        "serving added certificate"
    );
    CertIdentity {
        cert,
        comment,
        signer: CertSigner::Held(key),
    }
}

/// What the agent holds itself. A published store is never changed: a
/// write changes a copy (see [`Agent::write`]), so a key and its
/// constraints are always seen together. Each collection is shared between
/// copies until a write changes it, so a copy costs three reference counts.
#[derive(Clone, Default)]
struct Store {
    /// Keys added at runtime with `ssh-add FILE`.
    held: Arc<Vec<Expiring<SignerRef>>>,
    /// Certificates, each served as an identity of its own.
    certs: Arc<Vec<Expiring<CertIdentity>>>,
    /// The `ssh-add -c`/`-h` constraints of added keys, by their public key
    /// blob, shared with the certificates the key signs for. Entries are
    /// replaced when the key is re-added, and cleared when it is removed
    /// unless a certificate it signs for is still served. Replaced only when
    /// an entry changes, so a reader can tell from this `Arc` alone whether
    /// constraints changed between two snapshots.
    meta: Arc<HashMap<Vec<u8>, KeyMeta>>,
}

impl Store {
    fn has_expired(&self) -> bool {
        self.held.iter().any(Expiring::expired) || self.certs.iter().any(Expiring::expired)
    }

    /// Drop expired keys and certificates, and the constraints of the added
    /// keys that nothing signs with any more.
    fn purge_expired(&mut self) {
        let mut gone = Vec::new();
        if self.held.iter().any(Expiring::expired) {
            Arc::make_mut(&mut self.held).retain(|e| {
                let expired = e.expired();
                if expired {
                    gone.push(e.item.key_blob());
                }
                !expired
            });
        }
        if self.certs.iter().any(Expiring::expired) {
            Arc::make_mut(&mut self.certs).retain(|e| {
                let expired = e.expired();
                if expired && let CertSigner::Held(key) = &e.item.signer {
                    gone.push(key.key_blob());
                }
                !expired
            });
        }
        for key_blob in gone {
            self.forget_meta(&key_blob);
        }
    }

    /// The added key `key_blob` names, unless it has expired.
    fn held_key(&self, key_blob: &[u8]) -> Option<SignerRef> {
        self.held
            .iter()
            .find(|e| e.item.key_blob() == key_blob && !e.expired())
            .map(|e| e.item.clone())
    }

    /// The certificate whose blob is `blob`, unless its `ssh-add -t`
    /// lifetime has run out.
    fn cert(&self, blob: &[u8]) -> Option<&CertIdentity> {
        self.certs
            .iter()
            .find(|e| e.item.cert.blob() == blob && !e.expired())
            .map(|e| &e.item)
    }

    /// Serve `key`, replacing the same key if it is already served.
    fn hold(&mut self, key: SignerRef, lifetime: Option<u32>) {
        let blob = key.key_blob();
        let held = Arc::make_mut(&mut self.held);
        held.retain(|e| e.item.key_blob() != blob);
        held.push(Expiring::new(key, lifetime));
    }

    fn push_cert(&mut self, identity: CertIdentity, lifetime: Option<u32>) {
        let certs = Arc::make_mut(&mut self.certs);
        certs.retain(|e| e.item.cert.blob() != identity.cert.blob());
        certs.push(Expiring::new(identity, lifetime));
    }

    fn remove_held(&mut self, key_blob: &[u8]) -> bool {
        if !self.held.iter().any(|e| e.item.key_blob() == key_blob) {
            return false;
        }
        Arc::make_mut(&mut self.held).retain(|e| e.item.key_blob() != key_blob);
        true
    }

    fn take_cert(&mut self, blob: &[u8]) -> Option<CertIdentity> {
        let at = self.certs.iter().position(|e| e.item.cert.blob() == blob)?;
        Some(Arc::make_mut(&mut self.certs).remove(at).item)
    }

    fn remove_provider_certs(&mut self, key_blob: &[u8]) -> bool {
        let attached = |e: &Expiring<CertIdentity>| matches!(&e.item.signer, CertSigner::Provider(key) if key.key_blob() == key_blob);
        if !self.certs.iter().any(attached) {
            return false;
        }
        Arc::make_mut(&mut self.certs).retain(|e| !attached(e));
        true
    }

    /// Record or clear the constraints of an added key.
    fn set_meta(&mut self, blob: Vec<u8>, meta: KeyMeta) {
        if meta.is_empty() {
            self.remove_meta(&blob);
        } else if self.meta.get(&blob) != Some(&meta) {
            Arc::make_mut(&mut self.meta).insert(blob, meta);
        }
    }

    fn remove_meta(&mut self, key_blob: &[u8]) {
        if self.meta.contains_key(key_blob) {
            Arc::make_mut(&mut self.meta).remove(key_blob);
        }
    }

    /// Clear the constraints of the added key `key_blob` once nothing signs
    /// with it: its certificate is served on its own and keeps them after
    /// the plain key is removed.
    fn forget_meta(&mut self, key_blob: &[u8]) {
        let in_use = self.held.iter().any(|e| e.item.key_blob() == key_blob)
            || self.certs.iter().any(
                |e| matches!(&e.item.signer, CertSigner::Held(key) if key.key_blob() == key_blob),
            );
        if !in_use {
            self.remove_meta(key_blob);
        }
    }

    fn clear(&mut self) {
        *self = Store::default();
    }
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
            unlock_failures: AtomicU32::new(0),
            unlock_turn: Mutex::new(()),
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
        let extension: Arc<dyn Extension> = Arc::new(extension);
        self.extensions.rcu(|current| {
            let mut extensions = Vec::clone(current);
            extensions.retain(|e| e.name() != extension.name());
            extensions.push(Arc::clone(&extension));
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
        let decoder: Arc<dyn KeyDecoder> = Arc::new(decoder);
        self.key_types.rcu(|current| {
            let mut registry = KeyRegistry::clone(current);
            registry.register_shared(Arc::clone(&decoder));
            registry
        });
    }

    /// The lifetime keys get without their own `ssh-add -t`.
    pub fn default_lifetime(&self) -> Option<u32> {
        self.default_lifetime
    }

    /// Serve a key added with `ssh-add FILE`, with an optional lifetime from
    /// `ssh-add -t`. A key already served is replaced, so a fresh lifetime
    /// takes effect.
    pub fn add_key(&self, key: SignerRef, lifetime: Option<u32>) {
        self.add_held(key, None, lifetime, None);
    }

    /// Serve `key` added with `ssh-add FILE`, or `cert` with it as its
    /// signer. With `meta`, the key's constraints are recorded in the same
    /// snapshot, so no connection sees the key without them.
    fn add_held(
        &self,
        key: SignerRef,
        cert: Option<CertKey>,
        lifetime: Option<u32>,
        meta: Option<KeyMeta>,
    ) {
        let identity = cert.map(|cert| held_cert(key.clone(), cert));
        self.write(|store| {
            if let Some(meta) = &meta {
                store.set_meta(key.key_blob(), meta.clone());
            }
            match &identity {
                Some(identity) => store.push_cert(identity.clone(), lifetime),
                None => store.hold(key.clone(), lifetime),
            }
        });
        if identity.is_none() {
            tracing::info!(comment = key.comment(), "serving added key");
        }
    }

    /// Serve certificates for backend keys. Each is listed, under its file's
    /// comment (else its key id), while a backend serves a key it certifies
    /// and it has not expired.
    pub fn with_certificates(self, certs: impl IntoIterator<Item = CertKey>) -> Self {
        let served: Vec<Expiring<CertIdentity>> = certs
            .into_iter()
            .map(|cert| {
                let comment = match cert.comment() {
                    "" => cert.certificate().key_id().to_owned(),
                    comment => comment.to_owned(),
                };
                Expiring::new(
                    CertIdentity {
                        cert,
                        comment,
                        signer: CertSigner::Served,
                    },
                    None,
                )
            })
            .collect();
        self.write(|store| Arc::make_mut(&mut store.certs).extend(served.iter().cloned()));
        self
    }

    /// Serve the certificate `ssh-add FILE` sent with its private key, with
    /// an optional lifetime from `ssh-add -t` (which ssh-add sets to the
    /// certificate's expiry on its own). The certificate is listed under the
    /// key's comment, and a certificate already served is replaced.
    pub fn add_cert_key(&self, key: SignerRef, cert: CertKey, lifetime: Option<u32>) {
        self.add_held(key, Some(cert), lifetime, None);
    }

    /// Stop serving the certificate whose blob is `blob`. Returns whether
    /// anything was removed.
    pub fn remove_cert(&self, blob: &[u8]) -> bool {
        self.write(|store| store.take_cert(blob).is_some())
    }

    /// Forget what the agent attached to a backend key that its backend
    /// stopped serving on its own: the certificates `ssh-add -s` attached to
    /// it and, once something was removed (`served` says whether the key
    /// itself was), its `ssh-add -c`/`-h` constraints. Returns whether any
    /// certificate was dropped.
    pub fn release(&self, key_blob: &[u8], served: bool) -> bool {
        self.write(|store| {
            let dropped = store.remove_provider_certs(key_blob);
            if served || dropped {
                store.remove_meta(key_blob);
            }
            dropped
        })
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

    /// Lock with `passphrase`; fails if already locked, as in OpenSSH.
    pub fn lock(&self, passphrase: &[u8]) -> bool {
        let locked = self.locker.lock(passphrase);
        if locked {
            self.lifecycle.iter().for_each(|hook| hook.locked());
        }
        locked
    }

    /// Unlock if `passphrase` is the one the agent was locked with.
    pub fn unlock(&self, passphrase: &[u8]) -> bool {
        let unlocked = self.locker.unlock(passphrase);
        if unlocked {
            self.lifecycle.iter().for_each(|hook| hook.unlocked());
        }
        unlocked
    }

    /// Drop identities whose lifetime has elapsed, in the backends too.
    /// Reads skip expired identities on their own; this frees them.
    pub fn purge_expired(&self) {
        self.purge_backends();
        if self.snapshot().has_expired() {
            self.write(|_| ());
        }
    }

    fn purge_backends(&self) {
        for backend in &self.backends {
            backend.purge_expired();
        }
    }

    /// The store as it is now. It never changes, however many writes follow.
    fn snapshot(&self) -> Arc<Store> {
        self.store.load_full()
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
        self.public_keys_in(&self.snapshot())
    }

    /// [`Self::public_keys`], with the added keys of `store`.
    fn public_keys_in(&self, store: &Store) -> Vec<PublicKey> {
        self.purge_backends();
        let mut keys: Vec<PublicKey> = self
            .backends
            .iter()
            .flat_map(|b| b.identities())
            .map(|key| key.public_key().clone())
            .collect();
        keys.extend(
            store
                .held
                .iter()
                .filter(|e| !e.expired())
                .map(|e| e.item.public_key().clone()),
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
    pub fn identities_for(&self, connection: &Connection) -> Vec<wire::Listed> {
        for _ in 0..LOOKUP_ATTEMPTS {
            let before = self.snapshot();
            let mut consulted = Vec::new();
            let listed = self.list_identities(&before, connection, &mut consulted);
            let after = self.snapshot();
            if Arc::ptr_eq(&before.meta, &after.meta)
                || consulted
                    .iter()
                    .all(|blob| before.meta.get(blob) == after.meta.get(blob))
            {
                return listed;
            }
            tracing::debug!("key constraints changed during the listing");
        }
        tracing::warn!("key constraints kept changing; listing no identities");
        Vec::new()
    }

    /// One pass of [`Self::identities_for`] over `store`, which may be out
    /// of date by the time the backends answer. The blobs whose constraints
    /// it read go in `consulted`.
    fn list_identities(
        &self,
        store: &Store,
        connection: &Connection,
        consulted: &mut Vec<Vec<u8>>,
    ) -> Vec<wire::Listed> {
        let mut out = Vec::new();
        for key in self.public_keys_in(store) {
            let Ok(blob) = key.to_bytes() else {
                continue;
            };
            consulted.push(blob.clone());
            if self.blob_permitted(store, &blob, connection)
                && self.listing_allowed(&key, None, connection)
            {
                out.push(wire::listed(&key));
            }
        }
        for identity in store.certs.iter().filter(|e| !e.expired()).map(|e| &e.item) {
            if identity.cert.expired() {
                tracing::debug!(
                    key_id = identity.cert.certificate().key_id(),
                    "certificate has expired; not listed"
                );
                continue;
            }
            let Some(signer) = self.cert_signer(identity) else {
                continue;
            };
            consulted.push(identity.cert.blob().to_vec());
            consulted.push(signer.key_blob());
            if self.blob_permitted(store, &signer.key_blob(), connection)
                && self.listing_allowed(signer.public_key(), Some(&identity.cert), connection)
            {
                out.push((identity.cert.blob().to_vec(), identity.comment.clone()));
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

    /// Whether the key with `blob` may be shown on this connection.
    fn blob_permitted(&self, store: &Store, blob: &[u8], connection: &Connection) -> bool {
        let meta = self.meta_for(store, blob);
        meta.destination.is_empty() || connection.permits(&meta.destination, None)
    }

    /// Certificates served for `key`, a backend or added key.
    pub fn certificates_for(&self, key: &PublicKey) -> Vec<CertKey> {
        self.snapshot()
            .certs
            .iter()
            .filter(|e| e.item.cert.certifies(key) && !e.item.cert.expired() && !e.expired())
            .map(|e| e.item.cert.clone())
            .collect()
    }

    /// The key that signs for a certificate, if it is served.
    fn cert_signer(&self, identity: &CertIdentity) -> Option<SignerRef> {
        match &identity.signer {
            CertSigner::Held(key) | CertSigner::Provider(key) => Some(key.clone()),
            CertSigner::Served => self
                .backends
                .iter()
                .flat_map(|b| b.known())
                .find(|key| identity.cert.certifies(key.public_key())),
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
    fn handle_unlocked(&self, request: Request, connection: &mut Connection) -> Vec<u8> {
        // Writes are taken one at a time; reads work on a store snapshot and
        // never wait for them.
        let _writing = request.changes_keys().then(|| lock(&self.changes));
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
                    return wire::failure();
                }
                let blob = key.key_blob();
                if !self.may_manage(&blob, connection) {
                    tracing::warn!("refused: key not permitted on this connection");
                    return wire::failure();
                }
                let meta = KeyMeta {
                    confirm,
                    destination,
                };
                self.add_held(key, cert.map(|cert| *cert), lifetime, Some(meta));
                wire::success()
            }
            Request::RemoveIdentity { key_blob } => {
                let target = self.signer_for(&key_blob).ok();
                let change = KeyChange::Remove {
                    key_blob: &key_blob,
                    key: target.as_ref().map(|t| t.public_key()),
                };
                if !self.manage_allowed(change, connection) {
                    return wire::failure();
                }
                if !self.may_manage(&key_blob, connection) {
                    tracing::warn!("refused: key not permitted on this connection");
                    return wire::failure();
                }
                let removed = self.write(|store| {
                    if store.remove_held(&key_blob) {
                        store.forget_meta(&key_blob);
                        Some("removed added key")
                    } else if let Some(identity) = store.take_cert(&key_blob) {
                        if let CertSigner::Held(key) = &identity.signer {
                            store.forget_meta(&key.key_blob());
                        }
                        Some("removed certificate")
                    } else {
                        None
                    }
                });
                if let Some(removed) = removed {
                    tracing::info!("{removed}");
                    wire::success()
                } else if self.backend_key(&key_blob).is_some()
                    && self.backends.iter().any(|b| b.remove(&key_blob))
                {
                    self.release(&key_blob, true);
                    tracing::info!("removed key");
                    wire::success()
                } else {
                    tracing::debug!("no such key to remove");
                    wire::failure()
                }
            }
            Request::RemoveAllIdentities => {
                if !self.manage_allowed(KeyChange::RemoveAll, connection) {
                    return wire::failure();
                }
                self.remove_all();
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
                    Err(e) => {
                        tracing::warn!(error = %e, "cannot add provider key");
                        wire::failure()
                    }
                }
            }
            Request::RemoveSmartcardKey { provider } => {
                let change = KeyChange::RemoveProvider {
                    provider: &provider,
                };
                if !self.manage_allowed(change, connection) {
                    return wire::failure();
                }
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
    fn add_smartcard(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
        meta: KeyMeta,
        certs: Option<AssociatedCerts>,
        connection: &Connection,
    ) -> Result<(), AgentError> {
        let source = self
            .smartcard
            .as_ref()
            .ok_or(AgentError::NoSmartcardProvider)?;
        let lifetime = self.lifetime_for(lifetime);
        self.purge_expired();
        // Fetch the key first: its blob names the constraints.
        let key = source.resolve(provider, pin).map_err(AgentError::Backend)?;
        let certs_only = certs.as_ref().is_some_and(|c| c.certs_only);
        let change = KeyChange::AddProvider {
            provider,
            key: key.public_key(),
            certificates: certs.as_ref().map_or(&[], |c| c.certs.as_slice()),
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
        self.publish_constrained(key.key_blob(), meta, || {
            if !certs_only {
                source
                    .add(provider, pin, lifetime)
                    .map_err(AgentError::Backend)?;
            }
            let Some(certs) = certs else {
                return Ok(());
            };
            let (matching, others): (Vec<_>, Vec<_>) = certs
                .certs
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
                return Err(AgentError::NoMatchingCertificate);
            }
            for cert in matching {
                tracing::info!(
                    key = key.comment(),
                    key_id = cert.certificate().key_id(),
                    "serving certificate"
                );
                let identity = CertIdentity {
                    cert,
                    comment: key.comment().to_owned(),
                    signer: CertSigner::Provider(key.clone()),
                };
                self.write(|store| store.push_cert(identity.clone(), lifetime));
            }
            Ok(())
        })
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
    /// cannot be guessed quickly through the socket.
    fn handle_unlock(&self, passphrase: &[u8]) -> Vec<u8> {
        if !self.is_locked() {
            tracing::warn!("unlock request refused: agent is not locked");
            return wire::failure();
        }
        // Held through the delay, so guesses are taken one at a time however
        // many connections send them.
        let _turn = lock(&self.unlock_turn);
        if self.unlock(passphrase) {
            self.unlock_failures.store(0, Ordering::SeqCst);
            tracing::info!("agent unlocked");
            return wire::success();
        }
        let increment = |n: u32| Some((n + 1).min(MAX_UNLOCK_FAILURES));
        let (Ok(previous) | Err(previous)) =
            self.unlock_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, increment);
        let failures = (previous + 1).min(MAX_UNLOCK_FAILURES);
        let delay = self.unlock_backoff * failures;
        tracing::warn!(failures, ?delay, "unlock request refused: wrong passphrase");
        std::thread::sleep(delay);
        wire::failure()
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
            .find(|e| e.name() == name)
            .cloned();
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

    /// The constraints of the key whose public key blob is `key_blob`. For a
    /// certificate the constraints are those of the key that signs for it.
    fn meta_for(&self, store: &Store, key_blob: &[u8]) -> KeyMeta {
        if let Some(meta) = store.meta.get(key_blob) {
            return meta.clone();
        }
        if let Some(identity) = store.cert(key_blob)
            && let Some(signer) = self.cert_signer(identity)
            && let Some(meta) = store.meta.get(&signer.key_blob())
        {
            return meta.clone();
        }
        KeyMeta::default()
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
    fn publish_constrained<T>(
        &self,
        blob: Vec<u8>,
        meta: KeyMeta,
        publish: impl FnOnce() -> Result<T, AgentError>,
    ) -> Result<T, AgentError> {
        let previous = self.write(|store| {
            let previous = store.meta.get(&blob).cloned();
            store.set_meta(blob.clone(), meta.clone());
            previous
        });
        let published = publish();
        if published.is_err() {
            // Unless something else, such as a backend's `release`, changed
            // them meanwhile.
            let ours = (!meta.is_empty()).then_some(&meta);
            let previous = previous.unwrap_or_default();
            self.write(|store| {
                if store.meta.get(&blob) == ours {
                    store.set_meta(blob.clone(), previous.clone());
                }
            });
        }
        published
    }

    /// Whether this connection may add, replace or remove the key with
    /// `key_blob`, which a destination constraint can forbid even though the
    /// key is served.
    fn may_manage(&self, key_blob: &[u8], connection: &Connection) -> bool {
        let meta = self.meta_for(&self.snapshot(), key_blob);
        meta.destination.is_empty() || connection.permits(&meta.destination, None)
    }

    /// Drop every identity: the backends', the keys added with
    /// `ssh-add FILE` and every certificate. Backs `ssh-add -D`.
    fn remove_all(&self) {
        for backend in &self.backends {
            backend.remove_all();
        }
        self.write(Store::clear);
        self.lifecycle.iter().for_each(|hook| hook.cleared());
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
    /// under. A backend's key is not in the store snapshot the lookup reads,
    /// so the key's constraints are read again once it is found; if they
    /// changed meanwhile the lookup is taken again, and if they keep
    /// changing the key is refused rather than signed with under ones it no
    /// longer has, or does not have yet. Other keys' constraints may change
    /// freely.
    fn constrained_signer(&self, key_blob: &[u8]) -> Result<(SignerRef, KeyMeta), AgentError> {
        for _ in 0..LOOKUP_ATTEMPTS {
            let before = self.snapshot();
            let signer = self.signer_in(&before, key_blob)?;
            let after = self.snapshot();
            let signer_blob = signer.key_blob();
            let meta = after.meta.get(&signer_blob);
            if Arc::ptr_eq(&before.meta, &after.meta) || before.meta.get(&signer_blob) == meta {
                return Ok((signer, meta.cloned().unwrap_or_default()));
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
        self.signer_in(&self.snapshot(), key_blob)
    }

    /// [`Self::signer_for`], with the added keys and certificates of
    /// `store`.
    fn signer_in(&self, store: &Store, key_blob: &[u8]) -> Result<SignerRef, AgentError> {
        self.purge_backends();
        if let Some(key) = self.backend_key(key_blob) {
            return Ok(key);
        }
        if let Some(key) = store.held_key(key_blob) {
            return Ok(key);
        }
        match store.cert(key_blob) {
            Some(identity) if identity.cert.expired() => {
                tracing::warn!(
                    key_id = identity.cert.certificate().key_id(),
                    "certificate has expired"
                );
                Err(AgentError::UnknownKey)
            }
            Some(identity) => self.cert_signer(identity).ok_or(AgentError::UnknownKey),
            None => Err(AgentError::UnknownKey),
        }
    }
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
    use std::time::Instant;

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
        agent
            .unlock_failures
            .store(MAX_UNLOCK_FAILURES, Ordering::SeqCst);
        let mut wrong = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter3".as_slice().encode(&mut wrong).unwrap();
        assert_eq!(agent.handle(&wrong), wire::failure());
        assert_eq!(
            agent.unlock_failures.load(Ordering::SeqCst),
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
            assert_eq!(agent.unlock_failures.load(Ordering::SeqCst), failures);
        }

        let mut right = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut right).unwrap();
        assert_eq!(agent.handle(&right), wire::success());
        assert_eq!(agent.unlock_failures.load(Ordering::SeqCst), 0);
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

        // Pretend the lifetime elapsed.
        agent.write(|store| Arc::make_mut(&mut store.held)[0].expires = Some(Instant::now()));
        assert!(agent.public_keys().is_empty());
        let blob = agent.snapshot().held[0].item.key_blob();
        assert!(agent.signer_for(&blob).is_err());
        // Reads skip the key but leave it to a write, or the server's tick.
        assert_eq!(agent.snapshot().held.len(), 1);
        agent.purge_expired();
        assert!(agent.snapshot().held.is_empty());
    }

    /// `ssh-agent -t`, as [`Agent::with_default_lifetime`]: keys added
    /// without their own lifetime get the default, and an explicit `-t` wins.
    #[test]
    fn default_lifetime_applies_to_added_keys() {
        let agent = Agent::new().with_default_lifetime(Some(60));
        let (add, _) = local_key(0x12, "default@example.com");
        assert_eq!(agent.handle(&add), wire::success());
        let expires = agent.snapshot().held[0]
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
    struct Midway {
        keys: crate::testing::MemoryBackend,
        during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl Backend for Midway {
        fn identities(&self) -> Vec<SignerRef> {
            let during = self.during.lock().unwrap().take();
            if let Some(during) = during {
                during();
            }
            self.keys.identities()
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
                keys: crate::testing::MemoryBackend::new([key.clone()]),
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
                keys: crate::testing::MemoryBackend::new([key.clone()]),
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
                    agent.write(|store| store.set_meta(blob.clone(), hidden.clone()));
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
                    agent.add_held(ed25519(seed, "churn"), None, None, Some(confirm));
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

    /// An added key's constraints go once it and every certificate it signs
    /// for have expired, so the key comes back unconstrained.
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
        agent.add_held(key.clone(), Some(cert), None, Some(confirm.clone()));

        agent.write(|store| Arc::make_mut(&mut store.held)[0].expires = Some(Instant::now()));
        agent.purge_expired();
        assert_eq!(
            agent.snapshot().meta.get(&key.key_blob()),
            Some(&confirm),
            "the certificate still signs under the constraint"
        );

        agent.write(|store| Arc::make_mut(&mut store.certs)[0].expires = Some(Instant::now()));
        agent.purge_expired();
        assert!(agent.snapshot().meta.is_empty());
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
        agent.write(|store| store.set_meta(key.key_blob(), previous.clone()));

        assert!(add(&hidden).is_err());
        assert_eq!(agent.snapshot().meta.get(&key.key_blob()), Some(&previous));

        provider.release.store(true, Ordering::SeqCst);
        assert!(add(&hidden).is_err());
        assert_eq!(agent.snapshot().meta.get(&key.key_blob()), None);
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

    /// Re-adding a key with `ssh-add -c` while a sign looks it up refuses
    /// the sign rather than signing without asking.
    #[test]
    fn a_constraint_added_midway_refuses_the_sign() {
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
        // it must not sign, then or after.
        assert_eq!(agent.handle(&sign_body(&blob, b"data")), wire::failure());
        assert_eq!(agent.handle(&sign_body(&blob, b"data")), wire::failure());
    }

    /// Removing an `ssh-add -c` key leaves its constraint with the
    /// certificate it still signs for, until that goes too.
    #[test]
    fn a_certificate_keeps_its_keys_constraint() {
        let key = ed25519(0x1c, "ferris@example.com");
        let cert = crate::testing::certify(key.public_key().key_data());
        let agent = Agent::new();
        agent.add_key(key.clone(), None);
        agent.add_cert_key(key.clone(), cert.clone(), None);
        agent.write(|store| {
            store.set_meta(
                key.key_blob(),
                KeyMeta {
                    confirm: true,
                    destination: Vec::new(),
                },
            )
        });
        let remove = |blob: &[u8]| {
            let mut body = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
            blob.encode(&mut body).unwrap();
            body
        };

        assert_eq!(agent.handle(&remove(&key.key_blob())), wire::success());
        assert_eq!(
            agent.handle(&sign_body(cert.blob(), b"data")),
            wire::failure(),
            "the certificate signed without confirming"
        );
        assert_eq!(agent.handle(&remove(cert.blob())), wire::success());
        assert!(agent.snapshot().meta.is_empty());
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
        agent.add_key(key.clone(), None);
        agent.add_cert_key(key.clone(), cert.clone(), None);
        agent.write(|store| {
            store.set_meta(
                key.key_blob(),
                KeyMeta {
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
                },
            )
        });

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
}
