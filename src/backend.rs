//! Where an agent's keys come from, besides `ssh-add FILE`.
//!
//! - A [`Backend`] serves identities it owns: keys on a hardware token, in
//!   a keychain, fetched from a service. The agent lists them, signs with
//!   them and asks the backend to drop them on `ssh-add -d`/`-D`.
//! - A [`SmartcardProvider`] answers `ssh-add -s PROVIDER` and
//!   `ssh-add -e PROVIDER`: it turns the provider string into a key and
//!   starts or stops serving it. A provider is usually also the
//!   [`Backend`] that lists the keys it added.
//! - A [`Lifecycle`] hook hears when the agent is locked, unlocked or
//!   cleared, to drop cached secrets such as PIN tokens.
//!
//! Keys loaded with `ssh-add FILE` are decoded by a
//! [`KeyDecoder`](crate::KeyDecoder) and held by the agent itself.

use crate::signer::{BoxError, SignerRef};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A source of identities the agent serves on its owner's behalf.
///
/// [`Self::remove`] and [`Self::remove_all`] are called while the agent
/// commits a key change, which it does one at a time. A request that
/// changes keys, locks or unlocks (through
/// [`Agent::handle`](crate::Agent::handle), [`Agent::lock`](crate::Agent::lock)
/// or [`Agent::unlock`](crate::Agent::unlock)) made from one of them is
/// refused; one made on another thread while holding a lock they take waits
/// for the commit to finish, so never returns.
/// [`Agent::release`](crate::Agent::release) and the agent's other methods
/// may be called. [`Self::known`] is also called in that turn by
/// [`Agent::release`](crate::Agent::release) made on another thread, to
/// check the key is gone, so call `release` with none of the locks it
/// takes held. The other methods are called with no lock held.
pub trait Backend: Send + Sync {
    /// Every identity to list, fetching what is not known yet (which may
    /// mean talking to a device). Keys that cannot be fetched are left out,
    /// with a log line, so a client still sees the rest.
    fn identities(&self) -> Vec<SignerRef>;

    /// The identities known without fetching anything, used to find the key
    /// a sign or remove request names. Defaults to [`Self::identities`]; a
    /// backend whose fetch is slow or asks the user for something should
    /// answer from its cache.
    fn known(&self) -> Vec<SignerRef> {
        self.identities()
    }

    /// `ssh-add -d`: stop serving the identity whose public key blob is
    /// `key_blob`. Returns whether it was served.
    fn remove(&self, _key_blob: &[u8]) -> bool {
        false
    }

    /// `ssh-add -D`: stop serving every identity this backend can drop.
    fn remove_all(&self) {}

    /// Drop identities whose lifetime has run out. Called before every
    /// lookup, and about once a second by the server.
    fn purge_expired(&self) {}
}

/// What [`SmartcardProvider::remove`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// Whether the key was being served (and is not any more).
    pub served: bool,
    /// The public key blob of the key the provider string names, if it is
    /// known. Certificates attached to it with `ssh-add -s PROVIDER CERT…`
    /// are dropped with it, and so are its `ssh-add -c`/`-h` constraints.
    pub key_blob: Option<Vec<u8>>,
}

/// Answers `ssh-add -s PROVIDER` and `ssh-add -e PROVIDER`.
///
/// OpenSSH names a PKCS#11 library as the provider; an agent built on this
/// crate decides what the string means, such as a slot or a key label on
/// its own device. The agent handles constraints, lifetimes' defaults and
/// attached certificates around these calls.
///
/// [`Self::add`] and [`Self::remove`] are called while the agent commits a
/// key change, which it does one at a time: a request that changes keys,
/// locks or unlocks (through [`Agent::handle`](crate::Agent::handle),
/// [`Agent::lock`](crate::Agent::lock) or
/// [`Agent::unlock`](crate::Agent::unlock)) made from one is refused, and a
/// slow call holds up other connections' key changes (not
/// their listings or signatures) until it returns. [`Self::resolve`] is
/// called before, with no lock held, so a PIN prompt there holds up no
/// one.
pub trait SmartcardProvider: Send + Sync {
    /// The key `provider` names, fetched (or found in a cache) but not
    /// served yet. `pin` is the one `ssh-add -s` read, often empty.
    fn resolve(&self, provider: &[u8], pin: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError>;

    /// Start serving the key `provider` names, with the lifetime in seconds
    /// from `ssh-add -t` (or the agent's default). Re-adding a served key
    /// restarts its lifetime.
    fn add(
        &self,
        provider: &[u8],
        pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
    ) -> Result<(), BoxError>;

    /// Stop serving the key `provider` names.
    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError>;
}

/// Hears the agent's state changes.
pub trait Lifecycle: Send + Sync {
    /// `ssh-add -x` locked the agent.
    ///
    /// Called before the agent is locked or unlocked again, so the hooks
    /// hear of each in the order they happened: a lock, unlock or key change
    /// asked for from here (through [`Agent::handle`](crate::Agent::handle),
    /// [`Agent::lock`](crate::Agent::lock) or
    /// [`Agent::unlock`](crate::Agent::unlock)) fails. To change keys on
    /// unlock, do it once the hook has returned, such as from another
    /// thread.
    fn locked(&self) {}

    /// `ssh-add -X` unlocked it. Called as [`Self::locked`] is.
    fn unlocked(&self) {}

    /// `ssh-add -D` removed every identity. Called before another key
    /// change can land, while the agent commits this one: a request that
    /// changes keys, locks or unlocks (through
    /// [`Agent::handle`](crate::Agent::handle),
    /// [`Agent::lock`](crate::Agent::lock) or
    /// [`Agent::unlock`](crate::Agent::unlock)) made from here is refused.
    fn cleared(&self) {}
}

/// A value with an optional expiry, such as an identity added with
/// `ssh-add -t`.
#[derive(Debug, Clone)]
pub struct Expiring<T> {
    pub item: T,
    pub expires: Option<Instant>,
}

impl<T> Expiring<T> {
    /// `lifetime` is in seconds; `None` or zero never expires.
    pub fn new(item: T, lifetime: Option<u32>) -> Self {
        let expires = lifetime
            .filter(|secs| *secs > 0)
            .map(|secs| Instant::now() + Duration::from_secs(secs as u64));
        Expiring { item, expires }
    }

    pub fn expired(&self) -> bool {
        self.expires.is_some_and(|at| Instant::now() >= at)
    }
}
