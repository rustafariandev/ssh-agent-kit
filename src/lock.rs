//! `ssh-add -x`/`-X`: locking the agent with a passphrase.
//!
//! The agent asks a [`Locker`] whether it is locked and to check the unlock
//! passphrase; it slows down wrong guesses itself. [`PassphraseLock`] is the
//! default, which keeps only a salted hash of the passphrase, as OpenSSH's
//! agent does. A custom locker can tie the lock to something else, such as
//! a hardware token.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, MutexGuard};

/// Holds the agent's lock state.
pub trait Locker: Send + Sync {
    /// Whether the agent is locked.
    fn is_locked(&self) -> bool;

    /// Lock with `passphrase`. Returns `false` if already locked, as in
    /// OpenSSH, or if the lock could not be set.
    fn lock(&self, passphrase: &[u8]) -> bool;

    /// Unlock if `passphrase` is the one the agent was locked with.
    fn unlock(&self, passphrase: &[u8]) -> bool;
}

/// The default [`Locker`]: a salted SHA-256 of the passphrase while locked,
/// compared in constant time, so the passphrase itself is not kept.
#[derive(Default)]
pub struct PassphraseLock(Mutex<Option<PassphraseHash>>);

impl PassphraseLock {
    fn state(&self) -> MutexGuard<'_, Option<PassphraseHash>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Locker for PassphraseLock {
    fn is_locked(&self) -> bool {
        self.state().is_some()
    }

    fn lock(&self, passphrase: &[u8]) -> bool {
        let mut state = self.state();
        if state.is_some() {
            return false;
        }
        match PassphraseHash::new(passphrase) {
            Some(hash) => {
                *state = Some(hash);
                true
            }
            None => {
                tracing::error!("cannot lock: no system randomness for the salt");
                false
            }
        }
    }

    fn unlock(&self, passphrase: &[u8]) -> bool {
        let mut state = self.state();
        match state.as_ref() {
            Some(hash) if hash.matches(passphrase) => {
                *state = None;
                true
            }
            _ => false,
        }
    }
}

/// A salted SHA-256 of the lock passphrase. Compared in constant time.
struct PassphraseHash {
    salt: [u8; 16],
    digest: [u8; 32],
}

impl PassphraseHash {
    /// Hash `passphrase` under a fresh random salt; `None` if the system
    /// has no randomness to give.
    fn new(passphrase: &[u8]) -> Option<Self> {
        let mut salt = [0u8; 16];
        OsRng.try_fill_bytes(&mut salt).ok()?;
        let digest = Self::digest(&salt, passphrase);
        Some(PassphraseHash { salt, digest })
    }

    fn digest(salt: &[u8; 16], passphrase: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(salt)
            .chain_update(passphrase)
            .finalize()
            .into()
    }

    fn matches(&self, passphrase: &[u8]) -> bool {
        let candidate = Self::digest(&self.salt, passphrase);
        self.digest
            .iter()
            .zip(candidate.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}
