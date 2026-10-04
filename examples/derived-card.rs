//! A custom [`SmartcardProvider`]: `ssh-add -s NAME` serves an ed25519 key
//! derived from a secret seed and NAME, like a toy hardware token. The same
//! name always gives the same key, so it can sit in `authorized_keys`.
//!
//! The provider is also the [`Backend`] that lists the keys it added, and it
//! honours `ssh-add -t` lifetimes with [`Expiring`].
//!
//! ```sh
//! cargo run --example derived-card -- /tmp/card.sock &
//! export SSH_AUTH_SOCK=/tmp/card.sock
//! ssh-add -s github          # the PIN prompt is accepted and ignored
//! ssh-add -L                 # the derived public key, comment "github"
//! ssh-add -t 60 -s laptop    # served for one minute
//! ssh-add -e github
//! ```
//!
//! Set `CARD_SEED` to any string to keep the keys across restarts; without
//! it, each run derives from a fresh random seed.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use ssh_agent_kit::ssh_key::private::Ed25519Keypair;
use ssh_agent_kit::ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use ssh_agent_kit::{
    Agent, Backend, BoxError, Expiring, Removed, Signer, SignerRef, SmartcardProvider, bind_socket,
    serve,
};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A key derived for one name.
struct DerivedKey {
    private: PrivateKey,
    public: PublicKey,
}

impl Signer for DerivedKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, BoxError> {
        Ok(signature::Signer::try_sign(&self.private, data)?)
    }
}

struct Card {
    seed: Zeroizing<[u8; 32]>,
    /// The keys `ssh-add -s` added, by name.
    served: Mutex<Vec<Expiring<(String, SignerRef)>>>,
}

impl Card {
    fn name(provider: &[u8]) -> Result<String, BoxError> {
        let name = std::str::from_utf8(provider)?.trim();
        if name.is_empty() {
            return Err("empty key name".into());
        }
        Ok(name.to_owned())
    }

    /// The key for `name`: ed25519 from SHA-256(seed ‖ name).
    fn derive(&self, name: &str) -> SignerRef {
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            Sha256::new()
                .chain_update(self.seed.as_slice())
                .chain_update(name.as_bytes())
                .finalize()
                .into(),
        );
        let mut private = PrivateKey::from(Ed25519Keypair::from_seed(&secret));
        private.set_comment(name);
        let public = private.public_key().clone();
        SignerRef::new(DerivedKey { private, public })
    }
}

impl SmartcardProvider for Card {
    fn resolve(&self, provider: &[u8], _pin: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
        Ok(self.derive(&Self::name(provider)?))
    }

    fn add(
        &self,
        provider: &[u8],
        _pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
    ) -> Result<(), BoxError> {
        let name = Self::name(provider)?;
        let key = self.derive(&name);
        let mut served = self.served.lock().unwrap();
        served.retain(|e| e.item.0 != name);
        served.push(Expiring::new((name.clone(), key), lifetime));
        eprintln!("serving {name}");
        Ok(())
    }

    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
        let name = Self::name(provider)?;
        let mut served = self.served.lock().unwrap();
        let before = served.len();
        served.retain(|e| e.item.0 != name);
        Ok(Removed {
            served: served.len() != before,
            key_blob: Some(self.derive(&name).key_blob()),
        })
    }
}

impl Backend for Card {
    fn identities(&self) -> Vec<SignerRef> {
        let served = self.served.lock().unwrap();
        served.iter().map(|e| e.item.1.clone()).collect()
    }

    fn remove(&self, key_blob: &[u8]) -> bool {
        let mut served = self.served.lock().unwrap();
        let before = served.len();
        served.retain(|e| e.item.1.key_blob() != key_blob);
        served.len() != before
    }

    fn remove_all(&self) {
        self.served.lock().unwrap().clear();
    }

    fn purge_expired(&self) {
        self.served.lock().unwrap().retain(|e| !e.expired());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(socket) = std::env::args_os().nth(1) else {
        eprintln!("usage: derived-card SOCKET");
        std::process::exit(2);
    };
    let mut seed = Zeroizing::new([0u8; 32]);
    match std::env::var("CARD_SEED") {
        Ok(text) => seed.copy_from_slice(&Sha256::digest(text.as_bytes())),
        Err(_) => OsRng.fill_bytes(seed.as_mut_slice()),
    }
    let card = Arc::new(Card {
        seed,
        served: Mutex::new(Vec::new()),
    });

    let (listener, _guard) = bind_socket(Path::new(&socket))?;
    let agent = Agent::new()
        .with_backend(Arc::clone(&card) as _)
        .with_smartcard(card);
    serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
    Ok(())
}
