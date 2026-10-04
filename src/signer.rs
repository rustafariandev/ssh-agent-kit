//! The signing capability every served key has.
//!
//! A [`Signer`] is one identity the agent lists and signs with: a private
//! key held in memory, a key on a hardware token, a FIDO credential, or
//! anything else that can produce an SSH signature. The agent looks keys up
//! by their public key blob, checks their constraints, calls
//! [`Signer::sign`] and verifies the result before it leaves, so a faulty
//! backend cannot hand out a bad signature.

use signature::Verifier;
use ssh_key::{HashAlg, PublicKey, Signature};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

/// The error a backend reports when it cannot sign. The agent logs it and
/// answers `SSH_AGENT_FAILURE`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A key the agent can sign with.
///
/// Implementations should not expose secret material through `fmt::Debug`,
/// and should log their own successes and failures in the detail only they
/// know (a device name, a slot).
pub trait Signer: Send + Sync {
    /// The public key. Its comment is the identity the agent lists.
    fn public_key(&self) -> &PublicKey;

    /// Sign `data`, returning a complete SSH signature. `hash` is the RSA
    /// digest the client asked for (`sha2-256` or `sha2-512`); other key
    /// types ignore it. The agent refuses SHA-1 RSA requests before this is
    /// called.
    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError>;

    /// Check `sig` over `data` against [`Self::public_key`]. The agent calls
    /// this after every [`Self::sign`], so a faulty signature never leaves.
    /// Override it for keys the generic verifier does not take, such as RSA
    /// keys outside 2048 to 4096 bits.
    fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), BoxError> {
        Ok(verify(self.public_key(), data, sig)?)
    }

    /// Wire blob used to match sign and remove requests.
    fn key_blob(&self) -> Vec<u8> {
        self.public_key().to_bytes().expect("vec write")
    }
}

/// A shared [`Signer`] with value semantics.
///
/// `PartialEq`/`Eq` compare only the public key, so a request that carries
/// one can still derive them; `Debug` shows the public key only.
#[derive(Clone)]
pub struct SignerRef(Arc<dyn Signer>);

impl SignerRef {
    pub fn new(signer: impl Signer + 'static) -> Self {
        SignerRef(Arc::new(signer))
    }

    pub fn from_arc(signer: Arc<dyn Signer>) -> Self {
        SignerRef(signer)
    }

    pub fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    pub fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        self.0.sign(data, hash)
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), BoxError> {
        self.0.verify(data, sig)
    }

    pub fn key_blob(&self) -> Vec<u8> {
        self.0.key_blob()
    }

    pub fn comment(&self) -> &str {
        self.0.public_key().comment()
    }

    pub fn as_arc(&self) -> &Arc<dyn Signer> {
        &self.0
    }
}

impl fmt::Debug for SignerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignerRef")
            .field(self.0.public_key())
            .finish()
    }
}

impl PartialEq for SignerRef {
    fn eq(&self, other: &Self) -> bool {
        self.0.key_blob() == other.0.key_blob()
    }
}

impl Eq for SignerRef {}

/// A signature that does not verify against its public key.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("signature does not verify against the public key")]
pub struct VerifyError;

/// Check `sig` over `message` against `key`.
pub fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> Result<(), VerifyError> {
    Verifier::verify(key, message, sig).map_err(|_| VerifyError)
}
