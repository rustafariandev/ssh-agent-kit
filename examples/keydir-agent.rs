//! A custom [`Backend`]: serve every unencrypted ed25519, ECDSA or RSA key
//! in a directory, picking up added and deleted files on each listing.
//!
//! The agent never holds the keys itself. The backend reads them when a
//! client lists keys, and each [`Signer`] signs straight from its file's key.
//! RSA keys show two things a signer may need: honouring the digest the
//! client asks for, and overriding [`Signer::verify`].
//!
//! ```sh
//! mkdir -p /tmp/keys
//! ssh-keygen -q -t ed25519 -N '' -C demo -f /tmp/keys/demo
//! ssh-keygen -q -t rsa -b 3072 -N '' -C demo-rsa -f /tmp/keys/demo-rsa
//! cargo run --example keydir-agent -- /tmp/keys /tmp/keydir.sock &
//! SSH_AUTH_SOCK=/tmp/keydir.sock ssh-add -l
//! SSH_AUTH_SOCK=/tmp/keydir.sock ssh-keygen -Y sign -n file -f /tmp/keys/demo-rsa.pub README.md
//! ```

use rand_core::OsRng;
use rsa::Pkcs1v15Sign;
use sha2::{Digest, Sha256, Sha512};
use ssh_agent_kit::ssh_key::private::{KeypairData, RsaKeypair};
use ssh_agent_kit::ssh_key::{Algorithm, HashAlg, Mpint, PrivateKey, PublicKey, Signature};
use ssh_agent_kit::{Agent, Backend, BoxError, Signer, SignerRef, bind_socket, serve};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// An ed25519 or ECDSA key file, which `ssh-key` signs itself.
struct FileKey {
    private: PrivateKey,
    public: PublicKey,
}

impl Signer for FileKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// `hash` only matters for RSA, so it is ignored here.
    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, BoxError> {
        Ok(signature::Signer::try_sign(&self.private, data)?)
    }
}

/// An RSA key file, signed with the `rsa` crate.
struct RsaFileKey {
    key: rsa::RsaPrivateKey,
    public: PublicKey,
}

/// Smallest RSA modulus accepted, in bits, as OpenSSH enforces.
const MIN_RSA_BITS: usize = 1024;

impl RsaFileKey {
    /// Rebuild the `rsa` key from the file's fields. `p` and `q` are passed
    /// as the file gives them: `ssh-key`'s own conversion passes `p` twice.
    fn new(pair: &RsaKeypair, public: PublicKey) -> Result<Self, BoxError> {
        let int = |m: &Mpint| {
            m.as_positive_bytes()
                .map(rsa::BigUint::from_bytes_be)
                .ok_or("malformed RSA key")
        };
        let n = int(&pair.public.n)?;
        if n.bits() < MIN_RSA_BITS {
            return Err(format!("{}-bit RSA key is too small", n.bits()).into());
        }
        let key = rsa::RsaPrivateKey::from_components(
            n,
            int(&pair.public.e)?,
            int(&pair.private.d)?,
            vec![int(&pair.private.p)?, int(&pair.private.q)?],
        )?;
        Ok(RsaFileKey { key, public })
    }
}

/// The PKCS#1 v1.5 scheme and digest of `data` for `rsa-sha2-256` or
/// `rsa-sha2-512`. The agent refuses SHA-1 (`ssh-rsa`) before signing.
fn scheme(data: &[u8], hash: HashAlg) -> Result<(Pkcs1v15Sign, Vec<u8>), BoxError> {
    match hash {
        HashAlg::Sha256 => Ok((Pkcs1v15Sign::new::<Sha256>(), Sha256::digest(data).to_vec())),
        HashAlg::Sha512 => Ok((Pkcs1v15Sign::new::<Sha512>(), Sha512::digest(data).to_vec())),
        other => Err(format!("unsupported RSA digest {other}").into()),
    }
}

impl Signer for RsaFileKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Sign with the digest the client asked for; the signature's algorithm
    /// (`rsa-sha2-256` or `rsa-sha2-512`) must say which.
    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        let (scheme, digest) = scheme(data, hash)?;
        // Blinded, to keep the private exponent out of the timing.
        let raw = self.key.sign_with_rng(&mut OsRng, scheme, &digest)?;
        Ok(Signature::new(Algorithm::Rsa { hash: Some(hash) }, raw)?)
    }

    /// The agent checks every signature before it leaves. `ssh-key`'s
    /// verifier only takes 2048- to 4096-bit moduli, so check with `rsa`.
    fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), BoxError> {
        let Algorithm::Rsa { hash: Some(hash) } = sig.algorithm() else {
            return Err("not an rsa-sha2 signature".into());
        };
        let (scheme, digest) = scheme(data, hash)?;
        Ok(self
            .key
            .to_public_key()
            .verify(scheme, &digest, sig.as_bytes())?)
    }
}

/// Every usable key in `dir`, read afresh on each listing.
struct KeyDir {
    dir: PathBuf,
}

impl KeyDir {
    fn load(path: &Path) -> Result<SignerRef, BoxError> {
        let private = PrivateKey::read_openssh_file(path)?;
        if private.is_encrypted() {
            return Err("encrypted".into());
        }
        let public = private.public_key().clone();
        Ok(match private.key_data() {
            KeypairData::Rsa(pair) => SignerRef::new(RsaFileKey::new(pair, public)?),
            KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {
                SignerRef::new(FileKey { private, public })
            }
            _ => return Err(format!("unsupported key type {}", private.algorithm()).into()),
        })
    }
}

impl Backend for KeyDir {
    fn identities(&self) -> Vec<SignerRef> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_none())
            .collect();
        paths.sort();
        paths
            .iter()
            .filter_map(|path| match Self::load(path) {
                Ok(key) => Some(key),
                Err(e) => {
                    eprintln!("skipping {}: {e}", path.display());
                    None
                }
            })
            .collect()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(dir), Some(socket)) = (args.next(), args.next()) else {
        eprintln!("usage: keydir-agent DIR SOCKET");
        std::process::exit(2);
    };
    let (listener, _guard) = bind_socket(Path::new(&socket))?;
    let agent = Agent::new().with_backend(Arc::new(KeyDir { dir: dir.into() }));
    serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
    Ok(())
}
