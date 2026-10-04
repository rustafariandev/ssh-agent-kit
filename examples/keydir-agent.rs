//! A custom [`Backend`]: serve every unencrypted ed25519 or ECDSA key in a
//! directory, picking up added and deleted files on each listing.
//!
//! The agent never holds the keys itself. The backend reads them when a
//! client lists keys, and each [`Signer`] signs straight from its file's key.
//!
//! ```sh
//! mkdir -p /tmp/keys && ssh-keygen -q -t ed25519 -N '' -C demo -f /tmp/keys/demo
//! cargo run --example keydir-agent -- /tmp/keys /tmp/keydir.sock &
//! SSH_AUTH_SOCK=/tmp/keydir.sock ssh-add -l
//! SSH_AUTH_SOCK=/tmp/keydir.sock ssh-keygen -Y sign -n file -f /tmp/keys/demo.pub README.md
//! ```

use ssh_agent_kit::ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use ssh_agent_kit::{Agent, Backend, BoxError, Signer, SignerRef, bind_socket, serve};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// One key file.
struct FileKey {
    private: PrivateKey,
    public: PublicKey,
}

impl Signer for FileKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// `ssh-key` signs ed25519 and ECDSA keys itself. RSA is left out: it
    /// would have to honour `hash`, which this simple signer ignores.
    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, BoxError> {
        Ok(signature::Signer::try_sign(&self.private, data)?)
    }
}

/// Every usable key in `dir`, read afresh on each listing.
struct KeyDir {
    dir: PathBuf,
}

impl KeyDir {
    fn load(path: &Path) -> Option<FileKey> {
        let private = PrivateKey::read_openssh_file(path).ok()?;
        if private.is_encrypted() || private.algorithm().is_rsa() {
            eprintln!("skipping {}: encrypted or RSA", path.display());
            return None;
        }
        let public = private.public_key().clone();
        Some(FileKey { private, public })
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
            .filter_map(|p| Self::load(p))
            .map(SignerRef::new)
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
