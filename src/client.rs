//! A minimal client of the SSH agent protocol, for adding keys to a running
//! agent (one built on this crate, or OpenSSH's) the way `ssh-add` does.

use crate::wire;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cannot connect to the agent at {path}: {source}")]
    Connect { path: PathBuf, source: io::Error },
    #[error("agent connection failed: {0}")]
    Io(#[from] io::Error),
    #[error("bad reply from the agent: {0}")]
    Frame(#[from] wire::FrameError),
    #[error("the agent closed the connection without replying")]
    Closed,
    #[error("the agent refused the key")]
    Refused,
}

/// Add a key with `SSH2_AGENTC_ADD_IDENTITY`. `body` is what follows the
/// message type: the key type, the key and its comment.
pub fn add_identity(socket: &Path, body: &[u8]) -> Result<(), ClientError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| ClientError::Connect {
        path: socket.to_owned(),
        source,
    })?;
    let mut request = Vec::with_capacity(1 + body.len());
    request.push(wire::SSH2_AGENTC_ADD_IDENTITY);
    request.extend_from_slice(body);
    wire::write_frame(&mut stream, &request)?;
    match wire::read_frame(&mut stream)?.as_deref() {
        Some([wire::SSH_AGENT_SUCCESS]) => Ok(()),
        Some(_) => Err(ClientError::Refused),
        None => Err(ClientError::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, bind_socket, serve};
    use ssh_encoding::Encode;
    use ssh_key::private::Ed25519Keypair;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A key added over a socket is served, and a malformed body is refused.
    #[test]
    fn adds_a_key_to_a_running_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (listener, _guard) = bind_socket(&path).unwrap();
        let agent = Arc::new(Agent::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let agent = Arc::clone(&agent);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, agent, shutdown))
        };

        let pair = Ed25519Keypair::from_seed(&[0x5A; 32]);
        let mut body = Vec::new();
        "ssh-ed25519".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();
        add_identity(&path, &body).unwrap();
        let served = agent.public_keys();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].key_data(), &pair.public.into());
        assert_eq!(served[0].comment(), "ferris@example.com");

        assert!(matches!(
            add_identity(&path, b"garbage"),
            Err(ClientError::Refused)
        ));
        assert!(matches!(
            add_identity(&dir.path().join("missing.sock"), &body),
            Err(ClientError::Connect { .. })
        ));

        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
}
