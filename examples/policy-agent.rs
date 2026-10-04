//! A custom [`Policy`]: decide what the agent's keys may sign, and who may
//! change them, beyond the constraints the client attached.
//!
//! This policy:
//!
//! - signs SSH logins, but refuses them through a forwarded agent
//!   (`ssh -A`) once the session says so with `session-bind@openssh.com`;
//! - signs `ssh-keygen -Y sign` only in the namespaces it was given
//!   (`git` by default, for signed commits);
//! - refuses anything else, such as arbitrary data from an unknown client;
//! - refuses `ssh-add`, `-d` and `-D` from forwarded connections;
//! - writes an audit line for every signature.
//!
//! ```sh
//! cargo run --example policy-agent -- /tmp/policy.sock git file &
//! export SSH_AUTH_SOCK=/tmp/policy.sock
//! ssh-add ~/.ssh/id_ed25519
//! ssh-keygen -Y sign -n file -f ~/.ssh/id_ed25519.pub README.md   # allowed
//! ssh-keygen -Y sign -n other -f ~/.ssh/id_ed25519.pub README.md  # refused
//! ```

use ssh_agent_kit::wire::{SignedData, classify_data};
use ssh_agent_kit::{Agent, Connection, Policy, SignInfo, bind_socket, serve};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct Rules {
    /// `ssh-keygen -Y sign` namespaces that may be signed.
    namespaces: Vec<String>,
}

/// Whether the client's last `session-bind@openssh.com` said the agent is
/// being used through a forwarded connection.
fn forwarded(connection: &Connection) -> bool {
    connection.bindings().iter().any(|b| b.forwarded)
}

impl Policy for Rules {
    fn allow_sign(&self, request: &SignInfo<'_>) -> bool {
        let verdict = match classify_data(request.data) {
            SignedData::UserAuth { .. } if forwarded(request.connection) => {
                Err("login through a forwarded agent".to_owned())
            }
            SignedData::UserAuth { user, .. } => {
                eprintln!("login as {user} allowed");
                Ok(())
            }
            SignedData::SshSig { namespace } if self.namespaces.contains(&namespace) => Ok(()),
            SignedData::SshSig { namespace } => Err(format!("namespace {namespace:?}")),
            SignedData::Other => Err("unrecognised data".to_owned()),
        };
        if let Err(why) = &verdict {
            eprintln!("refused {}: {why}", request.key.comment());
        }
        verdict.is_ok()
    }

    fn signed(&self, request: &SignInfo<'_>) {
        eprintln!(
            "audit: {} signed {} bytes",
            request.key.comment(),
            request.data.len()
        );
    }

    fn allow_manage(&self, connection: &Connection) -> bool {
        !forwarded(connection)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(socket) = args.next() else {
        eprintln!("usage: policy-agent SOCKET [NAMESPACE…]");
        std::process::exit(2);
    };
    let mut namespaces: Vec<String> = args.collect();
    if namespaces.is_empty() {
        namespaces.push("git".to_owned());
    }

    let (listener, _guard) = bind_socket(Path::new(&socket))?;
    let agent = Agent::new().with_policy(Arc::new(Rules { namespaces }));
    serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
    Ok(())
}
