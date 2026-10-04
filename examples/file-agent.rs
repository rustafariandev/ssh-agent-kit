//! A minimal agent built on the kit: it holds the keys `ssh-add FILE` sends,
//! asks before signing with keys added with `ssh-add -c`, and logs every
//! signature through a policy.
//!
//! ```sh
//! cargo run --example file-agent -- /tmp/file-agent.sock &
//! export SSH_AUTH_SOCK=/tmp/file-agent.sock
//! ssh-add ~/.ssh/id_ed25519
//! ssh-add -l
//! ```

use ssh_agent_kit::{
    Agent, Confirm, ConfirmRequest, Policy, SignInfo, bind_socket, default_socket_path, serve,
};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Asks on the terminal the agent was started from.
struct AskOnStdin;

impl Confirm for AskOnStdin {
    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        eprint!("{} ", request.message());
        std::io::stderr().flush().ok()?;
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer).ok()?;
        Some(matches!(answer.trim(), "y" | "yes"))
    }
}

/// Allows everything and prints each signature.
struct Audit;

impl Policy for Audit {
    fn signed(&self, request: &SignInfo<'_>) {
        eprintln!(
            "signed {} bytes with {}",
            request.data.len(),
            request.key.comment()
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_socket_path("file-agent"));
    let (listener, _guard) = bind_socket(&path)?;
    let agent = Agent::new()
        .with_confirm(Arc::new(AskOnStdin))
        .with_policy(Arc::new(Audit));
    eprintln!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK", path.display());
    serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
    Ok(())
}
