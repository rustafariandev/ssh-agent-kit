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
//!
//! On Windows the socket is a named pipe, and the agent also answers
//! PuTTY's tools as Pageant would, on Pageant's pipe and window:
//!
//! ```powershell
//! cargo run --example file-agent -- \.\pipe\file-agent
//! $env:SSH_AUTH_SOCK = '\.\pipe\file-agent'   # in another window
//! ssh-add $HOME\.ssh\id_ed25519
//! ssh-add -l
//! ```
//!
//! Git Bash's own `ssh` cannot open the pipe, so the agent also serves a
//! Cygwin-style socket for it, and prints its path:
//!
//! ```sh
//! export SSH_AUTH_SOCK=C:/Users/me/AppData/Local/file-agent/agent.sock
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
    let agent = Arc::new(
        Agent::new()
            .with_confirm(Arc::new(AskOnStdin))
            .with_policy(Arc::new(Audit)),
    );
    let shutdown = Arc::new(AtomicBool::new(false));
    #[cfg(windows)]
    {
        eprintln!("$env:SSH_AUTH_SOCK = '{}'", path.display());
        serve_as_pageant(&agent, &shutdown);
        serve_cygwin(&agent, &shutdown);
    }
    #[cfg(unix)]
    eprintln!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK", path.display());
    serve(listener, agent, shutdown)?;
    Ok(())
}

/// Answer the `ssh` that Git for Windows, MSYS2 and Cygwin bundle too, on a
/// Cygwin-style socket in `%LOCALAPPDATA%\file-agent`.
#[cfg(windows)]
fn serve_cygwin(agent: &Arc<Agent>, shutdown: &Arc<AtomicBool>) {
    use ssh_agent_kit::{bind_cygwin_socket, server::runtime_dir};

    let path = runtime_dir("file-agent").join("agent.sock");
    match bind_cygwin_socket(&path) {
        Ok((listener, guard)) => {
            // Git Bash takes the path with forward slashes.
            let unix_path = path.to_string_lossy().replace('\\', "/");
            eprintln!("export SSH_AUTH_SOCK='{unix_path}'   # in Git Bash");
            let (agent, shutdown) = (Arc::clone(agent), Arc::clone(shutdown));
            std::thread::spawn(move || {
                let _guard = guard;
                if let Err(e) = serve(listener, agent, shutdown) {
                    eprintln!("Cygwin socket: {e}");
                }
            });
        }
        Err(e) => eprintln!("not serving a Cygwin socket: {e}"),
    }
}

/// Answer PuTTY's tools too, on threads of their own: newer ones on
/// Pageant's pipe, older ones through its window. Either is skipped, with a
/// warning, when a Pageant already has it.
#[cfg(windows)]
fn serve_as_pageant(agent: &Arc<Agent>, shutdown: &Arc<AtomicBool>) {
    use ssh_agent_kit::{pageant_pipe_name, serve_pageant_window};

    let pipe = pageant_pipe_name()
        .map_err(|e| e.to_string())
        .and_then(|name| bind_socket(&name).map_err(|e| e.to_string()));
    match pipe {
        Ok((listener, guard)) => {
            let (agent, shutdown) = (Arc::clone(agent), Arc::clone(shutdown));
            std::thread::spawn(move || {
                let _guard = guard;
                if let Err(e) = serve(listener, agent, shutdown) {
                    eprintln!("Pageant pipe: {e}");
                }
            });
        }
        Err(e) => eprintln!("not serving Pageant's pipe: {e}"),
    }
    let (agent, shutdown) = (Arc::clone(agent), Arc::clone(shutdown));
    std::thread::spawn(move || {
        if let Err(e) = serve_pageant_window(agent, shutdown) {
            eprintln!("not serving Pageant's window: {e}");
        }
    });
}
