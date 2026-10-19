//! A custom [`Extension`]: answer `SSH_AGENTC_EXTENSION` requests named
//! `status@example.com` with a line about the agent, and a client that asks
//! for it over the socket.
//!
//! Extensions are how an agent offers more than the standard protocol, such
//! as asking a hardware backend for its status or rotating a key. The agent
//! answers `session-bind@openssh.com` and `query` itself; other names go to
//! the registered handlers.
//!
//! ```sh
//! cargo run --example extension-agent -- serve /tmp/ext.sock &
//! cargo run --example extension-agent -- ask /tmp/ext.sock
//! SSH_AUTH_SOCK=/tmp/ext.sock ssh-add -x   # lock, then ask again
//! ```

use ssh_agent_kit::wire::{self, read_frame, write_frame};
use ssh_agent_kit::{
    Agent, Extension, ExtensionContext, ExtensionReply, bind_socket, connect, serve,
};
use ssh_encoding::{Decode, Encode};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const STATUS: &str = "status@example.com";

/// Answers with uptime, request count and lock state as one SSH string,
/// after `SSH_AGENT_SUCCESS`, as OpenSSH's extension replies are shaped.
struct Status {
    started: Instant,
    asked: AtomicU64,
}

impl Extension for Status {
    fn name(&self) -> &str {
        STATUS
    }

    fn handle(&self, ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply {
        // This extension takes no arguments.
        if !data.is_empty() {
            return ExtensionReply::Failure;
        }
        let asked = self.asked.fetch_add(1, Ordering::Relaxed) + 1;
        let line = format!(
            "up {}s, asked {asked} times, {}",
            self.started.elapsed().as_secs(),
            if ctx.locked() { "locked" } else { "unlocked" }
        );
        let mut body = vec![wire::SSH_AGENT_SUCCESS];
        line.encode(&mut body).expect("vec write");
        ExtensionReply::Raw(body)
    }
}

/// Send one extension request and print the reply.
fn ask(socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = connect(socket)?;
    let mut request = vec![wire::SSH_AGENTC_EXTENSION];
    STATUS.encode(&mut request)?;
    write_frame(&mut stream, &request)?;
    let reply = read_frame(&mut stream)?.ok_or("agent closed the connection")?;
    match reply.split_first() {
        Some((&wire::SSH_AGENT_SUCCESS, mut rest)) => {
            println!("{}", String::decode(&mut rest)?);
        }
        Some((&kind, _)) => println!("agent refused (message type {kind})"),
        None => println!("empty reply"),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve", socket] => {
            let (listener, _guard) = bind_socket(Path::new(socket))?;
            let agent = Agent::new().with_extension(Status {
                started: Instant::now(),
                asked: AtomicU64::new(0),
            });
            serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
        }
        ["ask", socket] => ask(Path::new(socket))?,
        _ => {
            eprintln!("usage: extension-agent serve SOCKET | ask SOCKET");
            std::process::exit(2);
        }
    }
    Ok(())
}
