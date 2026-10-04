//! A custom [`Handler`] and a [`Lifecycle`] hook: forget every key once the
//! agent has gone unused for a while, and log lock, unlock and clear events.
//!
//! [`serve`] drives any [`Handler`], so an agent can be wrapped to watch or
//! reshape traffic. [`Handler::tick`] runs about once a second even when no
//! client is talking, which is where the idle check lives.
//!
//! ```sh
//! cargo run --example idle-agent -- /tmp/idle.sock 30 &   # forget after 30 s idle
//! export SSH_AUTH_SOCK=/tmp/idle.sock
//! ssh-add ~/.ssh/id_ed25519
//! ssh-add -l          # still there; each request restarts the clock
//! sleep 31; ssh-add -l
//! ```

use ssh_agent_kit::wire;
use ssh_agent_kit::{Agent, Connection, Handler, Lifecycle, bind_socket, serve};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Wraps an agent, forgetting its keys after `idle` without a request.
struct IdleWipe {
    agent: Agent,
    idle: Duration,
    last_request: Mutex<Instant>,
    /// Set once the keys are wiped, so it happens once per idle spell.
    wiped: AtomicBool,
}

impl Handler for IdleWipe {
    fn handle_in(&self, body: &[u8], connection: &mut Connection) -> Vec<u8> {
        *self.last_request.lock().unwrap() = Instant::now();
        self.wiped.store(false, Ordering::Relaxed);
        self.agent.handle_in(body, connection)
    }

    fn tick(&self) {
        self.agent.purge_expired();
        let idle_for = self.last_request.lock().unwrap().elapsed();
        if idle_for >= self.idle && !self.wiped.swap(true, Ordering::Relaxed) {
            // The same request `ssh-add -D` sends. A locked agent refuses it,
            // so locked keys stay until the agent is unlocked and used.
            let reply = self.agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]);
            if reply == wire::success() {
                eprintln!("idle for {}s: keys forgotten", idle_for.as_secs());
            }
        }
    }
}

/// Logs the agent's state changes.
struct Log;

impl Lifecycle for Log {
    fn locked(&self) {
        eprintln!("agent locked");
    }

    fn unlocked(&self) {
        eprintln!("agent unlocked");
    }

    fn cleared(&self) {
        eprintln!("every identity removed");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(socket), Some(seconds)) = (args.next(), args.next()) else {
        eprintln!("usage: idle-agent SOCKET IDLE_SECONDS");
        std::process::exit(2);
    };
    let idle = Duration::from_secs(seconds.parse()?);

    let (listener, _guard) = bind_socket(Path::new(&socket))?;
    let handler = IdleWipe {
        agent: Agent::new().with_lifecycle(Arc::new(Log)),
        idle,
        last_request: Mutex::new(Instant::now()),
        wiped: AtomicBool::new(false),
    };
    serve(
        listener,
        Arc::new(handler),
        Arc::new(AtomicBool::new(false)),
    )?;
    Ok(())
}
