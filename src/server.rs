//! Serving an agent: the accept loop, per-connection framing, and the
//! owner-only socket.
//!
//! [`serve`] runs any [`Handler`] (usually an [`Agent`]) over
//! any [`Listener`]. The usual transport is a unix socket, or a named pipe
//! on Windows, with [`bind_socket`] creating it safely; another (a vsock,
//! an in-process pair for tests) needs only the two small traits.

use crate::agent::Agent;
use crate::destination::Connection;
use crate::wire;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(windows)]
pub use crate::pipe::{
    SocketListener, bind_socket, default_socket_path, ephemeral_socket_path, runtime_dir,
};
#[cfg(unix)]
pub use crate::unix::{
    SocketListener, bind_socket, default_socket_path, ephemeral_socket_path, runtime_dir,
};

/// Answers agent requests. [`Agent`] is the implementation; an owner that
/// wraps an agent implements this by forwarding.
pub trait Handler: Send + Sync + 'static {
    /// Handle one request body on `connection` and produce the reply body.
    fn handle_in(&self, body: &[u8], connection: &mut Connection) -> Vec<u8>;

    /// Called about once a second while serving, so time-limited state
    /// (keys added with `ssh-add -t`) is dropped even when no client talks.
    /// Runs on a thread of its own, so it may wait, such as for a key change
    /// another connection is making, without holding up the server; the
    /// next tick comes once it returns. A tick that panics is logged, and
    /// ticking goes on.
    fn tick(&self) {}
}

impl Handler for Agent {
    fn handle_in(&self, body: &[u8], connection: &mut Connection) -> Vec<u8> {
        Agent::handle_in(self, body, connection)
    }

    fn tick(&self) {
        self.purge_expired();
    }
}

/// One accepted client connection.
pub trait Stream: Read + Write + Send + Sized + 'static {
    /// A second handle for reading while this one writes.
    fn try_clone(&self) -> io::Result<Self>;

    /// Block on reads (the listener may have handed it over non-blocking).
    fn set_blocking(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Whether the peer may use the agent at all. Checked once, before the
    /// first request.
    fn peer_allowed(&self) -> bool {
        true
    }
}

/// Where clients connect.
pub trait Listener: Send {
    type Stream: Stream;

    /// Prepare to accept: [`serve`] polls [`Self::accept`], so it must not
    /// block.
    fn start(&self) -> io::Result<()> {
        Ok(())
    }

    /// The next client, or an error of kind [`io::ErrorKind::WouldBlock`]
    /// when none is waiting.
    fn accept(&self) -> io::Result<Self::Stream>;
}

/// Serve one client connection until it closes.
pub fn handle_connection<H: Handler + ?Sized, S: Stream>(handler: &H, mut stream: S) {
    let _ = stream.set_blocking();
    // A client that stops reading must not hold the thread forever.
    let _ = stream.set_write_timeout(Some(FRAME_TIMEOUT));
    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "cannot clone stream");
            return;
        }
    };
    // One connection carries the session bindings of one SSH session, so
    // keep them across the requests that arrive on it.
    let mut connection = Connection::default();
    loop {
        // A connection may sit idle between requests for as long as its SSH
        // session lasts, but once a request starts it must arrive whole.
        let _ = reader.set_read_timeout(None);
        let mut first = [0u8; 1];
        match reader.read(&mut first) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(error = %e, "connection closed");
                return;
            }
        }
        let _ = reader.set_read_timeout(Some(FRAME_TIMEOUT));
        // A request may carry a private key (`ssh-add FILE`): wipe it after.
        let body = match wire::read_frame(&mut first.as_slice().chain(&mut reader)) {
            Ok(Some(body)) => Zeroizing::new(body),
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(error = %e, "connection closed");
                return;
            }
        };
        let reply = handler.handle_in(&body, &mut connection);
        if let Err(e) = wire::write_frame(&mut stream, &reply) {
            tracing::debug!(error = %e, "cannot write reply");
            return;
        }
    }
}

/// How often [`serve`] calls [`Handler::tick`].
pub(crate) const PURGE_INTERVAL: Duration = Duration::from_secs(1);

/// How long a started request may take to arrive, and a reply to be read.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections served at once; more are closed until some end, so idle or
/// stalled clients cannot exhaust threads and memory.
const MAX_CONNECTIONS: usize = 128;

/// Counts a connection while its thread runs.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How often the accept loop looks for a new connection and for `shutdown`.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Accept connections until `shutdown` is set. Each connection runs on its
/// own thread, after its peer passes [`Stream::peer_allowed`]. The handler
/// is ticked about once a second on a thread of its own, so a tick that
/// waits, such as on a key change held up by a PIN prompt, never stops
/// connections from being accepted.
pub fn serve<L: Listener, H: Handler>(
    listener: L,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.start()?;
    let _ticker = spawn_ticker(&handler);
    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(stream) => {
                if !stream.peer_allowed() {
                    tracing::warn!("refused a connection from another user");
                    continue;
                }
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    tracing::warn!(limit = MAX_CONNECTIONS, "too many connections; refused one");
                    continue;
                }
                let slot = ConnectionSlot(Arc::clone(&active));
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let _slot = slot;
                    handle_connection(handler.as_ref(), stream)
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Stops the ticker [`spawn_ticker`] started when dropped, so it ends with
/// [`serve`] however that returns: dropping the sender wakes it at once.
pub(crate) struct Ticker {
    _stop: mpsc::Sender<()>,
}

/// Tick `handler` about once a second until the returned [`Ticker`] is
/// dropped or the handler is. Drops keys whose `ssh-add -t` lifetime has
/// run out even when no client is talking to the agent, so their secrets do
/// not linger. Not joined: a tick still running when the server stops
/// finishes on its own.
///
/// The ticker holds the handler only for the length of each tick, so once
/// [`serve`] returns and its owner drops it, the agent and its keys go even
/// though the ticker has not woken yet.
pub(crate) fn spawn_ticker<H: Handler>(handler: &Arc<H>) -> Ticker {
    let (stop, stopped) = mpsc::channel::<()>();
    let handler = Arc::downgrade(handler);
    std::thread::spawn(move || {
        while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(PURGE_INTERVAL) {
            let Some(handler) = handler.upgrade() else {
                return;
            };
            // A tick that panics once must not stop every later purge.
            let ticked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.tick()));
            if ticked.is_err() {
                tracing::error!("tick panicked; ticking on");
            }
        }
    });
    Ticker { _stop: stop }
}

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("an agent is already listening on {0}")]
    AlreadyRunning(PathBuf),
    #[error("cannot create socket directory {path}: {source}")]
    Directory { path: PathBuf, source: io::Error },
    #[error("refusing socket directory {path}: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
    #[error("refusing to replace {0}, which is not a socket")]
    NotASocket(PathBuf),
    #[error("cannot bind {path}: {source}")]
    Bind { path: PathBuf, source: io::Error },
}

/// Removes the socket file when dropped. A named pipe has no file: it goes
/// once its listener does.
pub struct SocketGuard(pub(crate) PathBuf);

impl SocketGuard {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A socket path for a test: `agent.sock` in `dir`, or on Windows a pipe
/// name no other test uses.
#[cfg(test)]
pub(crate) fn test_socket_path(dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = dir;
        crate::pipe::unique_test_pipe()
    }
    #[cfg(unix)]
    dir.join("agent.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A second agent cannot take over the socket of one that is running.
    #[test]
    fn a_live_socket_is_not_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = test_socket_path(dir.path());
        let (_listener, _guard) = bind_socket(&path).unwrap();
        assert!(matches!(
            bind_socket(&path),
            Err(SocketError::AlreadyRunning(_))
        ));
    }

    /// A tick that waits, as one making a key change waits for another
    /// connection's, does not stop the server from accepting and answering
    /// connections.
    #[test]
    fn a_waiting_tick_does_not_hold_up_connections() {
        struct StuckTick {
            ticked: Mutex<mpsc::Sender<()>>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl Handler for StuckTick {
            fn handle_in(&self, _body: &[u8], _connection: &mut Connection) -> Vec<u8> {
                wire::success()
            }
            fn tick(&self) {
                let _ = self.ticked.lock().unwrap().send(());
                let _ = self.release.lock().unwrap().recv();
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = test_socket_path(dir.path());
        let (listener, _guard) = bind_socket(&path).unwrap();
        let (ticked, tick_started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let handler = Arc::new(StuckTick {
            ticked: Mutex::new(ticked),
            release: Mutex::new(released),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, handler, shutdown))
        };

        tick_started.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut stream = crate::client::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        wire::write_frame(&mut stream, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let reply = wire::read_frame(&mut stream).unwrap();
        assert_eq!(reply, Some(wire::success()));

        release.send(()).unwrap();
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }

    /// Between ticks the ticker does not hold the handler, so the agent
    /// goes with its last owner once the server stops.
    #[test]
    fn the_ticker_holds_the_handler_only_while_ticking() {
        struct Ticks(Mutex<mpsc::Sender<()>>);
        impl Handler for Ticks {
            fn handle_in(&self, _body: &[u8], _connection: &mut Connection) -> Vec<u8> {
                wire::failure()
            }
            fn tick(&self) {
                let _ = self.0.lock().unwrap().send(());
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let (listener, _guard) = bind_socket(&test_socket_path(dir.path())).unwrap();
        let (ticked, ticks) = mpsc::channel();
        let handler = Arc::new(Ticks(Mutex::new(ticked)));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let handler = Arc::clone(&handler);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, handler, shutdown))
        };
        ticks.recv_timeout(Duration::from_secs(5)).unwrap();
        // Ours and `serve`'s, once the tick that just ran has returned.
        let started = std::time::Instant::now();
        while Arc::strong_count(&handler) != 2 && started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            Arc::strong_count(&handler),
            2,
            "the ticker kept the handler"
        );

        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        let weak = Arc::downgrade(&handler);
        drop(handler);
        assert!(weak.upgrade().is_none(), "the handler outlived its owners");
    }

    /// A tick that panics does not stop the ticks after it.
    #[test]
    fn ticks_go_on_after_one_panics() {
        struct PanicsOnce {
            panicked: AtomicBool,
            ticked: Mutex<mpsc::Sender<()>>,
        }
        impl Handler for PanicsOnce {
            fn handle_in(&self, _body: &[u8], _connection: &mut Connection) -> Vec<u8> {
                wire::failure()
            }
            fn tick(&self) {
                if !self.panicked.swap(true, Ordering::SeqCst) {
                    panic!("the first tick fails");
                }
                let _ = self.ticked.lock().unwrap().send(());
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let (listener, _guard) = bind_socket(&test_socket_path(dir.path())).unwrap();
        let (ticked, ticks) = mpsc::channel();
        let handler = Arc::new(PanicsOnce {
            panicked: AtomicBool::new(false),
            ticked: Mutex::new(ticked),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, handler, shutdown))
        };
        let next = ticks.recv_timeout(Duration::from_secs(5));
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
        assert!(next.is_ok(), "no tick after the one that panicked");
    }
}
