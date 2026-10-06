//! Serving an agent: the accept loop, per-connection framing, and the
//! owner-only unix socket.
//!
//! [`serve`] runs any [`Handler`] (usually an [`Agent`]) over
//! any [`Listener`]. A unix socket is the usual transport, with
//! [`bind_socket`] creating it safely; another (a named pipe, a vsock, an
//! in-process pair for tests) needs only the two small traits.

use crate::agent::Agent;
use crate::destination::Connection;
use crate::wire;
use nix::sys::stat::{Mode, umask};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

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

impl Stream for UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        UnixStream::try_clone(self)
    }

    fn set_blocking(&self) -> io::Result<()> {
        self.set_nonblocking(false)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }

    /// Whether the peer runs as this user or root, as OpenSSH's agent checks:
    /// socket permissions are the first line, this the second.
    fn peer_allowed(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let peer = nix::sys::socket::getsockopt(self, nix::sys::socket::sockopt::PeerCredentials)
            .map(|cred| cred.uid());
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let peer = nix::unistd::getpeereid(self).map(|(uid, _)| uid.as_raw());
        match peer {
            Ok(uid) => uid == nix::unistd::getuid().as_raw() || uid == 0,
            Err(e) => {
                tracing::warn!(error = %e, "cannot get peer credentials");
                false
            }
        }
    }
}

impl Listener for UnixListener {
    type Stream = UnixStream;

    fn start(&self) -> io::Result<()> {
        self.set_nonblocking(true)
    }

    fn accept(&self) -> io::Result<UnixStream> {
        UnixListener::accept(self).map(|(stream, _)| stream)
    }
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
const PURGE_INTERVAL: Duration = Duration::from_secs(1);

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
const POLL_INTERVAL: Duration = Duration::from_millis(25);

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
    let _ticker = spawn_ticker(Arc::clone(&handler));
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
struct Ticker {
    _stop: mpsc::Sender<()>,
}

/// Tick `handler` about once a second until the returned [`Ticker`] is
/// dropped. Drops keys whose `ssh-add -t` lifetime has run out even when no
/// client is talking to the agent, so their secrets do not linger. Not
/// joined: a tick still running when the server stops finishes on its own.
fn spawn_ticker<H: Handler>(handler: Arc<H>) -> Ticker {
    let (stop, stopped) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(PURGE_INTERVAL) {
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

/// Removes the socket file when dropped.
pub struct SocketGuard(PathBuf);

impl SocketGuard {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create the listening socket with owner-only permissions.
///
/// A missing directory is created owner-only. An existing one must be safe
/// from other users (see `check_socket_dir`), since whoever can rename
/// the socket can put their own in its place and receive the keys `ssh-add`
/// sends. A stale socket file is replaced; a live one, or a file that is
/// not a socket, is an error.
pub fn bind_socket(path: &Path) -> Result<(UnixListener, SocketGuard), SocketError> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|source| SocketError::Directory {
                    path: dir.to_owned(),
                    source,
                })?;
        }
        check_socket_dir(dir)?;
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() {
            return Err(SocketError::NotASocket(path.to_owned()));
        }
        match UnixStream::connect(path) {
            Ok(_) => return Err(SocketError::AlreadyRunning(path.to_owned())),
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let bind_error = |source| SocketError::Bind {
        path: path.to_owned(),
        source,
    };
    // The umask is process-wide: two binds at once could each restore the
    // other's, creating a socket others can use and leaving the process with
    // the wrong umask. Take turns, so the socket is never created open.
    let listener = {
        let _turn = UMASK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let previous = umask(Mode::from_bits_truncate(0o077));
        let bound = UnixListener::bind(path);
        umask(previous);
        bound.map_err(bind_error)?
    };
    let guard = SocketGuard(path.to_owned());
    // Other code in the process may change the umask without the lock, so
    // set the mode outright too. On failure the guard removes the socket.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(bind_error)?;
    Ok((listener, guard))
}

/// Serialises the umask change in [`bind_socket`].
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Refuse a socket directory another user controls: one owned by someone
/// other than this user or root, one others can write to without the sticky
/// bit (which keeps them from renaming our socket, as in `/tmp`), or a
/// symlink another user owns, as a pre-created `/tmp/<app>-<uid>` would be.
fn check_socket_dir(dir: &Path) -> Result<(), SocketError> {
    let refuse = |reason| SocketError::UnsafeDirectory {
        path: dir.to_owned(),
        reason,
    };
    let unreadable = |source| SocketError::Directory {
        path: dir.to_owned(),
        source,
    };
    let uid = nix::unistd::getuid().as_raw();
    let trusted = |owner: u32| owner == uid || owner == 0;
    let link = std::fs::symlink_metadata(dir).map_err(unreadable)?;
    if link.file_type().is_symlink() && !trusted(link.uid()) {
        return Err(refuse("it is a symlink owned by another user"));
    }
    let meta = std::fs::metadata(dir).map_err(unreadable)?;
    if !meta.is_dir() {
        return Err(refuse("it is not a directory"));
    }
    if !trusted(meta.uid()) {
        return Err(refuse("it is owned by another user"));
    }
    let sticky = meta.mode() & 0o1000 != 0;
    if meta.mode() & 0o022 != 0 && !sticky {
        return Err(refuse("other users can write to it"));
    }
    Ok(())
}

/// Where an agent named `app` listens by default:
/// `$XDG_RUNTIME_DIR/<app>/agent.sock`, else `$TMPDIR/<app>/agent.sock` on
/// macOS, else `/tmp/<app>-<uid>/agent.sock`.
pub fn default_socket_path(app: &str) -> PathBuf {
    runtime_dir(app).join("agent.sock")
}

/// A fresh per-process socket path for `run`-style invocations.
pub fn ephemeral_socket_path(app: &str) -> PathBuf {
    runtime_dir(app).join(format!("run-{}.sock", std::process::id()))
}

/// The private per-user directory an agent named `app` keeps its sockets in.
pub fn runtime_dir(app: &str) -> PathBuf {
    let var = |name| std::env::var_os(name).filter(|dir| !dir.is_empty());
    if let Some(dir) = var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join(app);
    }
    // macOS gives each user a private $TMPDIR, while /tmp is shared.
    if cfg!(target_os = "macos")
        && let Some(dir) = var("TMPDIR")
    {
        return PathBuf::from(dir).join(app);
    }
    PathBuf::from(format!("/tmp/{app}-{}", nix::unistd::getuid()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_guard_creates_and_removes_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.sock");
        let (listener, guard) = bind_socket(&path).unwrap();
        assert!(path.exists());
        let mode = std::fs::metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o077, 0, "socket mode {mode:o} is not owner-only");
        let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "directory mode {dir_mode:o}");
        assert!(matches!(
            bind_socket(&path),
            Err(SocketError::AlreadyRunning(_))
        ));
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        // A stale socket is replaced.
        drop(UnixListener::bind(&path).unwrap());
        let (_l, _g) = bind_socket(&path).unwrap();
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
        let path = dir.path().join("agent.sock");
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
        let mut stream = UnixStream::connect(&path).unwrap();
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
        let (listener, _guard) = bind_socket(&dir.path().join("agent.sock")).unwrap();
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

    /// Sockets bound at the same time from many threads are all owner-only,
    /// and the process umask is left as it was.
    #[test]
    fn parallel_binds_are_all_owner_only() {
        // Reading the umask means setting it: take the same turn as
        // `bind_socket`, which other tests may be running meanwhile.
        let read_umask = || {
            let _turn = UMASK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let current = umask(Mode::from_bits_truncate(0o077));
            umask(current);
            current
        };
        let dir = tempfile::tempdir().unwrap();
        let before = read_umask();
        let threads: Vec<_> = (0..32)
            .map(|i| {
                let path = dir.path().join(format!("agent-{i}.sock"));
                std::thread::spawn(move || {
                    let bound = bind_socket(&path).unwrap();
                    let mode = std::fs::metadata(&path).unwrap().mode();
                    (bound, mode)
                })
            })
            .collect();
        for thread in threads {
            let (_bound, mode) = thread.join().unwrap();
            assert_eq!(mode & 0o077, 0, "socket mode {mode:o} is not owner-only");
        }
        assert_eq!(read_umask(), before, "umask changed");
    }

    #[test]
    fn a_file_that_is_not_a_socket_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, b"private key").unwrap();
        assert!(matches!(
            bind_socket(&path),
            Err(SocketError::NotASocket(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"private key");
    }

    /// A directory others can write to, as a pre-created `/tmp/<app>-<uid>`
    /// would be, is refused rather than used or fixed up.
    #[test]
    fn a_socket_directory_others_can_write_to_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("app");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            bind_socket(&shared.join("agent.sock")),
            Err(SocketError::UnsafeDirectory { .. })
        ));
        // With the sticky bit, others cannot rename the socket away.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let (_l, _g) = bind_socket(&shared.join("agent.sock")).unwrap();
        // An existing directory's mode is left as it was.
        let mode = std::fs::metadata(&shared).unwrap().mode();
        assert_eq!(mode & 0o7777, 0o1777);
    }
}
