//! The unix transport: an owner-only unix socket in a private directory,
//! with the peer's uid checked.

use crate::server::{Listener, SocketError, SocketGuard, Stream};
use nix::sys::stat::{Mode, umask};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// What [`bind_socket`] listens with: a unix socket.
pub type SocketListener = UnixListener;

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

/// Create the listening socket with owner-only permissions.
///
/// A missing directory is created owner-only. An existing one must be safe
/// from other users (see `check_socket_dir`), since whoever can rename
/// the socket can put their own in its place and receive the keys `ssh-add`
/// sends. A stale socket file is replaced; a live one, or a file that is
/// not a socket, is an error.
///
/// On Windows the path names a pipe instead; see the crate docs.
pub fn bind_socket(path: &Path) -> Result<(SocketListener, SocketGuard), SocketError> {
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
/// macOS, else `/tmp/<app>-<uid>/agent.sock`. On Windows,
/// `\\.\pipe\<app>-<user>`.
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
