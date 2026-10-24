//! The Cygwin transport, for the `ssh` and `ssh-add` that Git for Windows,
//! MSYS2 and Cygwin bundle. They have no unix sockets to use, and cannot
//! open a named pipe either: their runtime emulates a unix socket with a
//! loopback TCP port, named in a file at the socket's path.
//!
//! The file holds `!<socket >PORT s XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`
//! (and a NUL), and has the system attribute set. The hex words are a
//! 16-byte secret that tells clients who could read the file from anyone
//! else who finds the port. Once connected, the client sends the secret,
//! and the server checks it and sends it back. Then each sends the other
//! its credentials (pid, uid and gid, 12 bytes), and the agent protocol
//! follows.
//!
//! The file is owned by this user, and only this user and LocalSystem may
//! read it. The port is open to every local user, so a client is also
//! refused unless its process runs as this user or LocalSystem, as on the
//! named pipe.

use crate::pipe::{Handle, PeerUser, SecurityDescriptor, user_of_process, wide};
use crate::server::{Listener, Removal, SocketError, SocketGuard, Stream};
use rand_core::{OsRng, RngCore};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, GENERIC_WRITE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_SYSTEM};

/// What a Cygwin socket file starts with.
const COOKIE: &[u8] = b"!<socket >";

/// How long each side of the handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Handshakes run at once; connections beyond these are closed, so clients
/// that connect and say nothing cannot pile up threads.
const MAX_HANDSHAKES: usize = 16;

/// The secret a socket file names, as the 16 bytes sent on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Secret([u8; 16]);

impl Secret {
    fn random() -> Secret {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Secret(bytes)
    }

    /// The file holds four 32-bit words that Cygwin reads with `%x` and
    /// sends as they lie in memory: little-endian.
    fn words(&self) -> [u32; 4] {
        std::array::from_fn(|i| u32::from_le_bytes(self.0[4 * i..4 * i + 4].try_into().unwrap()))
    }

    fn from_words(words: [u32; 4]) -> Secret {
        let mut bytes = [0u8; 16];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Secret(bytes)
    }

    /// Whether `bytes` is this secret, compared in constant time.
    fn matches(&self, bytes: &[u8; 16]) -> bool {
        self.0
            .iter()
            .zip(bytes)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

/// What the socket file for `port` and `secret` holds.
fn socket_file(port: u16, secret: &Secret) -> Vec<u8> {
    let [a, b, c, d] = secret.words();
    let mut text = format!("!<socket >{port} s {a:08X}-{b:08X}-{c:08X}-{d:08X}").into_bytes();
    text.push(0);
    text
}

/// The port and secret a socket file names, or `None` if `contents` is not
/// a stream socket's.
fn parse_socket_file(contents: &[u8]) -> Option<(u16, Secret)> {
    let text = contents.strip_prefix(COOKIE)?;
    let text = text.strip_suffix(&[0]).unwrap_or(text);
    let mut fields = std::str::from_utf8(text).ok()?.split(' ');
    let port = fields.next()?.parse().ok()?;
    if fields.next()? != "s" {
        return None;
    }
    let mut words = fields.next()?.split('-');
    let mut next_word = || {
        let word = words.next()?;
        (word.len() == 8)
            .then(|| u32::from_str_radix(word, 16).ok())
            .flatten()
    };
    let secret = [next_word()?, next_word()?, next_word()?, next_word()?];
    if words.next().is_some() || fields.next().is_some() {
        return None;
    }
    Some((port, Secret::from_words(secret)))
}

/// The port and secret of the socket file at `path`. `Ok(None)` if the file
/// is not a socket file.
fn read_socket_file(path: &Path) -> io::Result<Option<(u16, Secret)>> {
    // A socket file is a line; anything much longer is something else.
    let mut contents = Vec::new();
    File::open(path)?.take(256).read_to_end(&mut contents)?;
    Ok(parse_socket_file(&contents))
}

/// Create a Cygwin-style socket at `path`, for the `ssh` and `ssh-add`
/// that Git for Windows, MSYS2 and Cygwin bundle. Point `SSH_AUTH_SOCK` at
/// it as those tools spell it: `/c/Users/me/agent.sock` in Git Bash and
/// MSYS2, `/cygdrive/c/Users/me/agent.sock` in Cygwin. Their unix socket
/// paths are limited to 108 bytes, so keep it short.
///
/// The agent listens on a loopback port that the file names, with a secret
/// only readers of the file know. The file is owned by this user and only
/// this user and LocalSystem may read it. Clients whose process runs as
/// anyone else are refused, as on the named pipe.
///
/// A missing directory is created. A stale socket file is replaced; a live
/// one is [`SocketError::AlreadyRunning`], and a file that is not a socket
/// file is [`SocketError::NotASocket`]. The [`SocketGuard`] removes the
/// file, unless another agent has replaced it since.
pub fn bind_cygwin_socket(path: &Path) -> Result<(CygwinListener, SocketGuard), SocketError> {
    let bind_error = |source| SocketError::Bind {
        path: path.to_owned(),
        source,
    };
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::create_dir_all(dir).map_err(|source| SocketError::Directory {
            path: dir.to_owned(),
            source,
        })?;
    }
    if path.exists() {
        match read_socket_file(path) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(SocketError::NotASocket(path.to_owned())),
            Err(e) => return Err(bind_error(e)),
        }
        if connect_cygwin(path).is_ok() {
            return Err(SocketError::AlreadyRunning(path.to_owned()));
        }
        std::fs::remove_file(path).map_err(bind_error)?;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(bind_error)?;
    let port = listener.local_addr().map_err(bind_error)?.port();
    let secret = Secret::random();
    let contents = socket_file(port, &secret);
    let mut file = match create_private_file(path) {
        Ok(file) => file,
        // Another agent made it since we looked.
        Err(e) if e.raw_os_error() == Some(ERROR_FILE_EXISTS as i32) => {
            return Err(SocketError::AlreadyRunning(path.to_owned()));
        }
        Err(e) => return Err(bind_error(e)),
    };
    let guard = SocketGuard {
        path: path.to_owned(),
        removal: Removal::FileHolding(contents.clone()),
    };
    // On failure the guard removes the file.
    file.write_all(&contents).map_err(bind_error)?;
    drop(file);
    let (finished, handshaken) = mpsc::channel();
    let listener = CygwinListener {
        listener,
        secret,
        handshaken: Mutex::new(handshaken),
        finished,
        handshaking: Arc::new(AtomicUsize::new(0)),
    };
    Ok((listener, guard))
}

/// A new file at `path` with the system attribute Cygwin looks for, owned
/// by this user and open to this user and LocalSystem alone.
fn create_private_file(path: &Path) -> io::Result<File> {
    let security = SecurityDescriptor::private()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str());
    // SAFETY: `name` is NUL-terminated and `attributes` points at a valid
    // descriptor; the result is checked.
    let handle = Handle::checked(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_SYSTEM,
            std::ptr::null_mut(),
        )
    })?;
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: `raw` is an open file handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(raw) })
}

/// Accepts connections on a Cygwin socket made by [`bind_cygwin_socket`].
///
/// Each client's handshake runs on a thread of its own, so a slow one does
/// not hold up the rest; [`Listener::accept`] hands over the clients that
/// have finished theirs.
pub struct CygwinListener {
    listener: TcpListener,
    secret: Secret,
    handshaken: Mutex<Receiver<CygwinStream>>,
    finished: Sender<CygwinStream>,
    handshaking: Arc<AtomicUsize>,
}

impl CygwinListener {
    /// Start the handshake of each client waiting to be accepted.
    fn take_new_clients(&self) -> io::Result<()> {
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                // A client that connected and left before we looked.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            if self.handshaking.fetch_add(1, Ordering::SeqCst) >= MAX_HANDSHAKES {
                self.handshaking.fetch_sub(1, Ordering::SeqCst);
                tracing::warn!(limit = MAX_HANDSHAKES, "too many handshakes; refused one");
                continue;
            }
            let secret = self.secret;
            let finished = self.finished.clone();
            let handshaking = Arc::clone(&self.handshaking);
            std::thread::spawn(move || {
                match accept_handshake(stream, &secret) {
                    Ok(Some(stream)) => {
                        let _ = finished.send(stream);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(error = %e, "Cygwin handshake failed"),
                }
                handshaking.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

impl Listener for CygwinListener {
    type Stream = CygwinStream;

    fn start(&self) -> io::Result<()> {
        self.listener.set_nonblocking(true)
    }

    fn accept(&self) -> io::Result<CygwinStream> {
        self.take_new_clients()?;
        match self
            .handshaken
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .try_recv()
        {
            Ok(stream) => Ok(stream),
            // `self` holds a sender, so the channel never disconnects.
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
}

/// The server's side of the handshake. `Ok(None)` for a client refused
/// for who it is or for a wrong secret.
fn accept_handshake(stream: TcpStream, secret: &Secret) -> io::Result<Option<CygwinStream>> {
    let mut stream = CygwinStream::new(stream)?;
    match stream.peer_user() {
        Ok(user) if user.is_trusted() => {}
        Ok(_) => {
            tracing::warn!("refused a connection from another user");
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot get the Cygwin client's user");
            return Ok(None);
        }
    }
    let mut sent = [0u8; 16];
    stream.read_exact(&mut sent)?;
    if !secret.matches(&sent) {
        tracing::warn!("refused a Cygwin client with the wrong secret");
        return Ok(None);
    }
    stream.write_all(&secret.0)?;
    let mut credentials = [0u8; 12];
    stream.read_exact(&mut credentials)?;
    stream.write_all(&own_credentials())?;
    stream.clear_timeouts()?;
    Ok(Some(stream))
}

/// The credentials sent in the handshake: this process's pid, with no uid
/// or gid (`-1`). Cygwin's ids are its own mapping of Windows users, which
/// OpenSSH's tools do not ask the agent for.
fn own_credentials() -> [u8; 12] {
    let mut credentials = [0xFF; 12];
    credentials[..4].copy_from_slice(&std::process::id().to_le_bytes());
    credentials
}

/// Connect to the Cygwin socket at `path` (a Windows path) and run the
/// handshake, as Git for Windows' `ssh-add` would. The agent must run as
/// this user or as LocalSystem.
pub fn connect_cygwin(path: &Path) -> io::Result<CygwinStream> {
    let (port, secret) = read_socket_file(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a Cygwin socket", path.display()),
        )
    })?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = CygwinStream::new(TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT)?)?;
    if !stream.peer_user()?.is_trusted() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is served by another user", path.display()),
        ));
    }
    stream.write_all(&secret.0)?;
    let mut echoed = [0u8; 16];
    stream.read_exact(&mut echoed)?;
    if !secret.matches(&echoed) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the agent at {} sent the wrong secret", path.display()),
        ));
    }
    stream.write_all(&own_credentials())?;
    let mut credentials = [0u8; 12];
    stream.read_exact(&mut credentials)?;
    stream.clear_timeouts()?;
    Ok(stream)
}

/// One end of a connection to a Cygwin socket, past the handshake: the
/// server end [`CygwinListener`] accepts, or the client end
/// [`connect_cygwin`] opens.
///
/// The peer's user is checked before the handshake, so
/// [`Stream::peer_allowed`] has nothing left to refuse.
pub struct CygwinStream(TcpStream);

impl CygwinStream {
    /// Wrap a fresh connection, with timeouts for the handshake.
    fn new(stream: TcpStream) -> io::Result<CygwinStream> {
        stream.set_nonblocking(false)?;
        // A frame's length and body are written apart.
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        Ok(CygwinStream(stream))
    }

    fn clear_timeouts(&self) -> io::Result<()> {
        self.0.set_read_timeout(None)?;
        self.0.set_write_timeout(None)
    }

    /// A second handle on the same connection.
    pub fn try_clone(&self) -> io::Result<CygwinStream> {
        self.0.try_clone().map(CygwinStream)
    }

    /// How long a read may wait; `None` waits for ever.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    /// How long a write may wait; `None` waits for ever.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    /// The user the process at the other end runs as.
    pub fn peer_user(&self) -> io::Result<PeerUser> {
        let (SocketAddr::V4(peer), SocketAddr::V4(local)) =
            (self.0.peer_addr()?, self.0.local_addr()?)
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not an IPv4 connection",
            ));
        };
        user_of_process(process_of_connection(peer, local)?).map(PeerUser)
    }
}

/// The process owning the TCP connection from `from` to `to`.
fn process_of_connection(from: SocketAddrV4, to: SocketAddrV4) -> io::Result<u32> {
    let mut buf: Vec<u32> = Vec::new();
    let mut len = 0u32;
    let rows = loop {
        // SAFETY: `buf` holds `len` writable bytes (none, the first time).
        let got = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match got {
            0 => break &buf[..],
            // The table grew: `len` is the size it needs now.
            ERROR_INSUFFICIENT_BUFFER => buf = vec![0; (len as usize).div_ceil(4)],
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    };
    // The table is a row count, then that many rows of six u32s.
    let count = rows.first().copied().unwrap_or(0) as usize;
    let rows = rows.get(1..).unwrap_or_default().as_chunks::<6>().0;
    let rows = rows.iter().take(count).map(
        |&[state, local_addr, local_port, remote_addr, remote_port, pid]| MIB_TCPROW_OWNER_PID {
            dwState: state,
            dwLocalAddr: local_addr,
            dwLocalPort: local_port,
            dwRemoteAddr: remote_addr,
            dwRemotePort: remote_port,
            dwOwningPid: pid,
        },
    );
    // Addresses and ports are in network order, as they lie in memory.
    let is = |addr: u32, port: u32, at: SocketAddrV4| {
        addr.to_ne_bytes() == at.ip().octets() && port as u16 == at.port().to_be()
    };
    for row in rows {
        if is(row.dwLocalAddr, row.dwLocalPort, from) && is(row.dwRemoteAddr, row.dwRemotePort, to)
        {
            return Ok(row.dwOwningPid);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no process owns the connection",
    ))
}

impl Read for CygwinStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for CygwinStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Stream for CygwinStream {
    fn try_clone(&self) -> io::Result<Self> {
        CygwinStream::try_clone(self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        CygwinStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        CygwinStream::set_write_timeout(self, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, serve, wire};
    use std::os::windows::fs::MetadataExt;
    use std::sync::atomic::AtomicBool;
    use std::thread::JoinHandle;
    use std::time::Instant;

    /// What Git for Windows' own `ssh-agent -a` writes.
    const GIT_AGENT_FILE: &[u8] = b"!<socket >65412 s B7B6841E-93BA5B6D-D3F6A6E0-495C0577\0";

    #[test]
    fn the_socket_file_reads_as_cygwin_writes_it() {
        let (port, secret) = parse_socket_file(GIT_AGENT_FILE).unwrap();
        assert_eq!(port, 65412);
        assert_eq!(
            secret.words(),
            [0xB7B6841E, 0x93BA5B6D, 0xD3F6A6E0, 0x495C0577]
        );
        assert_eq!(&secret.0[..4], &[0x1E, 0x84, 0xB6, 0xB7]);
        assert_eq!(socket_file(port, &secret), GIT_AGENT_FILE);
        let secret = Secret::random();
        assert_eq!(
            parse_socket_file(&socket_file(22, &secret)).map(|(port, read)| (port, read.0)),
            Some((22, secret.0))
        );
        for other in [
            &b"!<socket >65412 d B7B6841E-93BA5B6D-D3F6A6E0-495C0577\0"[..],
            b"!<socket >65412 s B7B6841E-93BA5B6D-D3F6A6E0\0",
            b"!<socket >65412 s B7B6841E-93BA5B6D-D3F6A6E0-495C0577-0\0",
            b"!<socket >99999 s B7B6841E-93BA5B6D-D3F6A6E0-495C0577\0",
            b"!<symlink>agent.sock\0",
            b"",
        ] {
            assert!(parse_socket_file(other).is_none(), "{other:?} parsed");
        }
    }

    /// An agent serving the socket at `path`, until dropped.
    struct Served {
        shutdown: Arc<AtomicBool>,
        server: Option<JoinHandle<io::Result<()>>>,
        _guard: SocketGuard,
    }

    impl Served {
        fn start(path: &Path) -> Served {
            let (listener, guard) = bind_cygwin_socket(path).unwrap();
            let shutdown = Arc::new(AtomicBool::new(false));
            let server = {
                let shutdown = Arc::clone(&shutdown);
                std::thread::spawn(move || serve(listener, Arc::new(Agent::new()), shutdown))
            };
            Served {
                shutdown,
                server: Some(server),
                _guard: guard,
            }
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(server) = self.server.take() {
                server.join().unwrap().unwrap();
            }
        }
    }

    fn list(stream: &mut CygwinStream) -> Vec<u8> {
        wire::write_frame(stream, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]).unwrap();
        wire::read_frame(stream).unwrap().unwrap()
    }

    /// The file is a system file holding the port and secret, owned by
    /// this user; a client that knows them is served, and the file goes
    /// with the guard.
    #[test]
    fn a_client_is_served_and_the_file_removed_after() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.sock");
        let served = Served::start(&path);
        let meta = std::fs::metadata(&path).unwrap();
        assert_ne!(meta.file_attributes() & FILE_ATTRIBUTE_SYSTEM, 0);
        assert!(read_socket_file(&path).unwrap().is_some());

        let mut client = connect_cygwin(&path).unwrap();
        assert!(client.peer_user().unwrap().is_trusted());
        assert_eq!(
            list(&mut client),
            [wire::SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
        drop(client);
        drop(served);
        assert!(!path.exists());
    }

    /// The file lets in this user and LocalSystem alone.
    #[test]
    fn the_file_is_private_to_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _served = Served::start(&path);
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout);
        let entries: Vec<_> = listing.lines().filter(|line| line.contains(":(")).collect();
        assert_eq!(entries.len(), 2, "{listing}");
        assert!(!listing.contains("(I)"), "inherited access: {listing}");
    }

    /// A client with the wrong secret is cut off before the agent answers.
    #[test]
    fn a_wrong_secret_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _served = Served::start(&path);
        let (port, secret) = read_socket_file(&path).unwrap().unwrap();
        let mut wrong = secret;
        wrong.0[0] ^= 1;
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(&wrong.0).unwrap();
        let mut reply = Vec::new();
        // Closed, or reset; either way, nothing read.
        let _ = stream.read_to_end(&mut reply);
        assert!(reply.is_empty(), "{reply:?}");
    }

    /// A live socket is not taken over, a stale one is replaced, and a file
    /// that is not a socket is left alone.
    #[test]
    fn only_a_stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let served = Served::start(&path);
        assert!(matches!(
            bind_cygwin_socket(&path),
            Err(SocketError::AlreadyRunning(_))
        ));
        drop(served);

        // One left by an agent that died: its port is closed.
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        std::fs::write(&path, socket_file(port, &Secret::random())).unwrap();
        let served = Served::start(&path);
        assert!(connect_cygwin(&path).is_ok());
        drop(served);

        let notes = dir.path().join("notes.txt");
        std::fs::write(&notes, b"not a socket").unwrap();
        assert!(matches!(
            bind_cygwin_socket(&notes),
            Err(SocketError::NotASocket(_))
        ));
        assert_eq!(std::fs::read(&notes).unwrap(), b"not a socket");
    }

    /// The guard leaves a socket file another agent has put in its place.
    #[test]
    fn the_guard_leaves_a_replaced_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (listener, guard) = bind_cygwin_socket(&path).unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let newer = socket_file(1, &Secret::random());
        std::fs::write(&path, &newer).unwrap();
        drop(guard);
        assert_eq!(std::fs::read(&path).unwrap(), newer);
    }

    /// A client that connects and says nothing holds up no one else.
    #[test]
    fn a_silent_client_does_not_hold_up_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _served = Served::start(&path);
        let (port, _) = read_socket_file(&path).unwrap().unwrap();
        let _silent = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let started = Instant::now();
        let mut client = connect_cygwin(&path).unwrap();
        assert_eq!(list(&mut client)[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        assert!(started.elapsed() < HANDSHAKE_TIMEOUT);
    }
}
