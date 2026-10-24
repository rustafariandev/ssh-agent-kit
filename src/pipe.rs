//! The Windows transport: an owner-only named pipe, with the peer's user
//! checked. Win32-OpenSSH's `ssh`, `ssh-add` and `ssh-keygen` connect to
//! the pipe `SSH_AUTH_SOCK` names, and PuTTY's tools to the one
//! [`pageant_pipe_name`](crate::pageant_pipe_name) gives.
//!
//! The Win32 calls are all in here and in `pageant`; each `unsafe` block
//! says why it is sound.

use crate::server::{Listener, Removal, SocketError, SocketGuard, Stream};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::IntoRawHandle;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER,
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetLengthSid, GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, INFINITE, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

/// What [`bind_socket`] listens with: a named pipe.
pub type SocketListener = PipeListener;

/// The prefix every local pipe name starts with.
const PIPE_PREFIX: &str = r"\\.\pipe\";

/// How long [`connect`] waits for a busy pipe, in all.
const BUSY_WAIT: Duration = Duration::from_secs(10);

/// A handle closed when dropped.
pub(crate) struct Handle(pub(crate) HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Handle {}
// SAFETY: as above; the calls made through a shared handle are thread-safe.
unsafe impl Sync for Handle {}

impl Handle {
    /// Wrap the result of a call returning a handle, null or
    /// `INVALID_HANDLE_VALUE` on failure.
    pub(crate) fn checked(handle: HANDLE) -> io::Result<Handle> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Handle(handle))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned by this value alone.
        unsafe { CloseHandle(self.0) };
    }
}

/// A fresh manual-reset event, unsignalled.
fn event() -> io::Result<Handle> {
    // SAFETY: no security attributes or name; the result is checked.
    Handle::checked(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
}

/// `s` as a NUL-terminated UTF-16 string.
pub(crate) fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// A security identifier, copied out of whatever buffer held it.
pub(crate) struct Sid(Vec<u32>);

impl Sid {
    /// Copy the SID at `sid`.
    ///
    /// # Safety
    /// `sid` must point at a valid SID.
    pub(crate) unsafe fn copy(sid: PSID) -> Sid {
        // SAFETY: the caller promises a valid SID, whose length this reads.
        let len = unsafe { GetLengthSid(sid) } as usize;
        // u32s, so the copy is aligned as a SID must be.
        let mut buf = vec![0u32; len.div_ceil(4)];
        // SAFETY: `len` bytes are readable at `sid` and writable in `buf`.
        unsafe { std::ptr::copy_nonoverlapping(sid as *const u8, buf.as_mut_ptr().cast(), len) };
        Sid(buf)
    }

    pub(crate) fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }

    /// Whether this is `sid`.
    ///
    /// # Safety
    /// `sid` must point at a valid SID.
    pub(crate) unsafe fn is(&self, sid: PSID) -> bool {
        // SAFETY: both are valid SIDs.
        unsafe { EqualSid(self.as_psid(), sid) != 0 }
    }

    /// Whether this is LocalSystem, the Windows counterpart of root.
    pub(crate) fn is_local_system(&self) -> bool {
        // SAFETY: `self` holds a valid SID.
        unsafe { IsWellKnownSid(self.as_psid(), WinLocalSystemSid) != 0 }
    }

    /// The `S-1-5-…` form, as SDDL wants it.
    fn to_string_sid(&self) -> io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `self` holds a valid SID; on success `text` is a
        // NUL-terminated string to free with `LocalFree`.
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `text` is NUL-terminated.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: `len` u16s are readable at `text`.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: `text` came from `ConvertSidToStringSidW`.
        unsafe { LocalFree(text.cast()) };
        Ok(s)
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Sid) -> bool {
        // SAFETY: `other` holds a valid SID.
        unsafe { self.is(other.as_psid()) }
    }
}

/// The user a process runs as.
pub(crate) fn process_user(process: HANDLE) -> io::Result<Sid> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a process handle; the result is checked.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut len = 0u32;
    // SAFETY: asks only for the size, into `len`.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    // SAFETY: reads the error the call above left.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    // u64s, so the TOKEN_USER the buffer holds is aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds `len` writable bytes.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer now starts with a TOKEN_USER, whose SID points
    // into the same buffer and is valid.
    Ok(unsafe { Sid::copy((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid) })
}

/// The user this process runs as.
pub(crate) fn current_user() -> io::Result<Sid> {
    // SAFETY: the pseudo-handle of this process needs no closing.
    process_user(unsafe { GetCurrentProcess() })
}

/// The user process `pid` runs as.
pub(crate) fn user_of_process(pid: u32) -> io::Result<Sid> {
    // SAFETY: the result is checked.
    let process =
        Handle::checked(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    process_user(process.0)
}

/// This user's login name, as `GetUserNameW` gives it.
pub(crate) fn user_name() -> io::Result<String> {
    let mut buf = vec![0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s.
    if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // `len` counts the NUL.
    Ok(String::from_utf16_lossy(
        &buf[..len.saturating_sub(1) as usize],
    ))
}

/// A security descriptor, freed when dropped.
pub(crate) struct SecurityDescriptor(pub(crate) PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is plain memory, read-only once made.
unsafe impl Send for SecurityDescriptor {}

impl SecurityDescriptor {
    /// One owned by this user and granting access to this user and
    /// LocalSystem alone: the Windows counterpart of mode 0600. PuTTY's
    /// clients also refuse a pipe this user does not own.
    pub(crate) fn private() -> io::Result<SecurityDescriptor> {
        let me = current_user()?.to_string_sid()?;
        let sddl = wide(OsStr::new(&format!("O:{me}D:P(A;;GA;;;{me})(A;;GA;;;SY)")));
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is to be
        // freed with `LocalFree`.
        let made = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if made == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: made by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe { LocalFree(self.0) };
    }
}

/// One instance of the pipe `name`, ready to be connected to.
fn create_instance(name: &[u16], security: &SecurityDescriptor, first: bool) -> io::Result<Handle> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let first = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    // SAFETY: `name` is NUL-terminated and `attributes` points at a valid
    // descriptor; the result is checked.
    Handle::checked(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &attributes,
        )
    })
}

/// Create the listening pipe, which only this user (and LocalSystem) may
/// open. `path` is a pipe name, `\\.\pipe\…`.
///
/// The pipe is created as its first instance, so a pipe of that name that
/// already exists, whether a live agent's or one another user made to pose
/// as ours, is [`SocketError::AlreadyRunning`].
pub fn bind_socket(path: &Path) -> Result<(SocketListener, SocketGuard), SocketError> {
    let bind_error = |source| SocketError::Bind {
        path: path.to_owned(),
        source,
    };
    let is_pipe = path
        .to_str()
        .and_then(|p| p.get(..PIPE_PREFIX.len()))
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PIPE_PREFIX))
        && path.as_os_str().len() > PIPE_PREFIX.len();
    if !is_pipe {
        return Err(bind_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            r"not a pipe name (\\.\pipe\NAME)",
        )));
    }
    let name = wide(path.as_os_str());
    let security = SecurityDescriptor::private().map_err(bind_error)?;
    let first = match create_instance(&name, &security, true) {
        Ok(pipe) => pipe,
        Err(e)
            if [ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY]
                .map(|code| code as i32)
                .contains(&e.raw_os_error().unwrap_or(0)) =>
        {
            return Err(SocketError::AlreadyRunning(path.to_owned()));
        }
        Err(e) => return Err(bind_error(e)),
    };
    let stop = Arc::new(event().map_err(bind_error)?);
    let (sender, incoming) = mpsc::channel();
    let thread = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("pipe accept".into())
            .spawn(move || accept_loop(name, security, first, &stop, sender))
            .map_err(bind_error)?
    };
    let listener = PipeListener {
        incoming: Mutex::new(incoming),
        stop,
        thread: Some(thread),
    };
    let guard = SocketGuard {
        path: path.to_owned(),
        removal: Removal::Nothing,
    };
    Ok((listener, guard))
}

/// Accepts connections on a named pipe made by [`bind_socket`].
///
/// A thread of its own waits for each client and has the next instance of
/// the pipe ready as soon as one connects, so clients seldom find it busy;
/// [`Listener::accept`] takes the connected ones without blocking.
pub struct PipeListener {
    incoming: Mutex<Receiver<io::Result<PipeStream>>>,
    stop: Arc<Handle>,
    thread: Option<JoinHandle<()>>,
}

impl Listener for PipeListener {
    type Stream = PipeStream;

    fn accept(&self) -> io::Result<PipeStream> {
        match self
            .incoming
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .try_recv()
        {
            Ok(connected) => connected,
            Err(TryRecvError::Empty) => Err(io::ErrorKind::WouldBlock.into()),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the pipe accept thread stopped",
            )),
        }
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        // SAFETY: `stop` is an open event.
        unsafe { SetEvent(self.stop.0) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Wait for a client on `pipe`. `Ok(false)` once `stop` is signalled.
fn wait_for_client(pipe: &Handle, stop: &Handle) -> io::Result<bool> {
    let connected = event()?;
    // SAFETY: all-zero is a valid OVERLAPPED.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = connected.0;
    // SAFETY: `overlapped` lives until the operation is over: it ends below,
    // or is cancelled and waited for.
    if unsafe { ConnectNamedPipe(pipe.0, &mut overlapped) } != 0 {
        return Ok(true);
    }
    // SAFETY: reads the error the call above left.
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => return Ok(true),
        ERROR_IO_PENDING => {}
        // A client that connected and left before we looked.
        ERROR_NO_DATA => {
            // SAFETY: `pipe` is an open server end.
            unsafe { DisconnectNamedPipe(pipe.0) };
            return wait_for_client(pipe, stop);
        }
        code => return Err(io::Error::from_raw_os_error(code as i32)),
    }
    let events = [connected.0, stop.0];
    // SAFETY: both handles are open events.
    let woke = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE) };
    if woke != WAIT_OBJECT_0 {
        // SAFETY: cancels the connect `overlapped` is for.
        unsafe { CancelIoEx(pipe.0, &overlapped) };
    }
    let mut ignored = 0;
    // SAFETY: waits for the connect to end, so `overlapped` is no longer in
    // use once this returns.
    let done = unsafe { GetOverlappedResult(pipe.0, &overlapped, &mut ignored, 1) };
    if woke != WAIT_OBJECT_0 {
        return Ok(false);
    }
    if done == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

/// The accept thread of a [`PipeListener`]: hand each connected instance
/// over, and make the next, until `stop` or an error, which is handed over
/// too.
fn accept_loop(
    name: Vec<u16>,
    security: SecurityDescriptor,
    first: Handle,
    stop: &Handle,
    connections: Sender<io::Result<PipeStream>>,
) {
    let mut pipe = first;
    loop {
        match wait_for_client(&pipe, stop) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => {
                // The client left as it came: start over on a fresh instance.
                match create_instance(&name, &security, false) {
                    Ok(next) => pipe = next,
                    Err(e) => {
                        let _ = connections.send(Err(e));
                        return;
                    }
                }
                continue;
            }
            Err(e) => {
                let _ = connections.send(Err(e));
                return;
            }
        }
        let next = create_instance(&name, &security, false);
        if connections
            .send(Ok(PipeStream::new(pipe, Side::Server)))
            .is_err()
        {
            return;
        }
        match next {
            Ok(next) => pipe = next,
            Err(e) => {
                let _ = connections.send(Err(e));
                return;
            }
        }
    }
}

/// Which end of a pipe a [`PipeStream`] is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Server,
    Client,
}

struct Inner {
    pipe: Handle,
    side: Side,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

/// One end of a named-pipe connection: the server end [`PipeListener`]
/// accepts, or the client end [`connect`](crate::connect) opens.
///
/// Clones share the pipe and its timeouts, as clones of a unix socket do.
/// Closing the last one leaves a reply the other end has not read yet for
/// it to read.
#[derive(Clone)]
pub struct PipeStream(Arc<Inner>);

impl PipeStream {
    fn new(pipe: Handle, side: Side) -> PipeStream {
        PipeStream(Arc::new(Inner {
            pipe,
            side,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
        }))
    }

    /// A second handle on the same connection.
    pub fn try_clone(&self) -> io::Result<PipeStream> {
        Ok(self.clone())
    }

    /// How long a read may wait; `None` waits for ever.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        check_timeout(timeout)?;
        *self
            .0
            .read_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = timeout;
        Ok(())
    }

    /// How long a write may wait for the other end to read; `None` waits
    /// for ever.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        check_timeout(timeout)?;
        *self
            .0
            .write_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = timeout;
        Ok(())
    }

    /// The user the process at the other end runs as.
    pub fn peer_user(&self) -> io::Result<PeerUser> {
        let mut pid = 0;
        // SAFETY: `pipe` is an open pipe handle; the result is checked.
        let got = unsafe {
            match self.0.side {
                Side::Server => GetNamedPipeClientProcessId(self.0.pipe.0, &mut pid),
                Side::Client => GetNamedPipeServerProcessId(self.0.pipe.0, &mut pid),
            }
        };
        if got == 0 {
            return Err(io::Error::last_os_error());
        }
        user_of_process(pid).map(PeerUser)
    }

    /// Run one overlapped read or write, `start`, waiting at most `timeout`
    /// for it.
    fn overlapped(
        &self,
        timeout: Option<Duration>,
        start: impl FnOnce(*mut OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        let done = event()?;
        // SAFETY: all-zero is a valid OVERLAPPED.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = done.0;
        // The caller's buffer and `overlapped` outlive the operation: it is
        // waited for below before either goes.
        if start(&mut overlapped) == 0 {
            // SAFETY: reads the error `start` left.
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        let wait = timeout.map_or(INFINITE, |t| {
            t.as_millis().clamp(1, u128::from(INFINITE - 1)) as u32
        });
        // SAFETY: `done` is an open event.
        let waited = unsafe { WaitForSingleObject(done.0, wait) };
        if waited == WAIT_TIMEOUT {
            // SAFETY: cancels the operation `overlapped` is for.
            unsafe { CancelIoEx(self.0.pipe.0, &overlapped) };
        }
        let mut moved = 0;
        // SAFETY: waits for the operation to end, cancelled or not.
        if unsafe { GetOverlappedResult(self.0.pipe.0, &overlapped, &mut moved, 1) } == 0 {
            // SAFETY: reads the error the call above left.
            let code = unsafe { GetLastError() };
            if waited == WAIT_TIMEOUT && code == ERROR_OPERATION_ABORTED {
                return Err(io::ErrorKind::TimedOut.into());
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(moved as usize)
    }
}

/// The user at the other end of a [`PipeStream`].
pub struct PeerUser(pub(crate) Sid);

impl PeerUser {
    /// Whether it is this user or LocalSystem: the same rule as "this uid
    /// or root" on a unix socket.
    pub fn is_trusted(&self) -> bool {
        self.0.is_local_system() || current_user().is_ok_and(|me| me == self.0)
    }
}

/// Refuse a zero timeout, as a unix socket does.
fn check_timeout(timeout: Option<Duration>) -> io::Result<()> {
    if timeout == Some(Duration::ZERO) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero timeout"));
    }
    Ok(())
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let timeout = *self
            .0
            .read_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let pipe = self.0.pipe.0;
        let read = self.overlapped(timeout, |overlapped| {
            // SAFETY: `buf` holds `len` writable bytes for the whole read.
            unsafe {
                ReadFile(
                    pipe,
                    buf.as_mut_ptr(),
                    len,
                    std::ptr::null_mut(),
                    overlapped,
                )
            }
        });
        match read {
            // The other end closed: end of stream.
            Err(e)
                if [ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED]
                    .map(|code| code as i32)
                    .contains(&e.raw_os_error().unwrap_or(0)) =>
            {
                Ok(0)
            }
            read => read,
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let timeout = *self
            .0
            .write_timeout
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let pipe = self.0.pipe.0;
        self.overlapped(timeout, |overlapped| {
            // SAFETY: `buf` holds `len` readable bytes for the whole write.
            unsafe { WriteFile(pipe, buf.as_ptr(), len, std::ptr::null_mut(), overlapped) }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream for PipeStream {
    fn try_clone(&self) -> io::Result<Self> {
        PipeStream::try_clone(self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        PipeStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        PipeStream::set_write_timeout(self, timeout)
    }

    /// Whether the peer runs as this user or LocalSystem. The pipe's
    /// security is the first line, this the second.
    fn peer_allowed(&self) -> bool {
        match self.peer_user() {
            Ok(user) => user.is_trusted(),
            Err(e) => {
                tracing::warn!(error = %e, "cannot get the pipe client's user");
                false
            }
        }
    }
}

/// Open the pipe `path` as a client: see [`connect`](crate::connect).
pub(crate) fn connect(path: &Path) -> io::Result<PipeStream> {
    let started = Instant::now();
    let file = loop {
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path);
        match opened {
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && started.elapsed() < BUSY_WAIT =>
            {
                // Every instance is taken: wait for the server to make another.
                let name = wide(path.as_os_str());
                // SAFETY: `name` is NUL-terminated.
                unsafe { WaitNamedPipeW(name.as_ptr(), 1000) };
            }
            opened => break opened?,
        }
    };
    let stream = PipeStream::new(Handle(file.into_raw_handle()), Side::Client);
    if !stream.peer_user()?.is_trusted() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is served by another user", path.display()),
        ));
    }
    Ok(stream)
}

/// The pipe an agent named `app` listens on by default:
/// `\\.\pipe\<app>-<user>`.
pub fn default_socket_path(app: &str) -> PathBuf {
    PathBuf::from(format!("{PIPE_PREFIX}{app}-{}", user_name_or_unknown()))
}

/// A fresh per-process pipe name for `run`-style invocations.
pub fn ephemeral_socket_path(app: &str) -> PathBuf {
    PathBuf::from(format!(
        "{PIPE_PREFIX}{app}-{}-run-{}",
        user_name_or_unknown(),
        std::process::id()
    ))
}

fn user_name_or_unknown() -> String {
    user_name().unwrap_or_else(|_| "user".into())
}

/// A per-user directory for an agent named `app` to keep state in:
/// `%LOCALAPPDATA%\<app>`. Pipes live in no directory, so the socket paths
/// do not use it.
pub fn runtime_dir(app: &str) -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .filter(|dir| !dir.is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join(app)
}

/// A pipe name no other test in this process, or another, uses.
#[cfg(test)]
pub(crate) fn unique_test_pipe() -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    PathBuf::from(format!(
        "{PIPE_PREFIX}ssh-agent-kit-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, serve, wire};
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, OWNER_SECURITY_INFORMATION,
    };

    /// The owner and the users the DACL of a pipe handle lets in.
    fn owner_and_allowed(handle: HANDLE) -> (Sid, Vec<Sid>) {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `handle` is open; the out-pointers point into `descriptor`.
        let got = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(got, ERROR_SUCCESS);
        // SAFETY: `owner` is valid while `descriptor` is.
        let owner_sid = unsafe { Sid::copy(owner) };
        let mut allowed = Vec::new();
        // SAFETY: `dacl` is valid while `descriptor` is, and each of its
        // AceCount entries is an access-allowed ACE (the pipe's DACL has no
        // other kind).
        unsafe {
            for i in 0..u32::from((*dacl).AceCount) {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                assert_ne!(GetAce(dacl, i, &mut ace), 0);
                let ace = ace as *const ACCESS_ALLOWED_ACE;
                assert_eq!((*ace).Header.AceType, 0, "not an access-allowed ACE");
                allowed.push(Sid::copy(std::ptr::addr_of!((*ace).SidStart) as PSID));
            }
            LocalFree(descriptor);
        }
        (owner_sid, allowed)
    }

    /// The pipe is owned by this user and lets in only this user and
    /// LocalSystem; a second agent on the name is refused.
    #[test]
    fn the_pipe_is_private_to_this_user() {
        let path = unique_test_pipe();
        let (listener, _guard) = bind_socket(&path).unwrap();
        let client = connect(&path).unwrap();
        let (owner, allowed) = owner_and_allowed(client.0.pipe.0);
        let me = current_user().unwrap();
        assert!(owner == me, "the pipe is owned by someone else");
        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&me));
        assert!(allowed.iter().any(Sid::is_local_system));
        assert!(matches!(
            bind_socket(&path),
            Err(SocketError::AlreadyRunning(_))
        ));
        drop(client);
        drop(listener);
        // Once the listener goes, so does the pipe, and the name is free.
        let (_listener, _guard) = bind_socket(&path).unwrap();
    }

    #[test]
    fn a_path_that_is_not_a_pipe_is_refused() {
        for path in [r"C:\agent.sock", r"\\.\pipe\", "agent.sock"] {
            assert!(
                matches!(bind_socket(Path::new(path)), Err(SocketError::Bind { .. })),
                "{path} was accepted"
            );
        }
    }

    /// Both ends see this process, running as this user, at the other end.
    #[test]
    fn both_ends_see_this_user() {
        let path = unique_test_pipe();
        let (listener, _guard) = bind_socket(&path).unwrap();
        let client = connect(&path).unwrap();
        let server = loop {
            match listener.accept() {
                Ok(server) => break server,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("{e}"),
            }
        };
        assert!(server.peer_allowed());
        assert!(client.peer_allowed());
    }

    /// A read with a timeout gives up when nothing comes, and the
    /// connection still works after.
    #[test]
    fn a_read_times_out_and_the_pipe_still_works() {
        let path = unique_test_pipe();
        let (listener, _guard) = bind_socket(&path).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, Arc::new(Agent::new()), shutdown))
        };
        let mut client = connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let started = Instant::now();
        let mut byte = [0u8];
        let err = client.read(&mut byte).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        wire::write_frame(&mut client, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let reply = wire::read_frame(&mut client).unwrap().unwrap();
        assert_eq!(reply, [wire::SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]);
        drop(client);
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }

    /// Many clients connecting at once all get served, waiting out a busy
    /// pipe rather than failing.
    #[test]
    fn a_burst_of_clients_is_served() {
        let path = unique_test_pipe();
        let (listener, _guard) = bind_socket(&path).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, Arc::new(Agent::new()), shutdown))
        };
        let clients: Vec<_> = (0..32)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut client = connect(&path).unwrap();
                    wire::write_frame(&mut client, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES])
                        .unwrap();
                    wire::read_frame(&mut client).unwrap().unwrap()
                })
            })
            .collect();
        for client in clients {
            assert_eq!(
                client.join().unwrap()[0],
                wire::SSH2_AGENT_IDENTITIES_ANSWER
            );
        }
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
}
