//! Pageant compatibility on Windows: PuTTY, plink, WinSCP and the many
//! tools built on PuTTY's code look for Pageant rather than
//! `SSH_AUTH_SOCK`.
//!
//! Newer ones connect to a per-user named pipe, which [`pageant_pipe_name`]
//! names; serve it with [`bind_socket`](crate::bind_socket) and
//! [`serve`](crate::serve) like any other. Older ones send `WM_COPYDATA` to
//! a hidden window named "Pageant", which [`serve_pageant_window`] opens.

use crate::destination::Connection;
use crate::pipe::{Handle, Sid, current_user, user_name, wide};
use crate::server::{Handler, POLL_INTERVAL, spawn_ticker};
use crate::wire;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, c_void};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HWND, LPARAM, LRESULT, LocalFree,
    WPARAM,
};
use windows_sys::Win32::Security::Authentication::Identity::{GetUserNameExW, NameUserPrincipal};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::Cryptography::{
    CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_CROSS_PROCESS, CryptProtectMemory,
};
use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    FILE_MAP_ALL_ACCESS, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION, MapViewOfFile, OpenFileMappingA,
    UnmapViewOfFile, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
    GWLP_USERDATA, GetWindowLongPtrW, MSG, MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW,
    QS_ALLINPUT, RegisterClassW, SetWindowLongPtrW, TranslateMessage, WM_COPYDATA, WNDCLASSW,
    WS_OVERLAPPEDWINDOW,
};

/// What PuTTY's clients put in `COPYDATASTRUCT::dwData`.
const AGENT_COPYDATA_ID: usize = 0x804e50ba;

/// The largest message Pageant takes, length field included.
const AGENT_MAX_MSGLEN: usize = 262144;

/// Ask for whatever access is allowed (`winnt.h`).
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The pipe PuTTY's tools (0.75 and later) look for Pageant on:
/// `\\.\pipe\pageant.<user>.<hash>`. The hash is of "Pageant" encrypted
/// with a key Windows keeps for this user's logon session, so the name is
/// the same in every process of the session and others cannot guess it.
///
/// It must be bound with [`bind_socket`](crate::bind_socket), whose pipe
/// this user owns, as PuTTY checks.
pub fn pageant_pipe_name() -> io::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        r"\\.\pipe\pageant.{}.{}",
        principal_user_name()?,
        obfuscate("Pageant")
    )))
}

/// The user name PuTTY puts in the pipe name: the user principal name up to
/// its `@`, else the login name.
fn principal_user_name() -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s.
    if unsafe { GetUserNameExW(NameUserPrincipal, buf.as_mut_ptr(), &mut len) } {
        // On success `len` leaves out the NUL.
        let principal = String::from_utf16_lossy(&buf[..len as usize]);
        let user = principal.split('@').next().unwrap_or_default();
        if !user.is_empty() {
            return Ok(user.to_owned());
        }
    }
    user_name()
}

/// PuTTY's `capi_obfuscate_string`: `name` and a NUL, zero-padded to the
/// encryption block size, encrypted with `CryptProtectMemory` for this
/// logon session, then SHA-256 over its SSH string encoding, in hex. PuTTY
/// hashes the plain padding if encryption fails, and so does this.
fn obfuscate(name: &str) -> String {
    let block = CRYPTPROTECTMEMORY_BLOCK_SIZE as usize;
    let mut data = name.as_bytes().to_vec();
    data.resize((name.len() + 1).div_ceil(block) * block, 0);
    // SAFETY: `data` holds that many writable bytes, a multiple of the
    // block size.
    unsafe {
        CryptProtectMemory(
            data.as_mut_ptr().cast(),
            data.len() as u32,
            CRYPTPROTECTMEMORY_CROSS_PROCESS,
        )
    };
    let mut hash = Sha256::new();
    hash.update((data.len() as u32).to_be_bytes());
    hash.update(&data);
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Answer older Pageant clients until `shutdown` is set: open the hidden
/// "Pageant" window they send `WM_COPYDATA` to, and answer each request
/// with `handler`. Ticks `handler` as [`serve`](crate::serve) does.
///
/// Each request comes as a file mapping the client made; one owned by
/// another user is ignored, as Pageant does. Each request is a connection
/// of its own, with no session bindings kept.
///
/// Fails with [`io::ErrorKind::AlreadyExists`] while a Pageant window is
/// open, Pageant's own or another agent's.
pub fn serve_pageant_window<H: Handler>(
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let name = wide(OsStr::new("Pageant"));
    // SAFETY: `name` is NUL-terminated.
    if !unsafe { FindWindowW(name.as_ptr(), name.as_ptr()) }.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a Pageant window is already open",
        ));
    }
    // SAFETY: the module handle of this executable needs no freeing.
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    // SAFETY: all-zero is a valid WNDCLASSW, filled in below.
    let mut class: WNDCLASSW = unsafe { std::mem::zeroed() };
    class.lpfnWndProc = Some(window_proc);
    class.hInstance = instance;
    class.lpszClassName = name.as_ptr();
    // SAFETY: `class` is valid and its name outlives the call. The class
    // stays registered for the process, always with `window_proc`.
    if unsafe { RegisterClassW(&class) } == 0
        && unsafe { GetLastError() } != ERROR_CLASS_ALREADY_EXISTS
    {
        return Err(io::Error::last_os_error());
    }
    let answer: Answer =
        Box::new(|request: &[u8]| handler.handle_in(request, &mut Connection::default()));
    // SAFETY: the class is registered and `name` is NUL-terminated. The
    // window is never shown.
    let window = unsafe {
        CreateWindowExW(
            0,
            name.as_ptr(),
            name.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            100,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `window` is ours; `answer` outlives it, as the window is
    // destroyed below before `answer` goes. Messages reach `window_proc`
    // only while this thread pumps them, after this.
    unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, &answer as *const Answer as isize) };
    let _ticker = spawn_ticker(&handler);
    while !shutdown.load(Ordering::SeqCst) {
        // SAFETY: waits on no handles, only for messages or the timeout.
        unsafe {
            MsgWaitForMultipleObjects(
                0,
                std::ptr::null(),
                0,
                POLL_INTERVAL.as_millis() as u32,
                QS_ALLINPUT,
            )
        };
        // SAFETY: all-zero is a valid MSG.
        let mut message: MSG = unsafe { std::mem::zeroed() };
        // SAFETY: `message` is writable; peeking also delivers the
        // messages other threads send, `WM_COPYDATA` among them.
        while unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            // SAFETY: `message` was just filled in.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    // SAFETY: `window` is ours and still open.
    unsafe { DestroyWindow(window) };
    drop(answer);
    Ok(())
}

/// What the window answers each request with.
type Answer<'a> = Box<dyn Fn(&[u8]) -> Vec<u8> + 'a>;

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: the user data is null or the `Answer` `serve_pageant_window`
    // keeps alive while the window is open.
    let answer = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *const Answer).as_ref() };
    if message == WM_COPYDATA
        && let Some(answer) = answer
    {
        // SAFETY: `WM_COPYDATA` carries a valid COPYDATASTRUCT.
        let data = unsafe { &*(lparam as *const COPYDATASTRUCT) };
        // A panic must not unwind into Windows.
        let answered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            answer_copydata(data, answer)
        }));
        return match answered {
            Ok(Ok(())) => 1,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "Pageant request not answered");
                0
            }
            Err(_) => {
                tracing::error!("Pageant request panicked");
                0
            }
        };
    }
    // SAFETY: passes on the message as it came.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn refused(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Answer one `WM_COPYDATA` request, which names a file mapping holding the
/// request; the reply goes in the same mapping.
fn answer_copydata(data: &COPYDATASTRUCT, answer: &Answer) -> io::Result<()> {
    if data.dwData != AGENT_COPYDATA_ID {
        return Err(refused("not a Pageant request"));
    }
    if data.lpData.is_null() || data.cbData == 0 {
        return Err(refused("no mapping name"));
    }
    // SAFETY: the sender's `cbData` bytes at `lpData` are readable for the
    // length of the message.
    let name =
        unsafe { std::slice::from_raw_parts(data.lpData as *const u8, data.cbData as usize) };
    if name.last() != Some(&0) {
        return Err(refused("the mapping name is not NUL-terminated"));
    }
    // SAFETY: `name` is NUL-terminated; the result is checked.
    let mapping =
        Handle::checked(unsafe { OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, name.as_ptr()) })?;
    // Pageant's check: the mapping must be this user's. Old PuTTY made it
    // owned by its process's default owner, which Pageant accepts too.
    let owner = owner_of(&mapping)?;
    if owner != current_user()? && owner != process_owner()? {
        return Err(refused("the mapping belongs to another user"));
    }
    // SAFETY: `mapping` is open; the view is unmapped below.
    let view = unsafe { MapViewOfFile(mapping.0, FILE_MAP_WRITE, 0, 0, 0) };
    if view.Value.is_null() {
        return Err(io::Error::last_os_error());
    }
    let answered = answer_in_view(view.Value.cast(), answer);
    // SAFETY: `view` was mapped above.
    unsafe { UnmapViewOfFile(view) };
    answered
}

/// Read the request at `view` and write the reply over it.
fn answer_in_view(view: *mut u8, answer: &Answer) -> io::Result<()> {
    // SAFETY: all-zero is a valid MEMORY_BASIC_INFORMATION.
    let mut region: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `region` is writable and `view` is a mapped address.
    let queried = unsafe {
        VirtualQuery(
            view as *const c_void,
            &mut region,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    let size = region.RegionSize.min(AGENT_MAX_MSGLEN);
    if size < 5 {
        return Err(refused("the mapping is too small for a request"));
    }
    // SAFETY: the first `size` bytes of the view are mapped and writable.
    let shared = unsafe { std::slice::from_raw_parts_mut(view, size) };
    let len = u32::from_be_bytes(shared[..4].try_into().unwrap()) as usize;
    let reply = if len == 0 || len > size - 4 {
        wire::failure()
    } else {
        // Copied out, so the client cannot change it while it is handled,
        // and wiped after, as it may carry a private key.
        let request = zeroize::Zeroizing::new(shared[4..4 + len].to_vec());
        let reply = answer(&request);
        if reply.len() > size - 4 {
            wire::failure()
        } else {
            reply
        }
    };
    shared[..4].copy_from_slice(&(reply.len() as u32).to_be_bytes());
    shared[4..4 + reply.len()].copy_from_slice(&reply);
    Ok(())
}

/// The owner of a kernel object.
fn owner_of(object: &Handle) -> io::Result<Sid> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `object` is open; `owner` points into `descriptor`, freed
    // after it is copied.
    let got = unsafe {
        GetSecurityInfo(
            object.0,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if got != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(got as i32));
    }
    // SAFETY: `owner` is a valid SID while `descriptor` is.
    let sid = unsafe { Sid::copy(owner) };
    // SAFETY: made by `GetSecurityInfo`.
    unsafe { LocalFree(descriptor) };
    Ok(sid)
}

/// The owner of this process, which is what objects it makes are owned by
/// unless it says otherwise.
fn process_owner() -> io::Result<Sid> {
    // SAFETY: opens this process; the result is checked.
    let process =
        Handle::checked(unsafe { OpenProcess(MAXIMUM_ALLOWED, 0, GetCurrentProcessId()) })?;
    owner_of(&process)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Agent;
    use crate::pipe::SecurityDescriptor;
    use ssh_encoding::Encode;
    use ssh_key::private::Ed25519Keypair;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW;

    /// One Pageant window at a time on the desktop: tests take turns.
    static WINDOW: Mutex<()> = Mutex::new(());

    fn pageant_window() -> HWND {
        let name = wide(OsStr::new("Pageant"));
        // SAFETY: `name` is NUL-terminated.
        unsafe { FindWindowW(name.as_ptr(), name.as_ptr()) }
    }

    /// A window served on a thread, until dropped.
    struct Served {
        shutdown: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<io::Result<()>>>,
        agent: Arc<Agent>,
    }

    impl Served {
        /// `None` when another Pageant is already open, as on a desktop
        /// running PuTTY's.
        fn start() -> Option<Served> {
            if !pageant_window().is_null() {
                eprintln!("skipped: a Pageant window is already open");
                return None;
            }
            let agent = Arc::new(Agent::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let thread = {
                let agent = Arc::clone(&agent);
                let shutdown = Arc::clone(&shutdown);
                std::thread::spawn(move || serve_pageant_window(agent, shutdown))
            };
            let started = Instant::now();
            while pageant_window().is_null() {
                assert!(started.elapsed() < Duration::from_secs(5), "no window");
                std::thread::sleep(Duration::from_millis(5));
            }
            Some(Served {
                shutdown,
                thread: Some(thread),
                agent,
            })
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let joined = thread.join();
                if !std::thread::panicking() {
                    joined.unwrap().unwrap();
                }
            }
        }
    }

    /// Send what PuTTY's client sends: a mapping this user owns, holding
    /// `frame`, named in a `WM_COPYDATA` with `id`. The send's result and
    /// the reply frame left in the mapping.
    fn send(id: usize, frame: &[u8]) -> (LRESULT, Vec<u8>) {
        let security = SecurityDescriptor::private().unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        // SAFETY: plain call.
        let name = format!("PageantRequest{:08x}", unsafe { GetCurrentThreadId() });
        let wide_name = wide(OsStr::new(&name));
        // SAFETY: a page-file mapping with valid attributes and name.
        let mapping = Handle::checked(unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &attributes,
                PAGE_READWRITE,
                0,
                AGENT_MAX_MSGLEN as u32,
                wide_name.as_ptr(),
            )
        })
        .unwrap();
        // SAFETY: `mapping` is open; unmapped below.
        let view = unsafe { MapViewOfFile(mapping.0, FILE_MAP_WRITE, 0, 0, 0) };
        assert!(!view.Value.is_null());
        // SAFETY: the mapping is AGENT_MAX_MSGLEN bytes.
        let shared =
            unsafe { std::slice::from_raw_parts_mut(view.Value as *mut u8, AGENT_MAX_MSGLEN) };
        shared[..frame.len()].copy_from_slice(frame);
        let mut name = name.into_bytes();
        name.push(0);
        let data = COPYDATASTRUCT {
            dwData: id,
            cbData: name.len() as u32,
            lpData: name.as_mut_ptr().cast(),
        };
        // SAFETY: the window answers before this returns, while `data` and
        // `name` live.
        let result = unsafe {
            SendMessageW(
                pageant_window(),
                WM_COPYDATA,
                0,
                &data as *const _ as LPARAM,
            )
        };
        let len = u32::from_be_bytes(shared[..4].try_into().unwrap()) as usize;
        let reply = shared[..4 + len.min(AGENT_MAX_MSGLEN - 4)].to_vec();
        // SAFETY: mapped above.
        unsafe { UnmapViewOfFile(view) };
        (result, reply)
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        frame
    }

    /// A key added through the window is listed through it, and the agent
    /// holds it.
    #[test]
    fn the_window_answers_requests() {
        let _turn = WINDOW.lock().unwrap_or_else(|p| p.into_inner());
        let Some(served) = Served::start() else {
            return;
        };
        let pair = Ed25519Keypair::from_seed(&[0x33; 32]);
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519".encode(&mut add).unwrap();
        pair.encode(&mut add).unwrap();
        "putty@example.com".encode(&mut add).unwrap();
        let (result, reply) = send(AGENT_COPYDATA_ID, &frame(&add));
        assert_eq!(result, 1);
        assert_eq!(reply, frame(&wire::success()));

        let (result, reply) = send(
            AGENT_COPYDATA_ID,
            &frame(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
        );
        assert_eq!(result, 1);
        assert_eq!(reply[4], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(reply[5..9], 1u32.to_be_bytes());
        assert_eq!(served.agent.public_keys().len(), 1);
    }

    /// A length beyond the mapping gets a failure without being handled,
    /// and a message that is not Pageant's is not answered.
    #[test]
    fn bad_requests_are_refused() {
        let _turn = WINDOW.lock().unwrap_or_else(|p| p.into_inner());
        let Some(_served) = Served::start() else {
            return;
        };
        let (result, reply) = send(AGENT_COPYDATA_ID, &u32::MAX.to_be_bytes());
        assert_eq!(result, 1);
        assert_eq!(reply, frame(&wire::failure()));
        let (result, _) = send(0x1234, &frame(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]));
        assert_eq!(result, 0);
    }

    #[test]
    fn a_second_window_is_refused() {
        let _turn = WINDOW.lock().unwrap_or_else(|p| p.into_inner());
        let Some(_served) = Served::start() else {
            return;
        };
        let second = serve_pageant_window(Arc::new(Agent::new()), Arc::new(AtomicBool::new(true)));
        assert_eq!(second.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }

    /// The pipe name has PuTTY's shape and is the same each time, as
    /// PuTTY's clients need it to be.
    #[test]
    fn the_pipe_name_is_stable() {
        let name = pageant_pipe_name().unwrap();
        let name = name.to_str().unwrap();
        let rest = name.strip_prefix(r"\\.\pipe\pageant.").unwrap();
        let (user, hash) = rest.rsplit_once('.').unwrap();
        assert!(!user.is_empty());
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(pageant_pipe_name().unwrap().to_str(), Some(name));
    }
}
