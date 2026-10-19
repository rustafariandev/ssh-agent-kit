//! The kit's agent driven by OpenSSH's own tools over a real socket, or on
//! Windows a named pipe and Win32-OpenSSH's tools.

use ssh_agent_kit::{Agent, ClientStream, bind_socket, connect, serve, wire};
use ssh_encoding::Encode;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

/// The OpenSSH tool `name`. On Windows, Win32-OpenSSH's (from
/// `$SSH_AGENT_KIT_OPENSSH`, else where Windows installs it), not whatever
/// comes first on `PATH`: the `ssh-add` Git for Windows bundles cannot
/// reach an agent on a named pipe.
fn tool(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let dir = std::env::var_os("SSH_AGENT_KIT_OPENSSH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
                Path::new(&root).join(r"System32\OpenSSH")
            });
        let exe = dir.join(format!("{name}.exe"));
        if exe.exists() {
            return exe;
        }
    }
    PathBuf::from(name)
}

fn have(name: &str) -> bool {
    let found = Command::new(tool(name))
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    // Windows CI must not pass by skipping everything.
    if !found && cfg!(windows) && std::env::var_os("CI").is_some() {
        panic!("{name} not found");
    }
    found
}

/// Where a test agent listens: `agent.sock` in `dir`, or on Windows a pipe
/// name no other test uses.
fn socket_in(dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = dir;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        PathBuf::from(format!(
            r"\\.\pipe\ssh-agent-kit-openssh-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[cfg(unix)]
    dir.join("agent.sock")
}

/// An askpass program in `dir` that answers `passphrase`: a shell script, or
/// on Windows a batch file.
fn askpass_program(dir: &Path, passphrase: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let script = dir.join("askpass.cmd");
        std::fs::write(&script, format!("@echo {passphrase}\r\n")).unwrap();
        script
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("askpass.sh");
        std::fs::write(&script, format!("#!/bin/sh\necho '{passphrase}'\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }
}

/// An agent serving on a socket in a temporary directory.
struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    shutdown: Arc<AtomicBool>,
    server: Option<JoinHandle<std::io::Result<()>>>,
}

impl Harness {
    fn start(agent: Agent) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_in(dir.path());
        let (listener, guard) = bind_socket(&socket).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                let _guard = guard;
                serve(listener, Arc::new(agent), shutdown)
            })
        };
        Harness {
            dir,
            socket,
            shutdown,
            server: Some(server),
        }
    }

    /// Run `tool` against this agent only: `SSH_AUTH_SOCK` is always set,
    /// so the user's own agent is never touched.
    fn run(&self, program: &str, args: &[&str]) -> Output {
        Command::new(tool(program))
            .args(args)
            .env("SSH_AUTH_SOCK", &self.socket)
            .env_remove("SSH_AGENT_PID")
            .env_remove("DISPLAY")
            .env_remove("SSH_ASKPASS")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `program` pointed at this agent, for tests that set more up.
    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(tool(program));
        c.env("SSH_AUTH_SOCK", &self.socket)
            .env_remove("SSH_AGENT_PID");
        c
    }

    fn keygen(&self, name: &str, kind: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        let out = Command::new(tool("ssh-keygen"))
            .args(["-q", "-t", kind, "-N", "", "-C", name, "-f"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        path
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().unwrap().unwrap();
        }
    }
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// `ssh-add` loads keys, `ssh-add -l` lists them, `ssh-keygen -Y sign`
/// signs through the agent and the signature verifies; `-d`, `-x`/`-X` and
/// `-D` behave as with OpenSSH's agent.
#[test]
fn openssh_tools_drive_the_agent() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let agent = Harness::start(Agent::new());
    let ed25519 = agent.keygen("ed25519-key", "ed25519");
    let ecdsa = agent.keygen("ecdsa-key", "ecdsa");

    for key in [&ed25519, &ecdsa] {
        let out = agent.run("ssh-add", &[text(key)]);
        assert!(out.status.success(), "{out:?}");
    }
    let out = agent.run("ssh-add", &["-l"]);
    let listing = String::from_utf8(out.stdout).unwrap();
    assert!(listing.contains("ed25519-key (ED25519)"), "{listing}");
    assert!(listing.contains("ecdsa-key (ECDSA)"), "{listing}");

    // Sign a file with the agent's key, given only the public half.
    let message = agent.dir.path().join("message");
    std::fs::write(&message, b"hello").unwrap();
    let public = format!("{}.pub", text(&ed25519));
    let out = agent.run(
        "ssh-keygen",
        &["-Y", "sign", "-n", "file", "-f", &public, text(&message)],
    );
    assert!(out.status.success(), "{out:?}");
    let signers = agent.dir.path().join("allowed_signers");
    let line = std::fs::read_to_string(&public).unwrap();
    std::fs::write(&signers, format!("ferris {line}")).unwrap();
    let out = Command::new(tool("ssh-keygen"))
        .args(["-Y", "verify", "-n", "file", "-I", "ferris", "-f"])
        .arg(&signers)
        .args(["-s", &format!("{}.sig", text(&message))])
        .stdin(std::fs::File::open(&message).unwrap())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    let out = agent.run("ssh-add", &["-d", text(&ecdsa)]);
    assert!(out.status.success(), "{out:?}");
    let out = agent.run("ssh-add", &["-L"]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 1);

    // Locked: nothing listed until unlocked. ssh-add reads the passphrase
    // from SSH_ASKPASS when there is no terminal.
    let askpass = askpass_program(agent.dir.path(), "hunter2");
    let with_askpass = |args: &[&str]| {
        Command::new(tool("ssh-add"))
            .args(args)
            .env("SSH_AUTH_SOCK", &agent.socket)
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    assert!(with_askpass(&["-x"]).status.success());
    assert!(!agent.run("ssh-add", &["-l"]).status.success());
    assert!(with_askpass(&["-X"]).status.success());
    assert!(agent.run("ssh-add", &["-l"]).status.success());

    let out = agent.run("ssh-add", &["-D"]);
    assert!(out.status.success(), "{out:?}");
    assert!(!agent.run("ssh-add", &["-l"]).status.success());
}

fn listed_keys(h: &Harness) -> usize {
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
        .count()
}

/// Run `ssh-add FILE`, loading a plain private key from disk.
fn ssh_add_file(h: &Harness, path: &Path) -> bool {
    h.cmd("ssh-add")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// An agent started with no identities serves no keys, and `ssh-add FILE`
/// populates it, exactly as a bare `ssh-agent` starts and is filled.
#[test]
fn empty_agent_starts_keyless_and_accepts_added_keys() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Agent::new());
    assert_eq!(listed_keys(&h), 0, "a keyless agent lists no keys");
    // As OpenSSH's ssh-add does for an empty agent: a message, no key lines.
    let empty = h.cmd("ssh-add").arg("-L").output().unwrap();
    assert!(!empty.status.success());
    assert!(!empty.stdout.starts_with(b"ssh-") && !empty.stdout.starts_with(b"ecdsa-"));

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let generated = Command::new(tool("ssh-keygen"))
        .args(["-t", "ed25519", "-N", "", "-C", "keyless@example.com", "-f"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success(), "ssh-keygen failed");

    assert!(ssh_add_file(&h, &key_path));
    assert_eq!(listed_keys(&h), 1);
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("keyless@example.com"))
        .expect("added key is listed");
    sign_and_check(&h, dir.path(), line, "keyless-ed25519");

    assert!(h.cmd("ssh-add").arg("-D").status().unwrap().success());
    assert_eq!(listed_keys(&h), 0);
}

/// `ssh-add FILE` loads a plain RSA key too, signing in software with the
/// digest the client asks for (`rsa-sha2-512` for `ssh-keygen -Y sign`).
/// 1024 bits, the smallest OpenSSH accepts, signs as well as 2048.
#[test]
fn ssh_add_loads_a_regular_rsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Agent::new());
    let dir = tempfile::tempdir().unwrap();
    for bits in ["1024", "2048"] {
        let name = format!("regular-rsa{bits}");
        let comment = format!("{name}@example.com");
        let key_path = dir.path().join(&name);
        let generated = Command::new(tool("ssh-keygen"))
            .args(["-t", "rsa", "-b", bits, "-N", "", "-C", &comment, "-f"])
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(generated.success(), "ssh-keygen failed");

        assert!(ssh_add_file(&h, &key_path));
        assert_eq!(listed_keys(&h), 1);

        // The added key really signs.
        let out = h.cmd("ssh-add").arg("-L").output().unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let line = text
            .lines()
            .find(|l| l.ends_with(&comment))
            .expect("added key is listed");
        assert!(line.starts_with("ssh-rsa "), "{line}");
        sign_and_check(&h, dir.path(), line, &name);

        // `ssh-add -d FILE` removes just that key.
        assert!(
            h.cmd("ssh-add")
                .arg("-d")
                .arg(&key_path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(listed_keys(&h), 0);
    }
}

/// `ssh-add FILE` loads a plain ECDSA key on any NIST curve, signing in
/// software with the curve's own digest.
#[test]
fn ssh_add_loads_a_regular_ecdsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    for (bits, name) in [(256, "nistp256"), (384, "nistp384"), (521, "nistp521")] {
        let h = Harness::start(Agent::new());
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(format!("id_ecdsa_{bits}"));
        let comment = format!("regular-{name}@example.com");
        let generated = Command::new(tool("ssh-keygen"))
            .args([
                "-t",
                "ecdsa",
                "-b",
                &bits.to_string(),
                "-N",
                "",
                "-C",
                &comment,
                "-f",
            ])
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(generated.success(), "ssh-keygen failed for {name}");

        assert!(ssh_add_file(&h, &key_path), "{name}");

        let out = h.cmd("ssh-add").arg("-L").output().unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let line = text
            .lines()
            .find(|l| l.ends_with(&comment))
            .unwrap_or_else(|| panic!("{name} key is listed: {text}"));
        assert!(line.starts_with(&format!("ecdsa-sha2-{name} ")), "{line}");
        sign_and_check(&h, dir.path(), line, name);

        assert!(
            h.cmd("ssh-add")
                .arg("-d")
                .arg(&key_path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(listed_keys(&h), 0, "{name}");
    }
}

/// `ssh-add FILE` loads a plain DSA key where OpenSSH still supports DSA.
/// Since OpenSSH 9.8 `ssh-dss` is compiled out by default, so this skips on
/// modern builds; the agent path is covered by unit tests either way. Only
/// built with the `dsa` feature, without which the agent refuses DSA keys.
#[cfg(feature = "dsa")]
#[test]
fn ssh_add_loads_a_regular_dsa_key() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Agent::new());
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_dsa");
    let generated = Command::new(tool("ssh-keygen"))
        .args(["-t", "dsa", "-N", "", "-C", "regular-dsa@example.com", "-f"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if !generated.success() {
        eprintln!("ssh-keygen has no DSA support; skipping");
        return;
    }

    assert!(ssh_add_file(&h, &key_path));
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.ends_with("regular-dsa@example.com"))
        .expect("added key is listed");
    assert!(line.starts_with("ssh-dss "), "{line}");
    sign_and_check(&h, dir.path(), line, "regular-dsa");
}

fn sign_and_check(h: &Harness, dir: &Path, pub_line: &str, name: &str) {
    let pub_path = dir.join(format!("{name}.pub"));
    std::fs::write(&pub_path, format!("{pub_line}\n")).unwrap();
    let msg_path = dir.join(format!("{name}.msg"));
    std::fs::write(&msg_path, b"the quick brown fox\n").unwrap();

    let status = h
        .cmd("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", "kit-test", "-f"])
        .arg(&pub_path)
        .arg(&msg_path)
        .status()
        .unwrap();
    assert!(status.success(), "ssh-keygen -Y sign failed for {name}");
    let sig_path = dir.join(format!("{name}.msg.sig"));
    assert!(sig_path.exists());

    let mut check = Command::new(tool("ssh-keygen"))
        .args(["-Y", "check-novalidate", "-n", "kit-test", "-f"])
        .arg(&pub_path)
        .arg("-s")
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    check
        .stdin
        .take()
        .unwrap()
        .write_all(b"the quick brown fox\n")
        .unwrap();
    let out = check.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "signature check failed for {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn roundtrip(socket: &Path, body: &[u8]) -> Vec<u8> {
    let mut stream = connect(socket).unwrap();
    wire::write_frame(&mut stream, body).unwrap();
    wire::read_frame(&mut stream).unwrap().unwrap()
}

#[test]
fn unsupported_and_unknown_key_requests_get_failure_and_keep_connection() {
    let h = Harness::start(Agent::new());
    // An add-identity with an empty key type is refused; extensions and the
    // SSH v1 listing get the replies OpenSSH's own agent gives.
    assert_eq!(
        roundtrip(&h.socket, &[17, 0, 0, 0, 0]),
        vec![wire::SSH_AGENT_FAILURE]
    );
    assert_eq!(
        roundtrip(&h.socket, &[wire::SSH_AGENTC_EXTENSION, 0, 0, 0, 0]),
        vec![wire::SSH_AGENT_EXTENSION_FAILURE]
    );
    assert_eq!(
        roundtrip(&h.socket, &[wire::SSH_AGENTC_REQUEST_RSA_IDENTITIES]),
        vec![wire::SSH_AGENT_RSA_IDENTITIES_ANSWER, 0, 0, 0, 0]
    );
    let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
    b"not a key".as_slice().encode(&mut body).unwrap();
    b"data".as_slice().encode(&mut body).unwrap();
    0u32.encode(&mut body).unwrap();
    // Two requests on one connection: failure must not close it.
    let mut stream = connect(&h.socket).unwrap();
    wire::write_frame(&mut stream, &body).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_FAILURE]
    );
    wire::write_frame(&mut stream, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let reply = wire::read_frame(&mut stream).unwrap().unwrap();
    assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
}

/// Sign `pub_path` (a public key file) as user certificate `name-cert.pub`
/// with a CA in `dir`, made on first use, valid for `validity`
/// (`ssh-keygen -V`; `always:forever` is what ssh-keygen writes without
/// `-V`). Returns the certificate line.
fn certify_valid(dir: &Path, pub_path: &Path, validity: &str) -> String {
    let ca = dir.join("ca");
    if !ca.exists() {
        let made = Command::new(tool("ssh-keygen"))
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f"])
            .arg(&ca)
            .status()
            .unwrap();
        assert!(made.success(), "ssh-keygen (CA) failed");
    }
    let signed = Command::new(tool("ssh-keygen"))
        .args(["-q", "-s"])
        .arg(&ca)
        .args(["-I", "kit-test", "-n", "ferris", "-V", validity])
        .arg(pub_path)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success(), "ssh-keygen -s failed");
    let stem = pub_path.to_str().unwrap().strip_suffix(".pub").unwrap();
    std::fs::read_to_string(format!("{stem}-cert.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

fn listing(h: &Harness) -> Vec<String> {
    let out = h.cmd("ssh-add").arg("-L").output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
        .map(str::to_owned)
        .collect()
}

/// `ssh-add FILE` sends the key's `-cert.pub` too: the certificate is listed
/// as an identity of its own and signs with the key, for each key type (each
/// leaves different public fields out of the add). `-C` loads only the
/// certificate, and `-d` removes both.
#[test]
fn ssh_add_loads_a_key_with_its_certificate() {
    if !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let h = Harness::start(Agent::new());
    let dir = tempfile::tempdir().unwrap();
    for (kind, bits, validity) in [
        ("ed25519", None, "always:forever"),
        ("rsa", Some("2048"), "-5m:+1h"),
        ("ecdsa", Some("384"), "-5m:+1h"),
    ] {
        let key_path = dir.path().join(format!("id_{kind}"));
        let mut keygen = Command::new(tool("ssh-keygen"));
        keygen.args(["-q", "-t", kind, "-N", "", "-C", "cert@example.com"]);
        if let Some(bits) = bits {
            keygen.args(["-b", bits]);
        }
        assert!(keygen.arg("-f").arg(&key_path).status().unwrap().success());
        let cert_line = certify_valid(dir.path(), &key_path.with_extension("pub"), validity);

        assert!(ssh_add_file(&h, &key_path), "ssh-add {kind} key and cert");
        let lines = listing(&h);
        assert_eq!(lines.len(), 2, "{kind}: {lines:?}");
        let listed_cert = lines
            .iter()
            .find(|l| l.contains("-cert-v01@openssh.com "))
            .expect("certificate is listed");
        assert_eq!(
            listed_cert.split_whitespace().nth(1),
            cert_line.split_whitespace().nth(1),
            "{kind}: listed unchanged"
        );
        sign_and_check(&h, dir.path(), &cert_line, &format!("{kind}-cert"));

        assert!(
            h.cmd("ssh-add")
                .arg("-d")
                .arg(&key_path)
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(listed_keys(&h), 0, "{kind}: -d removes key and cert");

        // ssh-add exits 1 after `-C` even with OpenSSH's agent, since the
        // plain key it skipped counts as not added; the listing tells.
        let out = h
            .cmd("ssh-add")
            .arg("-C")
            .arg(&key_path)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        // Older ssh-add, such as Windows' 9.5, has no `-C`.
        if String::from_utf8_lossy(&out.stderr).contains("unknown option") {
            eprintln!("ssh-add has no -C; skipping that part");
            continue;
        }
        let lines = listing(&h);
        assert_eq!(lines.len(), 1, "{kind}: {lines:?}");
        assert!(lines[0].contains("-cert-v01@openssh.com "));
        assert!(h.cmd("ssh-add").arg("-D").status().unwrap().success());
    }
}

/// A real OpenSSH `ssh-agent` on a private socket, so the same commands can be
/// run against it and against the kit's agent and the observable results compared.
///
/// Unix only: Windows' `ssh-agent` runs as a service on its one pipe, and
/// cannot be started as a user on another.
#[cfg(unix)]
struct ReferenceAgent {
    socket: std::path::PathBuf,
    child: std::process::Child,
    _dir: tempfile::TempDir,
}

#[cfg(unix)]
impl ReferenceAgent {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new(tool("ssh-agent"))
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ssh-agent");
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        ReferenceAgent {
            socket,
            child,
            _dir: dir,
        }
    }

    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(tool(program));
        c.env("SSH_AUTH_SOCK", &self.socket);
        c
    }
}

#[cfg(unix)]
impl Drop for ReferenceAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run `ssh-add` with `flag` against `cmd`'s agent, answering the prompt with
/// `passphrase` through SSH_ASKPASS. Returns whether it succeeded.
#[cfg(unix)]
fn askpass(cmd: &mut Command, dir: &Path, flag: &str, passphrase: &str) -> bool {
    let script = askpass_program(dir, passphrase);
    cmd.arg(flag)
        .env("SSH_ASKPASS", &script)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Run `ssh-add -l` against either agent, returning its exit status and stdout.
#[cfg(unix)]
fn list_output(mut cmd: Command) -> (bool, String) {
    let out = cmd.arg("-l").output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

/// The same commands must produce the same observable results from the kit's agent as
/// from a real OpenSSH `ssh-agent`: an empty list, loading a plain key,
/// listing it, removing it, clearing everything and locking the agent.
#[test]
#[cfg(unix)]
fn matches_openssh_agent_for_common_operations() {
    if !have("ssh-agent") || !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let reference = ReferenceAgent::start();
    let ours = Harness::start(Agent::new());

    let empty_ref = list_output(reference.cmd("ssh-add"));
    let empty_ours = list_output(ours.cmd("ssh-add"));
    assert_eq!(empty_ref, empty_ours);

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let generated = Command::new(tool("ssh-keygen"))
        .args(["-t", "ed25519", "-N", "", "-C", "diff@example.com", "-f"])
        .arg(&key_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success(), "ssh-keygen failed");

    let added_ref = ssh_add_file_cmd(reference.cmd("ssh-add"), &key_path);
    let added_ours = ssh_add_file(&ours, &key_path);
    assert!(added_ref && added_ours, "both agents load the key");

    let list_ref = list_output(reference.cmd("ssh-add"));
    let list_ours = list_output(ours.cmd("ssh-add"));
    assert_eq!(list_ref, list_ours, "listings match after loading a key");

    let sign_ref = signing_lines(reference.cmd("ssh-add"));
    let sign_ours = signing_lines(ours.cmd("ssh-add"));
    assert_eq!(sign_ref, sign_ours, "authorized_keys lines match");

    let removed_ref = ssh_add_file_cmd(reference.cmd("ssh-add"), &key_path);
    let removed_ours = ssh_add_file(&ours, &key_path);
    assert!(removed_ref && removed_ours);
    assert_eq!(
        list_output(reference.cmd("ssh-add")),
        list_output(ours.cmd("ssh-add")),
        "listings match after removal",
    );

    // Lock and unlock with a passphrase; both agents must agree on each step.
    assert!(ssh_add_file_cmd(reference.cmd("ssh-add"), &key_path));
    assert!(ssh_add_file(&ours, &key_path));
    askpass(&mut reference.cmd("ssh-add"), dir.path(), "-x", "hunter2");
    askpass(&mut ours.cmd("ssh-add"), dir.path(), "-x", "hunter2");
    let locked_ref = list_output(reference.cmd("ssh-add"));
    let locked_ours = list_output(ours.cmd("ssh-add"));
    assert_eq!(locked_ref, locked_ours, "a locked agent hides its keys");
    assert!(!locked_ref.0, "a locked agent fails to list keys");

    let wrong_ref = {
        let mut c = reference.cmd("ssh-add");
        askpass(&mut c, dir.path(), "-X", "wrong")
    };
    let wrong_ours = {
        let mut c = ours.cmd("ssh-add");
        askpass(&mut c, dir.path(), "-X", "wrong")
    };
    assert_eq!(wrong_ref, wrong_ours, "a wrong passphrase fails on both");
    assert!(!wrong_ref, "a wrong passphrase does not unlock");

    let right_ref = {
        let mut c = reference.cmd("ssh-add");
        askpass(&mut c, dir.path(), "-X", "hunter2")
    };
    let right_ours = {
        let mut c = ours.cmd("ssh-add");
        askpass(&mut c, dir.path(), "-X", "hunter2")
    };
    assert_eq!(right_ref, right_ours, "the right passphrase unlocks both");
    assert!(right_ref, "the right passphrase unlocks");
    assert_eq!(
        list_output(reference.cmd("ssh-add")),
        list_output(ours.cmd("ssh-add")),
        "listings agree once unlocked",
    );

    ours.cmd("ssh-add").arg("-D").status().unwrap();
    reference.cmd("ssh-add").arg("-D").status().unwrap();
    assert_eq!(
        list_output(reference.cmd("ssh-add")),
        list_output(ours.cmd("ssh-add")),
    );
}

/// `ssh-add FILE` against a command that already names its agent.
#[cfg(unix)]
fn ssh_add_file_cmd(mut cmd: Command, path: &Path) -> bool {
    cmd.arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// The authorized_keys lines from `ssh-add -L`, which ssh-add prints itself.
#[cfg(unix)]
fn signing_lines(mut cmd: Command) -> String {
    let out = cmd.arg("-L").output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// The `restrict-destination-v00@openssh.com` constraint extension for
/// allowing a key on `to_host`, identified by `hostkey`.
fn destination_constraint(to_host: &str, hostkey: &ssh_key::PublicKey) -> Vec<u8> {
    let mut keyspec = Vec::new();
    hostkey.to_bytes().unwrap().encode(&mut keyspec).unwrap();
    keyspec.push(0);

    let mut from = Vec::new();
    "".encode(&mut from).unwrap();
    "".encode(&mut from).unwrap();
    Vec::<u8>::new().encode(&mut from).unwrap();

    let mut to = Vec::new();
    "".encode(&mut to).unwrap();
    to_host.encode(&mut to).unwrap();
    Vec::<u8>::new().encode(&mut to).unwrap();
    to.extend_from_slice(&keyspec);

    let mut one = Vec::new();
    from.encode(&mut one).unwrap();
    to.encode(&mut one).unwrap();
    Vec::<u8>::new().encode(&mut one).unwrap();

    let mut list = Vec::new();
    one.encode(&mut list).unwrap();

    let mut out = Vec::new();
    wire::SSH_AGENT_CONSTRAIN_EXTENSION
        .encode(&mut out)
        .unwrap();
    "restrict-destination-v00@openssh.com"
        .encode(&mut out)
        .unwrap();
    list.encode(&mut out).unwrap();
    out
}

/// A `publickey` userauth request over `session_id` for `user` and `keyblob`,
/// the shape a `session-bind`ed client signs.
fn userauth_request(session_id: &[u8], user: &str, keyblob: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    session_id.encode(&mut data).unwrap();
    data.push(50); // SSH2_MSG_USERAUTH_REQUEST
    user.encode(&mut data).unwrap();
    "ssh-connection".encode(&mut data).unwrap();
    "publickey".encode(&mut data).unwrap();
    data.push(1); // signature follows
    "ssh-ed25519".encode(&mut data).unwrap();
    keyblob.encode(&mut data).unwrap();
    data
}

fn sign_body(keyblob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
    keyblob.encode(&mut body).unwrap();
    data.encode(&mut body).unwrap();
    0u32.encode(&mut body).unwrap();
    body
}

fn session_bind_body(
    hostkey: &ssh_key::PublicKey,
    session_id: &[u8],
    signature: &[u8],
    forwarding: bool,
) -> Vec<u8> {
    let mut body = vec![wire::SSH_AGENTC_EXTENSION];
    "session-bind@openssh.com".encode(&mut body).unwrap();
    hostkey.to_bytes().unwrap().encode(&mut body).unwrap();
    session_id.encode(&mut body).unwrap();
    signature.encode(&mut body).unwrap();
    body.push(forwarding as u8);
    body
}

/// `query` advertises `session-bind@openssh.com`, and a valid bind is
/// accepted; an invalid one is refused and poisons the connection.
#[test]
fn session_bind_is_verified_and_query_lists_it() {
    use signature::Signer;

    let h = Harness::start(Agent::new());

    // The `query` extension answers with the supported extension names.
    let mut query = vec![wire::SSH_AGENTC_EXTENSION];
    "query".encode(&mut query).unwrap();
    let reply = roundtrip(&h.socket, &query);
    assert_eq!(reply[0], 29, "SSH_AGENT_EXTENSION_RESPONSE");
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("session-bind@openssh.com"), "{text}");

    let host = ssh_key::private::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(
            &[9; 32],
        )),
        "host",
    )
    .unwrap();
    let hostkey = host.public_key().clone();
    let session_id = b"a session identifier";
    let signature = Signer::sign(&host, session_id);
    let mut signature_bytes = Vec::new();
    signature.encode(&mut signature_bytes).unwrap();

    let mut stream = connect(&h.socket).unwrap();
    let bind = session_bind_body(&hostkey, session_id, &signature_bytes, false);
    wire::write_frame(&mut stream, &bind).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_SUCCESS]
    );
    // A connection already bound for authentication cannot be bound again,
    // as OpenSSH refuses it.
    wire::write_frame(&mut stream, &bind).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_FAILURE]
    );

    // A bad signature is refused.
    let mut bad = connect(&h.socket).unwrap();
    let tampered = session_bind_body(&hostkey, session_id, b"not a signature", false);
    wire::write_frame(&mut bad, &tampered).unwrap();
    assert_eq!(
        wire::read_frame(&mut bad).unwrap().unwrap(),
        vec![wire::SSH_AGENT_FAILURE]
    );
}

/// A key added with a destination constraint is listed locally but signs only
/// on a connection bound to the permitted host with a matching session.
#[test]
fn destination_constrained_key_signs_only_on_its_bound_host() {
    use signature::Signer;

    let h = Harness::start(Agent::new());

    let pair = ssh_key::private::Ed25519Keypair::from_seed(&[0x21; 32]);
    let public = ssh_key::PublicKey::new(
        ssh_key::public::KeyData::Ed25519(pair.public),
        "constrained@example.com",
    );
    let keyblob = public.to_bytes().unwrap();

    let host = ssh_key::private::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(
            &[9; 32],
        )),
        "host",
    )
    .unwrap();
    let hostkey = host.public_key().clone();
    let session_id = b"bound session";
    let signature = Signer::sign(&host, session_id);
    let mut signature_bytes = Vec::new();
    signature.encode(&mut signature_bytes).unwrap();

    // Add the key with a destination constraint on a fresh (local) connection.
    let mut add = vec![wire::SSH2_AGENTC_ADD_ID_CONSTRAINED];
    "ssh-ed25519".encode(&mut add).unwrap();
    pair.encode(&mut add).unwrap();
    "constrained@example.com".encode(&mut add).unwrap();
    add.extend_from_slice(&destination_constraint("example.com", &hostkey));
    assert_eq!(roundtrip(&h.socket, &add), vec![wire::SSH_AGENT_SUCCESS]);

    // It is listed while the connection is local, as for `ssh-add -L`.
    let listed = roundtrip(&h.socket, &[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
    assert_eq!(listed[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
    assert_eq!(u32::from_be_bytes(listed[1..5].try_into().unwrap()), 1);

    // Signing on an unbound connection is refused, as OpenSSH refuses it.
    let data = userauth_request(session_id, "ferris", &keyblob);
    assert_eq!(
        roundtrip(&h.socket, &sign_body(&keyblob, &data)),
        vec![wire::SSH_AGENT_FAILURE]
    );

    // On a connection bound to the permitted host, the signature is served.
    let mut stream = connect(&h.socket).unwrap();
    let bind = session_bind_body(&hostkey, session_id, &signature_bytes, false);
    wire::write_frame(&mut stream, &bind).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_SUCCESS]
    );
    wire::write_frame(&mut stream, &sign_body(&keyblob, &data)).unwrap();
    let reply = wire::read_frame(&mut stream).unwrap().unwrap();
    assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);

    // A request for a different session is refused.
    let wrong = userauth_request(b"another session", "ferris", &keyblob);
    wire::write_frame(&mut stream, &sign_body(&keyblob, &wrong)).unwrap();
    assert_eq!(
        wire::read_frame(&mut stream).unwrap().unwrap(),
        vec![wire::SSH_AGENT_FAILURE]
    );
}

/// Send one request on an open connection and read its reply.
fn exchange(stream: &mut ClientStream, body: &[u8]) -> Vec<u8> {
    wire::write_frame(stream, body).unwrap();
    wire::read_frame(stream).unwrap().unwrap()
}

/// At most 128 connections are served at once: another is closed unanswered
/// until one of them ends.
#[test]
fn connections_beyond_the_limit_are_closed() {
    let h = Harness::start(Agent::new());
    let list = [wire::SSH2_AGENTC_REQUEST_IDENTITIES];
    let mut open: Vec<ClientStream> = (0..128)
        .map(|_| {
            let mut stream = connect(&h.socket).unwrap();
            exchange(&mut stream, &list);
            stream
        })
        .collect();

    let mut extra = connect(&h.socket).unwrap();
    let _ = wire::write_frame(&mut extra, &list);
    assert!(!matches!(wire::read_frame(&mut extra), Ok(Some(_))));

    // Once one ends, a new connection is served again.
    drop(open.pop());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut stream = connect(&h.socket).unwrap();
        let _ = wire::write_frame(&mut stream, &list);
        if let Ok(Some(reply)) = wire::read_frame(&mut stream) {
            assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never served again");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// For every key type `ssh-add FILE` accepts, the kit's agent lists and serves the
/// same key as OpenSSH's own agent.
#[test]
#[cfg(unix)]
fn matches_openssh_agent_listing_for_each_key_type() {
    if !have("ssh-agent") || !have("ssh-add") || !have("ssh-keygen") {
        eprintln!("OpenSSH tools not installed; skipping");
        return;
    }
    let reference = ReferenceAgent::start();
    let ours = Harness::start(Agent::new());
    let dir = tempfile::tempdir().unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("ed25519-key", &["-t", "ed25519"]),
        ("rsa2048-key", &["-t", "rsa", "-b", "2048"]),
        ("ecdsa256-key", &["-t", "ecdsa", "-b", "256"]),
        ("ecdsa384-key", &["-t", "ecdsa", "-b", "384"]),
        ("ecdsa521-key", &["-t", "ecdsa", "-b", "521"]),
    ];
    for (name, args) in cases {
        let key_path = dir.path().join(name);
        let generated = Command::new(tool("ssh-keygen"))
            .args(*args)
            .args(["-N", "", "-C", name, "-f"])
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(generated.success(), "ssh-keygen failed for {name}");

        assert!(
            ssh_add_file_cmd(reference.cmd("ssh-add"), &key_path),
            "reference agent loads {name}"
        );
        assert!(
            ssh_add_file(&ours, &key_path),
            "the kit's agent loads {name}"
        );
        assert_eq!(
            list_output(reference.cmd("ssh-add")),
            list_output(ours.cmd("ssh-add")),
            "listings match for {name}"
        );
        assert_eq!(
            signing_lines(reference.cmd("ssh-add")),
            signing_lines(ours.cmd("ssh-add")),
            "authorized_keys lines match for {name}"
        );

        reference.cmd("ssh-add").arg("-D").status().unwrap();
        ours.cmd("ssh-add").arg("-D").status().unwrap();
    }
}
