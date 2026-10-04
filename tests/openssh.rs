//! The kit's agent driven by OpenSSH's own tools over a real socket.

use ssh_agent_kit::{Agent, bind_socket, serve};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
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
        let socket = dir.path().join("agent.sock");
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
    fn run(&self, tool: &str, args: &[&str]) -> Output {
        Command::new(tool)
            .args(args)
            .env("SSH_AUTH_SOCK", &self.socket)
            .env_remove("SSH_AGENT_PID")
            .env_remove("DISPLAY")
            .env_remove("SSH_ASKPASS")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn keygen(&self, name: &str, kind: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        let out = Command::new("ssh-keygen")
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
    let out = Command::new("ssh-keygen")
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
    let askpass = agent.dir.path().join("askpass");
    std::fs::write(&askpass, "#!/bin/sh\necho hunter2\n").unwrap();
    std::fs::set_permissions(
        &askpass,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let with_askpass = |args: &[&str]| {
        Command::new("ssh-add")
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
