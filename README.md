# ssh-agent-kit

A Rust framework for building custom SSH agents.

`ssh-agent-kit` speaks the OpenSSH agent protocol, so `ssh`, `ssh-add`,
`ssh-keygen -Y sign` and `git` work with your agent unchanged. You decide
where keys come from and what is allowed. Out of the box it supports:

- keys added with `ssh-add FILE` (ed25519, RSA, ECDSA; DSA behind the `dsa`
  feature), held in memory;
- `ssh-add -t` lifetimes, `ssh-add -c` confirmation and `ssh-add -h`
  destination constraints, with `session-bind@openssh.com`;
- OpenSSH certificates, from `ssh-add`, `ssh-add -s PROVIDER CERT…` or files;
- `ssh-add -x`/`-X` locking, with OpenSSH's back-off on wrong passphrases;
- an owner-only unix socket, or named pipe on Windows, with peer user
  checks and a cap on connections;
- on Windows, Pageant's pipe and window, for PuTTY and the tools built on it,
  and a Cygwin-style socket for the `ssh` in Git for Windows, MSYS2 and
  Cygwin.

## Extension points

| To…                                            | implement                    | register with           |
|------------------------------------------------|------------------------------|-------------------------|
| serve keys from a device or service            | `Backend` + `Signer`         | `Agent::with_backend`   |
| answer `ssh-add -s`/`-e PROVIDER` (smartcards) | `SmartcardProvider`          | `Agent::with_smartcard` |
| accept new key types in `ssh-add FILE`         | `KeyDecoder` + `Signer`      | `Agent::with_key_type`  |
| ask the user about `ssh-add -c` keys           | `Confirm`                    | `Agent::with_confirm`   |
| veto or audit signatures, key changes, listing | `Policy`                     | `Agent::with_policy`    |
| answer `SSH_AGENTC_EXTENSION` requests         | `Extension`                  | `Agent::with_extension` |
| hear lock, unlock and `ssh-add -D`             | `Lifecycle`                  | `Agent::with_lifecycle` |
| keep the lock state elsewhere                  | `Locker`                     | `Agent::with_locker`    |
| serve over another transport (vsock, …)        | `Listener` + `Stream`        | `serve`                 |
| wrap the agent in your own type                | `Handler`                    | `serve`                 |

The agent never blocks on a slow key. The crate is synchronous and the
server runs one thread per connection, so a backend may block (waiting for
a touch, for example) while other clients keep listing, signing with other
keys, locking and removing keys. After every signature the agent checks it against the key
before it leaves.

## Example

```rust
use ssh_agent_kit::{Agent, Policy, SignInfo, bind_socket, default_socket_path, serve};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct Audit;

impl Policy for Audit {
    fn signed(&self, request: &SignInfo<'_>) {
        eprintln!("signed with {}", request.key.comment());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (listener, _guard) = bind_socket(&default_socket_path("my-agent"))?;
    let agent = Agent::new().with_policy(Arc::new(Audit));
    serve(listener, Arc::new(agent), Arc::new(AtomicBool::new(false)))?;
    Ok(())
}
```

`examples/file-agent.rs` is a runnable version:

```sh
cargo run --example file-agent -- /tmp/file-agent.sock &
SSH_AUTH_SOCK=/tmp/file-agent.sock ssh-add ~/.ssh/id_ed25519
```

[`examples/`](examples/README.md) has one small agent per extension point: a
key-directory backend, a smartcard provider, a signing policy, a protocol
extension, an idle-wipe handler with lifecycle hooks, and an in-process
transport.

[okagent](https://github.com/rustafariandev/onlykey-rs) is a full agent built
on this crate. It serves OnlyKey hardware keys and FIDO security keys.

## Platforms

On Linux, macOS and the BSDs the agent listens on a unix socket.
`bind_socket` creates it owner-only in a directory other users cannot
write to, and refuses connections from processes run by other users (root
excepted).

On Windows it listens on a named pipe instead. Win32-OpenSSH (the `ssh`,
`ssh-add` and `ssh-keygen` that ship with Windows) connects to the pipe
`SSH_AUTH_SOCK` names:

```powershell
cargo run --example file-agent -- \.\pipe\file-agent
$env:SSH_AUTH_SOCK = '\.\pipe\file-agent'   # in another window
ssh-add $HOME\.ssh\id_ed25519
```

The pipe is owned by you and only you and LocalSystem may open it. A
client's process must run as you or as LocalSystem. A pipe name that is
already taken, whether by a live agent or by another user posing as one,
is refused rather than shared.

PuTTY, plink, WinSCP and other tools built on PuTTY's code look for
Pageant rather than `SSH_AUTH_SOCK`, and the crate can answer them as
well. Newer ones connect to the pipe that `pageant_pipe_name()` names;
serve it like any other pipe. Older ones send `WM_COPYDATA` to a hidden
"Pageant" window, which `serve_pageant_window` opens. `file-agent` serves
all three ways.

The `ssh` and `ssh-add` that Git for Windows, MSYS2 and Cygwin bundle
cannot open a named pipe. They connect to a Cygwin-style socket: a file
naming a loopback port and a secret, which `bind_cygwin_socket` creates.
Only you and LocalSystem may read the file. Clients that don't know the
secret, or whose process runs as another user, are refused. Serve it
alongside the pipe, and point Git Bash at it with forward slashes:

```sh
export SSH_AUTH_SOCK=C:/Users/me/AppData/Local/my-agent/agent.sock
ssh-add -l
```

`file-agent` serves one in `%LOCALAPPDATA%\file-agent`. Alternatively,
point Git at Windows' OpenSSH, which uses the pipe:

```powershell
git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
```

## Features

- `dsa`: accept `ssh-dss` keys. This is off by default, because OpenSSH
  removed DSA in 10.0.
- `test-util`: test doubles (`testing::MemoryBackend`,
  `testing::RecordingConfirm`, certificate helpers) for testing agents built
  on the crate.

## Licence

MIT
