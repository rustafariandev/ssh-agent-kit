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
- an owner-only unix socket, peer uid checks and a cap on connections.

## Extension points

| To…                                            | implement                    | register with           |
|------------------------------------------------|------------------------------|-------------------------|
| serve keys from a device or service            | `Backend` + `Signer`         | `Agent::with_backend`   |
| answer `ssh-add -s`/`-e PROVIDER` (smartcards) | `SmartcardProvider`          | `Agent::with_smartcard` |
| accept new key types in `ssh-add FILE`         | `KeyDecoder` + `Signer`      | `Agent::with_key_type`  |
| ask the user about `ssh-add -c` keys           | `Confirm`                    | `Agent::with_confirm`   |
| veto or audit signatures and key changes       | `Policy`                     | `Agent::with_policy`    |
| answer `SSH_AGENTC_EXTENSION` requests         | `Extension`                  | `Agent::with_extension` |
| hear lock, unlock and `ssh-add -D`             | `Lifecycle`                  | `Agent::with_lifecycle` |
| keep the lock state elsewhere                  | `Locker`                     | `Agent::with_locker`    |
| serve over something other than a unix socket  | `Listener` + `Stream`        | `serve`                 |
| wrap the agent in your own type                | `Handler`                    | `serve`                 |

The crate is synchronous. The server runs one thread per connection, so a
backend may block (waiting for a touch, for example) without holding up
other clients. After every signature the agent checks it against the key
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

[okagent](https://github.com/rustafariandev/onlykey-rs) is a full agent built
on this crate. It serves OnlyKey hardware keys and FIDO security keys.

## Features

- `dsa`: accept `ssh-dss` keys. This is off by default, because OpenSSH
  removed DSA in 10.0.
- `test-util`: test doubles (`testing::MemoryBackend`,
  `testing::RecordingConfirm`, certificate helpers) for testing agents built
  on the crate.

## Licence

MIT
