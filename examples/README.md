# Examples

Each example is a small, complete agent that shows one extension point.
Run one with `cargo run --example NAME -- ARGS`, then point OpenSSH at its
socket with `SSH_AUTH_SOCK=SOCKET`.

| Example | Shows | Run |
|---|---|---|
| [`file-agent`](file-agent.rs) | The basics: hold `ssh-add FILE` keys, a `Confirm` prompt for `ssh-add -c`, and an audit `Policy` | `file-agent SOCKET` |
| [`keydir-agent`](keydir-agent.rs) | A `Backend` + `Signer`: serve the unencrypted ed25519, ECDSA and RSA keys in a directory, re-read on every listing; RSA honours the requested digest and overrides `Signer::verify` | `keydir-agent DIR SOCKET` |
| [`derived-card`](derived-card.rs) | A `SmartcardProvider` that is also a `Backend`: `ssh-add -s NAME` derives a key from a seed, honouring `ssh-add -t` with `Expiring` | `derived-card SOCKET` |
| [`policy-agent`](policy-agent.rs) | A `Policy`: allow logins and chosen `ssh-keygen -Y sign` namespaces only; refuse forwarded logins and key changes | `policy-agent SOCKET [NAMESPACE…]` |
| [`extension-agent`](extension-agent.rs) | An `Extension` that answers `status@example.com`, and a client that asks for it | `extension-agent serve SOCKET` / `ask SOCKET` |
| [`idle-agent`](idle-agent.rs) | A `Handler` wrapper that forgets keys after an idle time, and a `Lifecycle` hook that logs lock/unlock/clear | `idle-agent SOCKET SECONDS` |
| [`in-process`](in-process.rs) | A custom `Listener`: an agent served over in-memory connections, driven by raw protocol messages; checks itself | `in-process` |

Use a socket path short enough for a unix socket (about 100 bytes), in a
directory only you can write to: `bind_socket` refuses one that other users
can write to.

A quick session with one of them:

```sh
cargo run --example derived-card -- /tmp/card.sock &
export SSH_AUTH_SOCK=/tmp/card.sock
ssh-add -s github      # ssh-add asks for a PIN; this example ignores it
ssh-add -L
```

The examples print to stderr and keep running until killed. They use
`ssh-agent-kit`'s own dependencies (`ssh-encoding`, `signature`, `sha2`,
`rsa`, `rand_core`, `zeroize`). An agent of your own adds those it uses to its
`Cargo.toml`.
