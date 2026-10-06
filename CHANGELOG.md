# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- An `ssh-add -c`/`-h` key could lose its constraints, and sign without
  them, when it was re-added or signed with on one connection while another
  removed it. A key and its constraints now change together in one
  snapshot, key changes run one at a time, and a sign during whose lookup
  the key's constraints change looks it up again, and is refused if they
  keep changing.
- An `ssh-add -h` key could be listed to a connection its constraint hides
  it from while another connection removed it. A listing during which
  constraints change is now taken again.
- A `KeyDecoder` that called back into the agent while decoding, for
  example to register a key type, deadlocked the request. Requests now
  decode with their own snapshot of the registry.
- An `ssh-add -c`/`-h` key that expired left its constraints behind, so the
  same key served again later was still constrained. They now go with it.
- A key added with `ssh-add` and its certificate shared one set of
  constraints, so adding one without `-c`/`-h` dropped the other's: after
  `ssh-add -c key` and `ssh-add key-cert.pub`, the key signed without
  asking. Each now keeps the constraints it was added with, as in OpenSSH.
  Keys added with `ssh-add -s` still share theirs with their certificates.
- A `Handler::tick` that waited, such as one making a key change while
  another connection's was held up by a PIN prompt, stopped `serve` from
  accepting connections until it returned. Ticks now run on a thread of
  their own.

### Changed

- Listing and signing no longer wait on key changes: they read an immutable
  snapshot of the added keys, certificates and constraints, which each
  change replaces with a changed copy. Extensions and key types are
  registered the same way. Expired keys are skipped by reads and dropped
  by the next change or by the server's once-a-second tick.
- Every `Backend` method, not only `remove` and `remove_all`, is documented
  as possibly called while key changes are taken one at a time, since a key
  change looks up and purges backend keys too.

## [0.1.0] - 2026-10-04

First release, extracted from the agent in
[onlykey-rs](https://github.com/rustafariandev/onlykey-rs).

### Added

- The OpenSSH agent protocol: listing and signing, `ssh-add FILE`, `-d`,
  `-D`, `-s`/`-e`, `-x`/`-X`, protocol extensions and the SSH v1 identities
  request.
- Key constraints: `ssh-add -t` lifetimes, with a default lifetime
  (`ssh-agent -t`); `ssh-add -c` confirmation; and `ssh-add -h` destination
  constraints, with `session-bind@openssh.com` and the `query` extension.
- OpenSSH certificates added with `ssh-add`, attached with
  `ssh-add -s PROVIDER CERT…`, or loaded from files.
- In-memory ed25519, RSA and ECDSA keys, plus DSA behind the `dsa` feature.
- Locking with a salted passphrase hash, with OpenSSH's back-off on wrong
  passphrases.
- A unix-socket server: owner-only socket and directory checks, peer uid
  checks, one thread per connection, and a connection cap.
- Extension points: `Backend` and `Signer`, `SmartcardProvider`,
  `KeyDecoder`, `Confirm`, `Policy`, `Extension`, `Lifecycle`, `Locker`, and
  `Listener`/`Stream`/`Handler`.
- A minimal agent client (`client::add_identity`).
- Test doubles behind the `test-util` feature.
- Examples, one per extension point: `file-agent`, `keydir-agent`,
  `derived-card`, `policy-agent`, `extension-agent`, `idle-agent` and
  `in-process`.

[0.1.0]: https://github.com/rustafariandev/ssh-agent-kit/releases/tag/v0.1.0
