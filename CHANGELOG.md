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
- Re-adding an `ssh-add -s -c`/`-h` key with looser constraints lifted
  them as soon as it started, so the key signed under them while the
  provider asked for a PIN, and kept them if the add failed. They now
  change only once the add succeeds.
- `ssh-add -C -s` without `-c`/`-h`, adding certificates alone to a key
  served under constraints, replaced the key's constraints, so the key and
  its certificates signed without them. Such certificates now take the
  key's constraints, and the key keeps them.
- An `ssh-add -s` key removed while its certificates were being added, by
  its backend or by another connection's `ssh-add -e`, left them served,
  through a key no backend served and without its `-c`/`-h`. They are now
  attached before any other key change can land, and taken back if the
  backend dropped the key on its own meanwhile.
- A backend that released an `ssh-add -s -c`/`-h` key while re-serving it
  for the add took its constraints, so the key signed without them once
  added. They are now recorded again when the add succeeds.
- A key change that waited for another connection's, such as one held up
  by a PIN prompt, still ran if the agent was locked meanwhile. It is now
  refused.
- A key change asked for from a backend's or provider's callback while
  the agent committed another, on the same thread, waited on itself
  forever. It is now refused, with an error logged.
- A `Lifecycle::unlocked` hook or a `Locker` that sent an unlock while the
  agent was checking one waited on itself forever. A lock or unlock asked
  for from them is now refused instead.
- `ssh-add -x` was not ordered against an unlock's hooks, so a `locked`
  hook could run before the `unlocked` hook of the unlock it followed.
  Locks and unlocks, with their hooks, now run one at a time.
- Two right `ssh-add -X` passphrases sent at once counted the second as a
  wrong guess, which was then delayed and slowed later unlocks. It is now
  refused as the agent being unlocked. Unlock guesses still wait out the
  last failure's delay, but no lock is held while they do.
- A `Handler::tick` that waited, such as one making a key change while
  another connection's was held up by a PIN prompt, stopped `serve` from
  accepting connections until it returned. Ticks now run on a thread of
  their own. The ticker holds the handler only while it ticks, so the
  agent and its keys go with their last owner once `serve` returns.

### Changed

- Listing and signing no longer wait on key changes: they read an immutable
  snapshot of the added keys, certificates and constraints, which each
  change replaces with a changed copy. Extensions and key types are
  registered the same way, each by the name or key types it gave when
  registered, which are not asked again. Each certificate is kept with the
  key that signs for it, so a key and what was attached to it come and go
  together.
  Expired keys are dropped, and their secrets freed, by the first read or
  change after they expire.
- Key changes no longer hold their lock while looking keys up or asking
  the policy or the provider for the key. Those run first, with no lock
  held; the change then takes its turn and, if other changes landed
  meanwhile, prepares again. Only a backend's `remove`/`remove_all`, a
  provider's `add`/`remove` and the `cleared` hook run during the turn, so
  a PIN prompt in `SmartcardProvider::resolve` no longer holds up other
  connections' key changes, and `Policy::allow_manage` may change keys
  itself.

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
