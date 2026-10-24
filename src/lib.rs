//! A framework for building custom SSH agents.
//!
//! The crate speaks the OpenSSH agent protocol (`draft-miller-ssh-agent`),
//! including key constraints (`ssh-add -t`, `-c`, `-h`), certificates,
//! `session-bind@openssh.com` and locking. An agent built on it decides where
//! keys come from and what is allowed:
//!
//! | To…                                   | implement                      | and register with              |
//! |---------------------------------------|--------------------------------|--------------------------------|
//! | serve keys from a device or service   | [`Backend`] + [`Signer`]       | [`Agent::with_backend`]        |
//! | answer `ssh-add -s`/`-e PROVIDER`     | [`SmartcardProvider`]          | [`Agent::with_smartcard`]      |
//! | accept new key types in `ssh-add FILE`| [`KeyDecoder`] + [`Signer`]    | [`Agent::with_key_type`]       |
//! | ask the user about `ssh-add -c` keys  | [`Confirm`]                    | [`Agent::with_confirm`]        |
//! | veto signatures, changes and listing  | [`Policy`]                     | [`Agent::with_policy`]         |
//! | answer `SSH_AGENTC_EXTENSION` names   | [`Extension`]                  | [`Agent::with_extension`]      |
//! | hear lock, unlock and `ssh-add -D`    | [`Lifecycle`]                  | [`Agent::with_lifecycle`]      |
//! | keep the lock elsewhere               | [`Locker`]                     | [`Agent::with_locker`]         |
//! | serve over another transport (vsock, …) | [`Listener`] + [`Stream`] | [`serve`]                  |
//!
//! Private keys sent with `ssh-add FILE` (ed25519, RSA, ECDSA and, with the
//! `dsa` feature, DSA) are held in memory out of the box.
//!
//! [`bind_socket`] makes an owner-only unix socket, or on Windows a named
//! pipe (`\\.\pipe\NAME`) that Win32-OpenSSH reaches through
//! `SSH_AUTH_SOCK`. On Windows the crate also answers PuTTY's tools as
//! Pageant would: serve the pipe `pageant_pipe_name()` names, and open
//! Pageant's window with `serve_pageant_window`. The `ssh` that Git for
//! Windows, MSYS2 and Cygwin bundle reaches neither, but connects to the
//! Cygwin-style socket file `bind_cygwin_socket` makes.
//!
//! ```no_run
//! use ssh_agent_kit::{Agent, bind_socket, default_socket_path, serve};
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//!
//! let (listener, _guard) = bind_socket(&default_socket_path("my-agent"))?;
//! let agent = Arc::new(Agent::new());
//! serve(listener, agent, Arc::new(AtomicBool::new(false)))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The agent never blocks on a slow key. Everything is synchronous and the
//! server runs one thread per connection, so a backend may block (waiting
//! for a touch, say) while other clients keep listing, signing with other
//! keys, locking and removing keys.

pub mod agent;
pub mod backend;
pub mod cert;
pub mod client;
#[cfg(windows)]
mod cygwin;
pub mod destination;
pub mod extension;
pub mod keytype;
pub mod local;
pub mod lock;
#[cfg(windows)]
mod pageant;
#[cfg(windows)]
mod pipe;
pub mod policy;
pub mod server;
pub mod signer;
#[cfg(test)]
mod stress;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
#[cfg(unix)]
mod unix;
pub mod wire;

pub use agent::{Agent, AgentError};
pub use backend::{Backend, Expiring, Lifecycle, Removed, SmartcardProvider};
pub use cert::{AssociatedCerts, CertError, CertKey};
pub use client::{ClientStream, connect};
#[cfg(windows)]
pub use cygwin::{CygwinListener, CygwinStream, bind_cygwin_socket, connect_cygwin};
pub use destination::{
    BindError, Connection, ConstraintError, ConstraintHop, DestinationConstraint, HostKeySpec,
    SessionBinding, Userauth,
};
pub use extension::{Extension, ExtensionContext, ExtensionReply};
pub use keytype::{KeyDecodeError, KeyDecoder, KeyRegistry};
#[cfg(feature = "dsa")]
pub use local::DsaLocalKey;
pub use local::{
    EcdsaLocalKey, Ed25519LocalKey, LocalKey, LocalKeyError, LocalKeyRef, RsaLocalKey,
};
pub use lock::{Locker, PassphraseLock};
#[cfg(windows)]
pub use pageant::{pageant_pipe_name, serve_pageant_window};
#[cfg(windows)]
pub use pipe::{PeerUser, PipeListener, PipeStream};
pub use policy::{
    Confirm, ConfirmRequest, KeyChange, KeyConstraints, ListInfo, ManageInfo, Policy, SignInfo,
};
pub use server::{
    Handler, Listener, SocketError, SocketGuard, SocketListener, Stream, bind_socket,
    default_socket_path, ephemeral_socket_path, handle_connection, serve,
};
pub use signer::{BoxError, Signer, SignerRef, VerifyError, verify};
pub use ssh_key;
