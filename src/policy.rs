//! Asking the user, and deciding what the agent allows.
//!
//! - [`Confirm`] asks the user about one use of a key added with
//!   `ssh-add -c`. Without one, such keys never sign.
//! - [`Policy`] is a veto and audit hook over every signature, every key
//!   change and which keys are listed, beyond the constraints the client
//!   attached.

use crate::cert::CertKey;
use crate::destination::{Connection, DestinationConstraint};
use ssh_key::PublicKey;

/// One use of a key that the `ssh-add -c` confirm constraint asks the user
/// to allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmRequest {
    /// Comment of the key being used, e.g. `ferris@example.com`.
    pub identity: String,
    /// The key's SHA-256 fingerprint, as `SHA256:…`.
    pub fingerprint: String,
    /// What is being signed, if the request could be summarised.
    pub subject: Option<String>,
}

impl ConfirmRequest {
    /// One-line human-readable prompt.
    pub fn message(&self) -> String {
        let subject = self
            .subject
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        printable(&format!(
            "Allow use of key {}{subject}? Key fingerprint {}. (yes/no)",
            self.identity, self.fingerprint
        ))
    }
}

/// Asks the user whether a confirmed key may sign.
pub trait Confirm: Send + Sync {
    /// `Some(true)` allows this one use, `Some(false)` refuses it, and `None`
    /// means no answer could be had (no terminal, no askpass); the agent
    /// refuses unless the answer is `Some(true)`.
    fn confirm(&self, request: &ConfirmRequest) -> Option<bool>;
}

/// A signature the agent is about to make, or has made.
#[derive(Debug, Clone, Copy)]
pub struct SignInfo<'a> {
    /// The key that signs; for a certificate, the key it certifies.
    pub key: &'a PublicKey,
    /// The data to be signed.
    pub data: &'a [u8],
    /// The client connection, with its session bindings.
    pub connection: &'a Connection,
}

/// What the agent allows, beyond each key's own constraints. Every method
/// allows by default.
pub trait Policy: Send + Sync {
    /// Called for each sign request once the key's `ssh-add -h` destination
    /// constraint passes, and before the `ssh-add -c` confirm prompt, so the
    /// user is never asked about a signature the policy refuses. Returning
    /// `false` refuses it.
    fn allow_sign(&self, _request: &SignInfo<'_>) -> bool {
        true
    }

    /// Called after each signature, for auditing.
    fn signed(&self, _request: &SignInfo<'_>) {}

    /// Whether to show an identity when a client lists keys (`ssh-add -l`,
    /// and `ssh` choosing which keys to offer). Called for each key and
    /// certificate on every listing, after keys the connection's session
    /// bindings rule out (`ssh-add -h`) are already left out. Returning
    /// `false` leaves it out.
    ///
    /// Hiding is not refusing: a client that already knows a key can still
    /// ask the agent to sign with it. Refuse those in [`Self::allow_sign`].
    fn allow_list(&self, _request: &ListInfo<'_>) -> bool {
        true
    }

    /// Whether a client may make a key change: `ssh-add`, `ssh-add -d`,
    /// `-D`, `-s` or `-e`. Called before the change, and before each key's
    /// own `ssh-add -h` constraint is checked. Returning `false` refuses it.
    ///
    /// Called while the agent takes key changes one at a time: a request
    /// that changes keys (through [`Agent::handle`](crate::Agent::handle))
    /// made from here waits for this one to finish, so never returns.
    fn allow_manage(&self, _request: &ManageInfo<'_>) -> bool {
        true
    }
}

/// An identity the agent is about to list.
#[derive(Debug, Clone, Copy)]
pub struct ListInfo<'a> {
    /// The key; for a certificate, the key it certifies.
    pub key: &'a PublicKey,
    /// The certificate, when the identity is one.
    pub certificate: Option<&'a CertKey>,
    /// The client connection, with its session bindings.
    pub connection: &'a Connection,
}

/// A key change a client asks for, and the connection it came on.
#[derive(Debug, Clone, Copy)]
pub struct ManageInfo<'a> {
    pub change: KeyChange<'a>,
    /// The client connection, with its session bindings.
    pub connection: &'a Connection,
}

impl ManageInfo<'_> {
    /// The key the change is about, when one is known: the key to add, the
    /// served key to remove, or the key a provider resolved.
    pub fn key(&self) -> Option<&PublicKey> {
        match self.change {
            KeyChange::Add { key, .. } | KeyChange::AddProvider { key, .. } => Some(key),
            KeyChange::Remove { key, .. } => key,
            KeyChange::RemoveAll | KeyChange::RemoveProvider { .. } => None,
        }
    }
}

/// The key changes a client can ask for.
#[derive(Debug, Clone, Copy)]
pub enum KeyChange<'a> {
    /// `ssh-add FILE`: add a private key, or the certificate sent with it.
    Add {
        /// The key; for a certificate, the key it certifies.
        key: &'a PublicKey,
        certificate: Option<&'a CertKey>,
        constraints: KeyConstraints<'a>,
    },
    /// `ssh-add -d`: remove the key or certificate whose blob is `key_blob`.
    Remove {
        key_blob: &'a [u8],
        /// The served key with that blob, or the key a served certificate
        /// with that blob certifies; `None` when nothing served matches.
        key: Option<&'a PublicKey>,
    },
    /// `ssh-add -D`: remove every identity.
    RemoveAll,
    /// `ssh-add -s PROVIDER [CERT…]`: serve the key a
    /// [`SmartcardProvider`](crate::SmartcardProvider) resolves the provider
    /// string to. Asked once the provider has fetched the key, and before it
    /// is served.
    AddProvider {
        provider: &'a [u8],
        key: &'a PublicKey,
        /// The certificates given after the provider, certifying `key` or not.
        certificates: &'a [CertKey],
        /// `ssh-add -C`: serve only the certificates, not the key itself.
        certificates_only: bool,
        constraints: KeyConstraints<'a>,
    },
    /// `ssh-add -e PROVIDER`: stop serving the key the provider names. The
    /// provider string is not resolved, which could mean a device fetch.
    RemoveProvider { provider: &'a [u8] },
}

/// The constraints an added key would be served with.
#[derive(Debug, Clone, Copy)]
pub struct KeyConstraints<'a> {
    /// Seconds until the key is dropped: `ssh-add -t`, else the agent's
    /// default lifetime; `None` keeps it until removed.
    pub lifetime: Option<u32>,
    /// `ssh-add -c`: every use asks the user.
    pub confirm: bool,
    /// `ssh-add -h`: where the key may be used.
    pub destination: &'a [DestinationConstraint],
}

/// `text` with control characters and bidirectional overrides escaped, so a
/// prompt stays one line that says what it seems to. Key comments and the
/// signed data's description come from clients, which could otherwise move
/// the cursor, rewrite the prompt or send terminal escape sequences.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let reorders = matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        );
        if c.is_control() || reorders || c == '\u{2028}' || c == '\u{2029}' {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}
