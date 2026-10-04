//! Asking the user, and deciding what the agent allows.
//!
//! - [`Confirm`] asks the user about one use of a key added with
//!   `ssh-add -c`. Without one, such keys never sign.
//! - [`Policy`] is a veto and audit hook over every signature and every
//!   key change, beyond the constraints the client attached.

use crate::destination::Connection;
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
    /// Called for each sign request once the key's `ssh-add -c`/`-h`
    /// constraints pass. Returning `false` refuses it.
    fn allow_sign(&self, _request: &SignInfo<'_>) -> bool {
        true
    }

    /// Called after each signature, for auditing.
    fn signed(&self, _request: &SignInfo<'_>) {}

    /// Whether `connection` may add or remove keys at all (`ssh-add`,
    /// `ssh-add -d`, `-D`, `-s`, `-e`).
    fn allow_manage(&self, _connection: &Connection) -> bool {
        true
    }
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
