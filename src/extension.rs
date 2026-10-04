//! SSH agent protocol extensions: named requests the agent lets callers answer.
//!
//! Clients send an [`SSH_AGENTC_EXTENSION`](crate::wire::SSH_AGENTC_EXTENSION)
//! request carrying an extension name and an opaque payload. An [`Extension`]
//! registered with [`Agent::with_extension`](crate::Agent::with_extension)
//! answers the names it knows; every other name gets
//! [`SSH_AGENT_EXTENSION_FAILURE`](crate::wire::extension_failure), as OpenSSH's
//! agent replies to an extension it does not implement.
//!
//! Unlike the built-in operations, extensions never touch key material: the
//! only agent state an [`ExtensionContext`] exposes is whether the agent is
//! locked, so a handler can refuse its own operations while locked while
//! leaving lock-independent ones working.

use crate::wire;

/// Read-only state an [`Extension`] may consult while handling a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionContext {
    locked: bool,
}

impl ExtensionContext {
    /// Whether `ssh-add -x` has locked the agent. Extensions are not refused
    /// automatically while locked, so a handler decides for itself.
    pub fn locked(&self) -> bool {
        self.locked
    }

    pub(crate) fn new(locked: bool) -> Self {
        ExtensionContext { locked }
    }
}

/// The reply to an extension request.
///
/// [`Success`](Self::Success) and [`Failure`](Self::Failure) say the extension
/// is implemented and succeeded or failed; [`ExtensionFailure`](Self::ExtensionFailure)
/// says it is not implemented at all. [`Raw`](Self::Raw) carries a complete
/// reply body for an extension that answers with a message of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionReply {
    Success,
    Failure,
    ExtensionFailure,
    Raw(Vec<u8>),
}

impl ExtensionReply {
    /// The reply body to put on the wire.
    pub fn into_body(self) -> Vec<u8> {
        match self {
            ExtensionReply::Success => wire::success(),
            ExtensionReply::Failure => wire::failure(),
            ExtensionReply::ExtensionFailure => wire::extension_failure(),
            ExtensionReply::Raw(body) => body,
        }
    }
}

impl From<Vec<u8>> for ExtensionReply {
    fn from(body: Vec<u8>) -> Self {
        ExtensionReply::Raw(body)
    }
}

/// An SSH agent protocol extension, such as `query@openssh.com`.
///
/// Implementations answer the requests whose [`name`](Self::name) matches,
/// receiving the payload that follows the name. Register one with
/// [`Agent::with_extension`](crate::Agent::with_extension); the last
/// extension registered under a name wins.
///
/// ```no_run
/// use ssh_agent_kit::{Extension, ExtensionContext, ExtensionReply};
///
/// struct Ping;
///
/// impl Extension for Ping {
///     fn name(&self) -> &str {
///         "ping@example.com"
///     }
///
///     fn handle(&self, _ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply {
///         if data == b"ping" {
///             ExtensionReply::Success
///         } else {
///             ExtensionReply::Failure
///         }
///     }
/// }
/// ```
pub trait Extension: Send + Sync {
    /// The extension name matched against the request, e.g. `query@openssh.com`.
    fn name(&self) -> &str;

    /// Handle one request that named this extension, with everything after the
    /// name as `data`. Return [`ExtensionReply::Failure`] on error.
    fn handle(&self, ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_map_to_wire_bodies() {
        assert_eq!(ExtensionReply::Success.into_body(), wire::success());
        assert_eq!(ExtensionReply::Failure.into_body(), wire::failure());
        assert_eq!(
            ExtensionReply::ExtensionFailure.into_body(),
            wire::extension_failure()
        );
        assert_eq!(
            ExtensionReply::Raw(vec![1, 2, 3]).into_body(),
            vec![1, 2, 3]
        );
        assert_eq!(ExtensionReply::from(vec![9, 9]).into_body(), vec![9, 9]);
    }
}
