//! Destination constraints and session bindings.
//!
//! OpenSSH clients bind an agent connection to the SSH session it serves with
//! the `session-bind@openssh.com` extension, and may attach
//! `restrict-destination-v00@openssh.com` constraints to keys added with
//! `ssh-add -h`. This module parses those messages, records the bindings of
//! one connection, and decides whether a constrained key may be used there.
//!
//! The matching follows OpenSSH's `ssh-agent.c`: a constraint allows a key at
//! the destination of its `to` hop, and, with forwarding, at intermediate
//! hops. A connection with no bindings is local use, where constraints do not
//! apply.

use signature::Verifier;
use ssh_encoding::{Decode, Encode};
use ssh_key::{PublicKey, Signature};
use thiserror::Error;

/// The extension that binds a connection to a session and host key.
pub const SESSION_BIND: &str = "session-bind@openssh.com";
/// The constraint extension that restricts a key's destinations.
pub const RESTRICT_DESTINATION: &str = "restrict-destination-v00@openssh.com";
/// The extension that lists the extensions the agent supports.
pub const QUERY: &str = "query";

/// As OpenSSH: at most this many session IDs per connection.
pub const MAX_SESSION_IDS: usize = 16;
/// As OpenSSH: session identifiers longer than this are refused.
pub const MAX_SESSION_ID_LEN: usize = 128;
/// As OpenSSH: at most this many destination constraints on one key.
pub const MAX_DEST_CONSTRAINTS: usize = 1024;
/// As OpenSSH: a user match pattern longer than this is refused.
pub const MAX_USER_CONSTRAINT_LEN: usize = 256;

#[derive(Debug, Error)]
pub enum ConstraintError {
    #[error("malformed destination constraint: {0}")]
    Malformed(#[from] ssh_encoding::Error),
    #[error("malformed host key in destination constraint: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("a destination constraint's reserved field is not empty")]
    Reserved,
    #[error("the from-hop of a destination constraint names a user or lacks a host key")]
    InconsistentFrom,
    #[error("the to-hop of a destination constraint is incomplete")]
    IncompleteTo,
    #[error("too many destination constraints")]
    TooMany,
    #[error("the destination-constraint user pattern is too long")]
    UserTooLong,
    #[error(
        "a destination-constraint hop names only certificate authorities; host certificates are not supported, so the key could never be used there"
    )]
    CertificateAuthorityOnly,
}

/// One host key of a constraint hop: a plain key to match exactly, or a CA
/// key (`is_ca`) that must have signed the host certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeySpec {
    pub key: PublicKey,
    pub is_ca: bool,
}

/// One end of a destination constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintHop {
    /// A user pattern the destination user must match; empty means any.
    pub username: Option<String>,
    /// A hostname, for certificates and display; empty means origin or any.
    pub hostname: Option<String>,
    pub hostkeys: Vec<HostKeySpec>,
}

/// A key may only be used on the hosts its `to` hop allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationConstraint {
    pub from: ConstraintHop,
    pub to: ConstraintHop,
}

impl ConstraintHop {
    fn parse(mut reader: &[u8]) -> Result<Self, ConstraintError> {
        let username = String::decode(&mut reader)?;
        let hostname = String::decode(&mut reader)?;
        let reserved = Vec::<u8>::decode(&mut reader)?;
        if !reserved.is_empty() {
            return Err(ConstraintError::Reserved);
        }
        let mut hostkeys = Vec::new();
        while !reader.is_empty() {
            let blob = Vec::<u8>::decode(&mut reader)?;
            let key = PublicKey::from_bytes(&blob)?;
            let is_ca = u8::decode(&mut reader)?;
            match is_ca {
                0 => hostkeys.push(HostKeySpec { key, is_ca: false }),
                1 => hostkeys.push(HostKeySpec { key, is_ca: true }),
                _ => return Err(ConstraintError::Malformed(ssh_encoding::Error::Length)),
            }
        }
        let username = (!username.is_empty()).then_some(username);
        if username
            .as_ref()
            .is_some_and(|user| user.len() > MAX_USER_CONSTRAINT_LEN)
        {
            return Err(ConstraintError::UserTooLong);
        }
        let hostname = (!hostname.is_empty()).then_some(hostname);
        Ok(ConstraintHop {
            username,
            hostname,
            hostkeys,
        })
    }
}

/// Parse the payload of a `restrict-destination-v00@openssh.com` constraint
/// extension, the bytes after the extension name.
pub fn parse_constraints(
    reader: &mut &[u8],
) -> Result<Vec<DestinationConstraint>, ConstraintError> {
    // The extension payload is a string holding a sequence of strings, each
    // one constraint (see OpenSSH's parse_key_constraint_extension).
    let body = Vec::<u8>::decode(reader)?;
    if !reader.is_empty() {
        return Err(ConstraintError::Malformed(ssh_encoding::Error::Length));
    }
    let mut body = body.as_slice();
    let mut constraints = Vec::new();
    while !body.is_empty() {
        if constraints.len() >= MAX_DEST_CONSTRAINTS {
            return Err(ConstraintError::TooMany);
        }
        let one = Vec::<u8>::decode(&mut body)?;
        let mut one = one.as_slice();
        let from = Vec::<u8>::decode(&mut one)?;
        let to = Vec::<u8>::decode(&mut one)?;
        let reserved = Vec::<u8>::decode(&mut one)?;
        if !reserved.is_empty() || !one.is_empty() {
            return Err(ConstraintError::Reserved);
        }
        let constraint = DestinationConstraint {
            from: ConstraintHop::parse(&from)?,
            to: ConstraintHop::parse(&to)?,
        };
        if constraint.from.username.is_some()
            || constraint.from.hostname.is_none() != constraint.from.hostkeys.is_empty()
        {
            return Err(ConstraintError::InconsistentFrom);
        }
        if constraint.to.hostname.is_none() || constraint.to.hostkeys.is_empty() {
            return Err(ConstraintError::IncompleteTo);
        }
        // CA keys never match (see `permits`), so a hop with nothing else
        // would make the key unusable without saying why.
        for hop in [&constraint.from, &constraint.to] {
            if !hop.hostkeys.is_empty() && hop.hostkeys.iter().all(|spec| spec.is_ca) {
                return Err(ConstraintError::CertificateAuthorityOnly);
            }
        }
        constraints.push(constraint);
    }
    Ok(constraints)
}

/// A session bound to this agent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The server's host key, as sent in the bind.
    pub key: PublicKey,
    /// The session identifier from the initial key exchange.
    pub session_id: Vec<u8>,
    /// Whether this is a forwarded session (`ssh -A`) rather than the
    /// connection authenticating to the server.
    pub forwarded: bool,
}

/// Why a `session-bind@openssh.com` request was refused.
#[derive(Debug, Error)]
pub enum BindError {
    #[error("malformed session bind: {0}")]
    Malformed(#[from] ssh_encoding::Error),
    #[error("malformed host key or signature in session bind: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("session bind has an unexpected trailing byte")]
    TrailingData,
    #[error("the host key signature over the session identifier is invalid")]
    BadSignature,
    #[error("session identifier is longer than {MAX_SESSION_ID_LEN} bytes")]
    SessionIdTooLong,
    #[error("session identifier already bound to a different host key")]
    SessionIdConflict,
    #[error("cannot bind a connection already bound for authentication")]
    AlreadyBound,
    #[error("too many session identifiers bound to this connection")]
    TooManySessions,
}

/// The session bindings of one agent connection, and whether the client tried
/// to bind it at all. A failed bind makes every constrained key unavailable on
/// the connection, as in OpenSSH.
#[derive(Debug, Default, Clone)]
pub struct Connection {
    bindings: Vec<SessionBinding>,
    bind_attempted: bool,
}

impl Connection {
    /// The bindings recorded so far, oldest first.
    pub fn bindings(&self) -> &[SessionBinding] {
        &self.bindings
    }

    /// Whether the client sent any `session-bind@openssh.com` request, as
    /// `ssh` does on a connection it forwards or authenticates with. With no
    /// [`Self::bindings`], the bind failed.
    pub fn bind_attempted(&self) -> bool {
        self.bind_attempted
    }

    /// Record a `session-bind@openssh.com` request: verify `signature` over
    /// `session_id` with `hostkey`, then remember the binding.
    pub fn bind(
        &mut self,
        hostkey: PublicKey,
        session_id: &[u8],
        signature: &[u8],
        forwarded: bool,
    ) -> Result<(), BindError> {
        self.bind_attempted = true;
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(BindError::SessionIdTooLong);
        }
        let mut rest = signature;
        let signature = Signature::decode(&mut rest)?;
        if !rest.is_empty() {
            return Err(BindError::TrailingData);
        }
        Verifier::verify(&hostkey, session_id, &signature).map_err(|_| BindError::BadSignature)?;
        // A connection that already authenticated cannot be bound afterwards.
        if self.bindings.iter().any(|b| !b.forwarded) {
            return Err(BindError::AlreadyBound);
        }
        for binding in &self.bindings {
            if binding.session_id == session_id {
                if binding.key.key_data() == hostkey.key_data() {
                    return Ok(());
                }
                return Err(BindError::SessionIdConflict);
            }
        }
        if self.bindings.len() >= MAX_SESSION_IDS {
            return Err(BindError::TooManySessions);
        }
        self.bindings.push(SessionBinding {
            key: hostkey,
            session_id: session_id.to_vec(),
            forwarded,
        });
        Ok(())
    }

    /// Whether a key with `constraints` may be used on this connection.
    /// `user` is the destination user for a signature request, and `None` for
    /// listing or key management.
    pub fn permits(&self, constraints: &[DestinationConstraint], user: Option<&str>) -> bool {
        if constraints.is_empty() {
            return true; // unconstrained
        }
        if self.bind_attempted && self.bindings.is_empty() {
            return false; // a failed bind poisons the connection
        }
        if self.bindings.is_empty() {
            return true; // local use
        }
        let mut fromkey: Option<&PublicKey> = None;
        for (i, binding) in self.bindings.iter().enumerate() {
            let last = i + 1 == self.bindings.len();
            let test_user = if last { user } else { None };
            if last && binding.forwarded && user.is_some() {
                return false; // signing on a forwarding hop
            }
            if !last && !binding.forwarded {
                return false; // forwarding through a signing binding
            }
            if !permitted_by(constraints, fromkey, Some(&binding.key), test_user) {
                return false;
            }
            fromkey = Some(&binding.key);
        }
        // A key last bound for forwarding must also be permitted beyond it.
        let last = self.bindings.last().expect("bindings is not empty");
        if last.forwarded && user.is_none() {
            return permitted_by(constraints, Some(&last.key), None, None);
        }
        true
    }
}

/// Whether any constraint matches the keys and user, as OpenSSH's
/// `permitted_by_dest_constraints`.
fn permitted_by(
    constraints: &[DestinationConstraint],
    fromkey: Option<&PublicKey>,
    tokey: Option<&PublicKey>,
    user: Option<&str>,
) -> bool {
    for constraint in constraints {
        match fromkey {
            None => {
                // Matching the first hop: the from-hop must be the origin.
                if constraint.from.hostname.is_some() || !constraint.from.hostkeys.is_empty() {
                    continue;
                }
            }
            Some(key) => {
                if !hop_matches(&constraint.from, key) {
                    continue;
                }
            }
        }
        if let Some(key) = tokey
            && !hop_matches(&constraint.to, key)
        {
            continue;
        }
        if let (Some(pattern), Some(user)) = (&constraint.to.username, user)
            && !pattern_matches(user, pattern)
        {
            continue;
        }
        return true;
    }
    false
}

/// Match a host key against a constraint hop. A certificate host key can only
/// be matched through a CA it was signed by; this agent cannot inspect
/// certificates here, so such a key never matches a CA entry and is refused.
fn hop_matches(hop: &ConstraintHop, key: &PublicKey) -> bool {
    if key.algorithm().as_str().ends_with("-cert-v01@openssh.com") {
        return false;
    }
    hop.hostkeys
        .iter()
        .any(|spec| !spec.is_ca && spec.key.key_data() == key.key_data())
}

/// A `user`/`user@host` pattern with `*` and `?` wildcards, as `match_pattern`.
fn pattern_matches(value: &str, pattern: &str) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    let (mut v, mut p) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            v += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// What a signature request's data reveals when it is a userauth request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Userauth {
    /// The server-side user being authenticated.
    pub user: String,
    /// The session identifier of the connection.
    pub session_id: Vec<u8>,
    /// The host key of the connection, when the method is host-bound.
    pub hostkey: Option<PublicKey>,
}

const SSH2_MSG_USERAUTH_REQUEST: u8 = 50;
const METHOD_PUBLICKEY: &str = "publickey";
const METHOD_PUBLICKEY_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// Parse `data` as a publickey userauth request for `expected`, as OpenSSH's
/// `parse_userauth_request`. Returns `None` for anything else.
pub fn parse_userauth_request(data: &[u8], expected: &PublicKey) -> Option<Userauth> {
    parse_userauth_request_for(data, &expected.to_bytes().ok()?)
}

/// As [`parse_userauth_request`], for the key or certificate whose wire blob
/// is `expected`: a sign request names a certificate by its blob, and the
/// userauth request it signs carries that same blob.
pub fn parse_userauth_request_for(mut data: &[u8], expected: &[u8]) -> Option<Userauth> {
    let session_id = Vec::<u8>::decode(&mut data).ok()?;
    if session_id.is_empty() {
        return None;
    }
    if u8::decode(&mut data).ok()? != SSH2_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = String::decode(&mut data).ok()?;
    let service = String::decode(&mut data).ok()?;
    let method = String::decode(&mut data).ok()?;
    let sig_follows = u8::decode(&mut data).ok()?;
    let _pkalg = String::decode(&mut data).ok()?;
    let blob = Vec::<u8>::decode(&mut data).ok()?;
    if sig_follows != 1 || service != "ssh-connection" || blob != expected {
        return None;
    }
    let hostkey = if method == METHOD_PUBLICKEY_HOSTBOUND {
        let blob = Vec::<u8>::decode(&mut data).ok()?;
        Some(PublicKey::from_bytes(&blob).ok()?)
    } else if method == METHOD_PUBLICKEY {
        None
    } else {
        return None;
    };
    if !data.is_empty() {
        return None;
    }
    Some(Userauth {
        user,
        session_id,
        hostkey,
    })
}

/// Encode the reply to a `query` extension: the extension names this agent
/// understands, as OpenSSH's `process_ext_query`.
pub fn query_reply() -> Vec<u8> {
    let mut out = vec![29u8]; // SSH_AGENT_EXTENSION_RESPONSE
    QUERY.encode(&mut out).expect("vec write");
    SESSION_BIND.encode(&mut out).expect("vec write");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_encoding::Encode;
    use ssh_key::private::Ed25519Keypair;
    use ssh_key::private::KeypairData;
    use ssh_key::private::PrivateKey;

    fn keypair(seed: u8) -> PrivateKey {
        PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])),
            format!("key{seed}"),
        )
        .unwrap()
    }

    fn public(seed: u8) -> PublicKey {
        keypair(seed).public_key().clone()
    }

    /// Encode the nested buffers of one destination constraint, as the
    /// extension carries them.
    fn constraint(
        from_hostname: &str,
        from_keys: &[u8],
        to_user: &str,
        to_hostname: &str,
        to_keys: &[u8],
    ) -> Vec<u8> {
        let mut from = Vec::new();
        "".encode(&mut from).unwrap(); // from user must be empty
        from_hostname.encode(&mut from).unwrap();
        Vec::<u8>::new().encode(&mut from).unwrap(); // reserved
        from.extend_from_slice(from_keys);

        let mut to = Vec::new();
        to_user.encode(&mut to).unwrap();
        to_hostname.encode(&mut to).unwrap();
        Vec::<u8>::new().encode(&mut to).unwrap();
        to.extend_from_slice(to_keys);

        let mut one = Vec::new();
        from.encode(&mut one).unwrap();
        to.encode(&mut one).unwrap();
        Vec::<u8>::new().encode(&mut one).unwrap(); // reserved
        one
    }

    fn keyspec(key: &PublicKey, is_ca: bool) -> Vec<u8> {
        let mut out = Vec::new();
        key.to_bytes().unwrap().encode(&mut out).unwrap();
        out.push(is_ca as u8);
        out
    }

    fn extension(constraints: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for one in constraints {
            one.encode(&mut body).unwrap();
        }
        let mut out = Vec::new();
        body.encode(&mut out).unwrap();
        out
    }

    /// Host certificates are not supported, so a hop with only CA keys is
    /// refused when the key is added; one with a plain key too is kept.
    #[test]
    fn a_hop_with_only_ca_keys_is_refused() {
        let ca = keyspec(&public(1), true);
        let payload = extension(&[constraint("", &[], "", "example.com", &ca)]);
        assert!(matches!(
            parse_constraints(&mut payload.as_slice()),
            Err(ConstraintError::CertificateAuthorityOnly)
        ));
        let mut mixed = ca.clone();
        mixed.extend(keyspec(&public(2), false));
        let payload = extension(&[constraint("", &[], "", "example.com", &mixed)]);
        assert_eq!(parse_constraints(&mut payload.as_slice()).unwrap().len(), 1);
    }

    #[test]
    fn parses_a_destination_constraint() {
        let hostkey = public(1);
        let mut keys = Vec::new();
        keys.extend(keyspec(&hostkey, false));
        let payload = extension(&[constraint("", &[], "ferris", "example.com", &keys)]);
        let constraints = parse_constraints(&mut payload.as_slice()).unwrap();
        assert_eq!(constraints.len(), 1);
        let c = &constraints[0];
        assert_eq!(c.from.username, None);
        assert_eq!(c.from.hostname, None);
        assert!(c.from.hostkeys.is_empty());
        assert_eq!(c.to.username.as_deref(), Some("ferris"));
        assert_eq!(c.to.hostname.as_deref(), Some("example.com"));
        assert_eq!(c.to.hostkeys[0].key.key_data(), hostkey.key_data());
        assert!(!c.to.hostkeys[0].is_ca);
    }

    #[test]
    fn rejects_incomplete_and_inconsistent_constraints() {
        let hostkey = public(1);
        let keys = {
            let mut k = Vec::new();
            k.extend(keyspec(&hostkey, false));
            k
        };
        // A to-hop without keys is incomplete.
        let payload = extension(&[constraint("", &[], "", "example.com", &[])]);
        assert!(matches!(
            parse_constraints(&mut payload.as_slice()),
            Err(ConstraintError::IncompleteTo)
        ));
        // A from-hop with keys but no hostname is inconsistent.
        let payload = extension(&[constraint("", &keys, "", "example.com", &keys)]);
        assert!(matches!(
            parse_constraints(&mut payload.as_slice()),
            Err(ConstraintError::InconsistentFrom)
        ));
    }

    #[test]
    fn pattern_matching_follows_match_pattern() {
        assert!(pattern_matches("ferris", "ferris"));
        assert!(pattern_matches("ferris", "*"));
        assert!(pattern_matches("ferris", "fer*"));
        assert!(pattern_matches("ferris", "*ris"));
        assert!(pattern_matches("ferris", "f?rris"));
        assert!(pattern_matches("ferris", "f*r*is"));
        assert!(!pattern_matches("ferris", "fer"));
        assert!(!pattern_matches("ferris", "?erris!"));
        assert!(!pattern_matches("", "?"));
        assert!(pattern_matches("", "*"));
    }

    #[test]
    fn bind_verifies_the_signature_and_rejects_bad_ones() {
        let host = keypair(2);
        let session_id = b"a session identifier";
        let signature = Signer::sign(&host, session_id);
        let mut signature_bytes = Vec::new();
        signature.encode(&mut signature_bytes).unwrap();

        let mut conn = Connection::default();
        conn.bind(public(2), session_id, &signature_bytes, true)
            .unwrap();
        assert_eq!(conn.bindings().len(), 1);

        // The same session and key again is idempotent for a forwarded bind.
        conn.bind(public(2), session_id, &signature_bytes, true)
            .unwrap();
        assert_eq!(conn.bindings().len(), 1);

        // A different session identifier with the same key is another binding.
        let other = b"another session identifier";
        let other_sig = Signer::sign(&host, other);
        let mut other_bytes = Vec::new();
        other_sig.encode(&mut other_bytes).unwrap();
        conn.bind(public(2), other, &other_bytes, true).unwrap();
        assert_eq!(conn.bindings().len(), 2);

        // A bad signature is refused.
        let mut conn = Connection::default();
        assert!(conn.bind(public(2), session_id, b"", false).is_err());
        assert!(matches!(
            conn.bind(public(3), session_id, &signature_bytes, false),
            Err(BindError::BadSignature)
        ));

        // Binding the same session to a different key is a conflict.
        let mut conn = Connection::default();
        conn.bind(public(2), session_id, &signature_bytes, true)
            .unwrap();
        let three = keypair(3);
        let three_sig = Signer::sign(&three, session_id);
        let mut three_bytes = Vec::new();
        three_sig.encode(&mut three_bytes).unwrap();
        assert!(matches!(
            conn.bind(public(3), session_id, &three_bytes, false),
            Err(BindError::SessionIdConflict)
        ));

        // Once a connection is bound for authentication, it cannot be bound
        // again at all.
        let mut conn = Connection::default();
        conn.bind(public(2), session_id, &signature_bytes, false)
            .unwrap();
        assert!(matches!(
            conn.bind(public(2), other, &other_bytes, false),
            Err(BindError::AlreadyBound)
        ));
    }

    #[test]
    fn a_failed_bind_poisons_the_connection_for_constrained_keys() {
        let mut conn = Connection::default();
        // Record the attempt without a binding, as a rejected bind does.
        conn.bind(public(2), b"sid", b"not a signature", false)
            .unwrap_err();
        assert!(!conn.permits(
            &[DestinationConstraint {
                from: ConstraintHop {
                    username: None,
                    hostname: None,
                    hostkeys: Vec::new(),
                },
                to: ConstraintHop {
                    username: None,
                    hostname: Some("example.com".into()),
                    hostkeys: vec![HostKeySpec {
                        key: public(2),
                        is_ca: false,
                    }],
                },
            }],
            None
        ));
    }

    #[test]
    fn local_use_permits_constrained_keys() {
        let conn = Connection::default();
        let constraints = [DestinationConstraint {
            from: ConstraintHop {
                username: None,
                hostname: None,
                hostkeys: Vec::new(),
            },
            to: ConstraintHop {
                username: None,
                hostname: Some("example.com".into()),
                hostkeys: vec![HostKeySpec {
                    key: public(2),
                    is_ca: false,
                }],
            },
        }];
        assert!(conn.permits(&constraints, None));
        assert!(conn.permits(&constraints, Some("ferris")));
    }

    #[test]
    fn a_bound_connection_permits_only_the_constrained_host() {
        let host = keypair(2);
        let session_id = b"session";
        let sig = Signer::sign(&host, session_id);
        let mut bytes = Vec::new();
        sig.encode(&mut bytes).unwrap();
        let mut conn = Connection::default();
        conn.bind(public(2), session_id, &bytes, false).unwrap();

        let allowed = DestinationConstraint {
            from: ConstraintHop {
                username: None,
                hostname: None,
                hostkeys: Vec::new(),
            },
            to: ConstraintHop {
                username: None,
                hostname: Some("example.com".into()),
                hostkeys: vec![HostKeySpec {
                    key: public(2),
                    is_ca: false,
                }],
            },
        };
        let elsewhere = DestinationConstraint {
            from: ConstraintHop {
                username: None,
                hostname: None,
                hostkeys: Vec::new(),
            },
            to: ConstraintHop {
                username: None,
                hostname: Some("other.example".into()),
                hostkeys: vec![HostKeySpec {
                    key: public(3),
                    is_ca: false,
                }],
            },
        };
        assert!(conn.permits(std::slice::from_ref(&allowed), Some("ferris")));
        assert!(!conn.permits(&[elsewhere], Some("ferris")));
    }

    #[test]
    fn user_patterns_are_enforced_on_signature_requests() {
        let host = keypair(2);
        let session_id = b"session";
        let sig = Signer::sign(&host, session_id);
        let mut bytes = Vec::new();
        sig.encode(&mut bytes).unwrap();
        let mut conn = Connection::default();
        conn.bind(public(2), session_id, &bytes, false).unwrap();
        let constraints = [DestinationConstraint {
            from: ConstraintHop {
                username: None,
                hostname: None,
                hostkeys: Vec::new(),
            },
            to: ConstraintHop {
                username: Some("git".into()),
                hostname: Some("example.com".into()),
                hostkeys: vec![HostKeySpec {
                    key: public(2),
                    is_ca: false,
                }],
            },
        }];
        assert!(conn.permits(&constraints, Some("git")));
        assert!(!conn.permits(&constraints, Some("root")));
        // Listing (no user) cannot check the pattern, as in OpenSSH.
        assert!(conn.permits(&constraints, None));
    }

    #[test]
    fn parses_a_hostbound_userauth_request() {
        let key = keypair(4);
        let host = keypair(2);
        let mut body = Vec::new();
        b"session-id".encode(&mut body).unwrap();
        body.push(SSH2_MSG_USERAUTH_REQUEST);
        "ferris".encode(&mut body).unwrap();
        "ssh-connection".encode(&mut body).unwrap();
        METHOD_PUBLICKEY_HOSTBOUND.encode(&mut body).unwrap();
        body.push(1);
        key.public_key()
            .algorithm()
            .as_str()
            .encode(&mut body)
            .unwrap();
        key.public_key()
            .to_bytes()
            .unwrap()
            .encode(&mut body)
            .unwrap();
        host.public_key()
            .to_bytes()
            .unwrap()
            .encode(&mut body)
            .unwrap();

        let parsed = parse_userauth_request(&body, key.public_key()).unwrap();
        assert_eq!(parsed.user, "ferris");
        assert_eq!(parsed.session_id, b"session-id");
        assert_eq!(
            parsed.hostkey.as_ref().map(PublicKey::key_data),
            Some(host.public_key().key_data())
        );

        // A plain publickey request has no host key.
        let mut plain = Vec::new();
        b"session-id".encode(&mut plain).unwrap();
        plain.push(SSH2_MSG_USERAUTH_REQUEST);
        "ferris".encode(&mut plain).unwrap();
        "ssh-connection".encode(&mut plain).unwrap();
        METHOD_PUBLICKEY.encode(&mut plain).unwrap();
        plain.push(1);
        key.public_key()
            .algorithm()
            .as_str()
            .encode(&mut plain)
            .unwrap();
        key.public_key()
            .to_bytes()
            .unwrap()
            .encode(&mut plain)
            .unwrap();
        let parsed = parse_userauth_request(&plain, key.public_key()).unwrap();
        assert_eq!(parsed.hostkey, None);
    }
}
