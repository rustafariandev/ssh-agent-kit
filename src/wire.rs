//! SSH agent wire protocol: framing, the requests this agent serves, and
//! their replies (draft-miller-ssh-agent).

use crate::cert::{self, AssociatedCerts, CertKey};
use crate::destination::{self, DestinationConstraint};
use crate::keytype::{KeyDecodeError, KeyRegistry};
use crate::signer::SignerRef;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};
use std::io::{self, Read, Write};
use thiserror::Error;
use zeroize::Zeroizing;

/// SSH v1 request for RSA identities, which some clients still send first.
pub const SSH_AGENTC_REQUEST_RSA_IDENTITIES: u8 = 1;
pub const SSH_AGENT_RSA_IDENTITIES_ANSWER: u8 = 2;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
/// `ssh-add FILE`: add a private key held in memory.
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
/// `ssh-add -d FILE`: remove the identity with a given public key blob.
pub const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
/// `ssh-add -D`: remove every identity.
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
/// `ssh-add -s`: add a key named by a provider string.
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
/// `ssh-add -e`: remove a key named by a provider string.
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
/// `ssh-add -t N FILE`: add a private key with constraints.
pub const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
/// `ssh-add -s` with `-t`/`-c`/certificates: an add carrying constraints.
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
/// Constraint on `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`: a lifetime.
pub const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
/// Constraint on `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`: confirm each use.
pub const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;
/// Constraint carrying a named extension (destination constraints,
/// associated certificates).
pub const SSH_AGENT_CONSTRAIN_EXTENSION: u8 = 255;
/// Sign request flags asking for `rsa-sha2-256` / `rsa-sha2-512`.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// The hash a sign request asks for on an RSA key. `None` is plain
/// `ssh-rsa` (SHA-1), which the token cannot produce. When both flags are
/// set SHA-256 wins, as in OpenSSH's agent.
pub fn rsa_hash(flags: u32) -> Option<HashAlg> {
    if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        Some(HashAlg::Sha256)
    } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        Some(HashAlg::Sha512)
    } else {
        None
    }
}

/// Largest frame accepted from a client (OpenSSH uses the same bound).
pub const MAX_FRAME: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("empty request")]
    Empty,
    #[error("malformed request: {0}")]
    Malformed(#[from] ssh_encoding::Error),
    #[error(transparent)]
    Key(#[from] KeyDecodeError),
    #[error("unexpected trailing bytes in request")]
    TrailingData,
    #[error("unsupported key constraint {0:#04x}")]
    UnsupportedConstraint(u8),
    #[error("unsupported key constraint extension {0:?}")]
    UnsupportedExtension(String),
    #[error("key constraint {0} given twice")]
    DuplicateConstraint(&'static str),
    #[error(transparent)]
    Constraint(#[from] destination::ConstraintError),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    FrameTooLarge(usize),
}

/// A decoded client request.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// The SSH v1 identities request; answered with an empty list.
    RequestRsaIdentities,
    RequestIdentities,
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// `ssh-add FILE`: add a private key held in memory, or a FIDO credential
    /// signed by the device. `cert` is set when the add is for the key's
    /// certificate (`-cert.pub`) rather than the plain key. `lifetime` is the
    /// constraint from `ssh-add -t` (seconds), if any; `confirm` is the
    /// `ssh-add -c` constraint; `destination` the `ssh-add -h` constraint.
    AddIdentity {
        key: SignerRef,
        cert: Option<Box<CertKey>>,
        lifetime: Option<u32>,
        confirm: bool,
        destination: Vec<DestinationConstraint>,
    },
    /// `ssh-add -d FILE`: remove the identity with this public key blob.
    RemoveIdentity {
        key_blob: Vec<u8>,
    },
    /// `ssh-add -D`: remove every identity.
    RemoveAllIdentities,
    /// `ssh-add -x`: lock the agent with a passphrase.
    Lock(Zeroizing<Vec<u8>>),
    /// `ssh-add -X`: unlock it again.
    Unlock(Zeroizing<Vec<u8>>),
    /// `ssh-add -s`: add the key named by `provider`. `lifetime` is the
    /// constraint from `ssh-add -t` (seconds), if any; `pin` is accepted but
    /// unused. `certs` are the certificates given after the provider
    /// (`ssh-add -s PROVIDER CERT…`); `confirm` and `destination` are the
    /// `ssh-add -c` and `-h` constraints.
    AddSmartcardKey {
        provider: Vec<u8>,
        pin: Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
        confirm: bool,
        destination: Vec<DestinationConstraint>,
        certs: Option<AssociatedCerts>,
    },
    /// `ssh-add -e`: remove the key named by `provider`.
    RemoveSmartcardKey {
        provider: Vec<u8>,
    },
    /// A protocol extension: a name and the opaque payload after it. Answered
    /// by a registered [`Extension`](crate::extension::Extension), or with
    /// `SSH_AGENT_EXTENSION_FAILURE` when none matches.
    Extension {
        name: String,
        data: Vec<u8>,
    },
    /// Any message type this agent does not implement.
    Unsupported(u8),
}

impl Request {
    /// A short label for logs. `Debug` is not used for that, since it would
    /// print a lock passphrase.
    pub fn name(&self) -> &'static str {
        match self {
            Request::RequestRsaIdentities => "request-rsa-identities",
            Request::RequestIdentities => "request-identities",
            Request::Sign { .. } => "sign",
            Request::AddIdentity { .. } => "add-identity",
            Request::RemoveIdentity { .. } => "remove-identity",
            Request::RemoveAllIdentities => "remove-all-identities",
            Request::Lock(_) => "lock",
            Request::Unlock(_) => "unlock",
            Request::AddSmartcardKey { .. } => "add-smartcard-key",
            Request::RemoveSmartcardKey { .. } => "remove-smartcard-key",
            Request::Extension { .. } => "extension",
            Request::Unsupported(_) => "unsupported",
        }
    }

    /// Whether the request adds or removes keys, which a
    /// [`Policy`](crate::Policy) can forbid per connection.
    pub fn changes_keys(&self) -> bool {
        matches!(
            self,
            Request::AddIdentity { .. }
                | Request::RemoveIdentity { .. }
                | Request::RemoveAllIdentities
                | Request::AddSmartcardKey { .. }
                | Request::RemoveSmartcardKey { .. }
        )
    }
}

/// Decode one request body (without its length prefix), resolving key types
/// through the built-in [`KeyRegistry`] only. Use [`parse_request_with`] to
/// honour key types registered by a caller.
pub fn parse_request(body: &[u8]) -> Result<Request, WireError> {
    parse_request_with(&KeyRegistry::builtin(), body)
}

/// Decode one request body (without its length prefix), resolving the key type
/// of an `ADD_IDENTITY` request through `key_types`.
pub fn parse_request_with(key_types: &KeyRegistry, body: &[u8]) -> Result<Request, WireError> {
    let (&kind, mut rest) = body.split_first().ok_or(WireError::Empty)?;
    match kind {
        SSH_AGENTC_REQUEST_RSA_IDENTITIES => Ok(Request::RequestRsaIdentities),
        SSH2_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
        SSH2_AGENTC_ADD_IDENTITY => {
            let (key, cert) = decode_key(key_types, &mut rest)?;
            if !rest.is_empty() {
                return Err(WireError::TrailingData);
            }
            Ok(Request::AddIdentity {
                key,
                cert,
                lifetime: None,
                confirm: false,
                destination: Vec::new(),
            })
        }
        SSH2_AGENTC_ADD_ID_CONSTRAINED => {
            let (key, cert) = decode_key(key_types, &mut rest)?;
            let constraints = parse_constraints(&mut rest)?;
            // As in OpenSSH, certificates are associated only with a
            // provider's keys; a private key brings its own.
            if constraints.certs.is_some() {
                return Err(WireError::UnsupportedExtension(
                    cert::ASSOCIATED_CERTS.to_owned(),
                ));
            }
            Ok(Request::AddIdentity {
                key,
                cert,
                lifetime: constraints.lifetime,
                confirm: constraints.confirm,
                destination: constraints.destination,
            })
        }
        SSH2_AGENTC_REMOVE_IDENTITY => {
            let key_blob = Vec::<u8>::decode(&mut rest)?;
            Ok(Request::RemoveIdentity { key_blob })
        }
        SSH_AGENTC_REMOVE_ALL_IDENTITIES => Ok(Request::RemoveAllIdentities),
        SSH_AGENTC_ADD_SMARTCARD_KEY => {
            let provider = Vec::<u8>::decode(&mut rest)?;
            let pin = Zeroizing::new(Vec::<u8>::decode(&mut rest)?);
            Ok(Request::AddSmartcardKey {
                provider,
                pin,
                lifetime: None,
                confirm: false,
                destination: Vec::new(),
                certs: None,
            })
        }
        SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => {
            let provider = Vec::<u8>::decode(&mut rest)?;
            let pin = Zeroizing::new(Vec::<u8>::decode(&mut rest)?);
            let constraints = parse_constraints(&mut rest)?;
            Ok(Request::AddSmartcardKey {
                provider,
                pin,
                lifetime: constraints.lifetime,
                confirm: constraints.confirm,
                destination: constraints.destination,
                certs: constraints.certs,
            })
        }
        SSH_AGENTC_REMOVE_SMARTCARD_KEY => {
            let provider = Vec::<u8>::decode(&mut rest)?;
            // OpenSSH's client also sends the (empty) PIN; older clients did
            // not, so tolerate a missing trailing string.
            if !rest.is_empty() {
                let _pin = Vec::<u8>::decode(&mut rest)?;
            }
            Ok(Request::RemoveSmartcardKey { provider })
        }
        SSH_AGENTC_LOCK => Ok(Request::Lock(Zeroizing::new(Vec::decode(&mut rest)?))),
        SSH_AGENTC_UNLOCK => Ok(Request::Unlock(Zeroizing::new(Vec::decode(&mut rest)?))),
        SSH_AGENTC_EXTENSION => {
            let name = String::decode(&mut rest)?;
            Ok(Request::Extension {
                name,
                data: rest.to_vec(),
            })
        }
        SSH2_AGENTC_SIGN_REQUEST => {
            let key_blob = Vec::<u8>::decode(&mut rest)?;
            let data = Vec::<u8>::decode(&mut rest)?;
            let flags = u32::decode(&mut rest)?;
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            })
        }
        other => Ok(Request::Unsupported(other)),
    }
}

/// Decode the key of an add request: its type name, then the body, which
/// for a certificate type starts with the certificate.
fn decode_key(
    key_types: &KeyRegistry,
    rest: &mut &[u8],
) -> Result<(SignerRef, Option<Box<CertKey>>), WireError> {
    let key_type = String::decode(rest)?;
    if key_type.ends_with(cert::CERT_SUFFIX) {
        let (key, cert) = cert::decode_cert_add(key_types, &key_type, rest)?;
        Ok((key, Some(Box::new(cert))))
    } else {
        Ok((key_types.decode(&key_type, rest)?, None))
    }
}

/// The constraints of a constrained add.
#[derive(Debug, Default)]
struct Constraints {
    lifetime: Option<u32>,
    confirm: bool,
    destination: Vec<DestinationConstraint>,
    certs: Option<AssociatedCerts>,
}

/// Decode the constraint list that ends a constrained add. The lifetime,
/// confirm and destination constraints are understood, as is the
/// `sk-provider@openssh.com` extension `ssh-add` always attaches to a FIDO key
/// (whose value names the middleware library; this agent has its own, so it is
/// ignored) and the `associated-certs-v00@openssh.com` extension of
/// `ssh-add -s PROVIDER CERT…`. An unknown extension or constraint is
/// rejected so it is not silently dropped.
fn parse_constraints(rest: &mut &[u8]) -> Result<Constraints, WireError> {
    let mut constraints = Constraints::default();
    // As OpenSSH, a constraint given twice is refused rather than the later
    // one silently winning.
    let mut seen = Vec::new();
    let mut once = |name: &'static str| {
        if seen.contains(&name) {
            return Err(WireError::DuplicateConstraint(name));
        }
        seen.push(name);
        Ok(())
    };
    while !rest.is_empty() {
        let kind = u8::decode(rest)?;
        match kind {
            SSH_AGENT_CONSTRAIN_LIFETIME => {
                once("lifetime")?;
                constraints.lifetime = Some(u32::decode(rest)?);
            }
            SSH_AGENT_CONSTRAIN_CONFIRM => {
                once("confirm")?;
                constraints.confirm = true;
            }
            SSH_AGENT_CONSTRAIN_EXTENSION => {
                let name = String::decode(rest)?;
                if name == "sk-provider@openssh.com" {
                    once("sk-provider@openssh.com")?;
                    let _provider = String::decode(rest)?;
                } else if name == cert::ASSOCIATED_CERTS {
                    once(cert::ASSOCIATED_CERTS)?;
                    constraints.certs = Some(cert::parse_associated_certs(rest)?);
                } else if name == destination::RESTRICT_DESTINATION {
                    once(destination::RESTRICT_DESTINATION)?;
                    constraints.destination = destination::parse_constraints(rest)?;
                } else {
                    return Err(WireError::UnsupportedExtension(name));
                }
            }
            other => return Err(WireError::UnsupportedConstraint(other)),
        }
    }
    Ok(constraints)
}

/// One listed identity: a key or certificate blob and its comment.
pub type Listed = (Vec<u8>, String);

/// `SSH2_AGENT_IDENTITIES_ANSWER` listing `identities`.
pub fn identities_answer(identities: &[Listed]) -> Vec<u8> {
    let mut out = vec![SSH2_AGENT_IDENTITIES_ANSWER];
    (identities.len() as u32)
        .encode(&mut out)
        .expect("vec write");
    for (blob, comment) in identities {
        blob.encode(&mut out).expect("vec write");
        comment.encode(&mut out).expect("vec write");
    }
    out
}

/// The listing entry for a plain public key.
pub fn listed(key: &PublicKey) -> Listed {
    (key.to_bytes().expect("vec write"), key.comment().to_owned())
}

/// `SSH2_AGENT_SIGN_RESPONSE` carrying `sig`.
///
/// The `sk-` signature types put a one-byte flags field and a four-byte
/// counter after the signature string, and `ssh-key` 0.6.7 encodes that
/// trailer consistently only for `sk-ssh-ed25519`; for
/// `sk-ecdsa-sha2-nistp256` it folds the trailer into the signature string.
/// Both are written here per `PROTOCOL.u2f` so the reply decodes elsewhere.
pub fn sign_response(sig: &Signature) -> Vec<u8> {
    let mut blob = Vec::new();
    if matches!(
        sig.algorithm(),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
    ) {
        sig.algorithm().encode(&mut blob).expect("vec write");
        let body = sig.as_bytes();
        let split = body
            .len()
            .checked_sub(5)
            .expect("sk signature carries a trailer");
        body[..split].encode(&mut blob).expect("vec write");
        blob.extend_from_slice(&body[split..]);
    } else {
        sig.encode(&mut blob).expect("vec write");
    }
    let mut out = vec![SSH2_AGENT_SIGN_RESPONSE];
    blob.encode(&mut out).expect("vec write");
    out
}

pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

pub fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

/// `SSH_AGENT_RSA_IDENTITIES_ANSWER` with no keys: there are no SSH v1 keys.
pub fn rsa_identities_answer() -> Vec<u8> {
    vec![SSH_AGENT_RSA_IDENTITIES_ANSWER, 0, 0, 0, 0]
}

/// `SSH_AGENT_EXTENSION_FAILURE`, the reply to any extension request.
pub fn extension_failure() -> Vec<u8> {
    vec![SSH_AGENT_EXTENSION_FAILURE]
}

/// Read one length-prefixed frame. `None` at a clean EOF.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::Wire(WireError::FrameTooLarge(len)));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one length-prefixed frame.
pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> io::Result<()> {
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// What the data of a sign request is, as far as the agent can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedData {
    /// An SSH `publickey` userauth request (`SSH_MSG_USERAUTH_REQUEST`).
    UserAuth { user: String, service: String },
    /// An `ssh-keygen -Y sign` blob in the SSHSIG format.
    SshSig { namespace: String },
    /// Anything else.
    Other,
}

/// Recognise the userauth request blob and the SSHSIG format.
pub fn classify_data(data: &[u8]) -> SignedData {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        let mut r = rest;
        return match String::decode(&mut r) {
            Ok(namespace) => SignedData::SshSig { namespace },
            Err(_) => SignedData::Other,
        };
    }
    userauth_request(data).unwrap_or(SignedData::Other)
}

fn userauth_request(data: &[u8]) -> Option<SignedData> {
    let mut r = data;
    let _session_id = Vec::<u8>::decode(&mut r).ok()?;
    let msg_type = u8::decode(&mut r).ok()?;
    if msg_type != 50 {
        return None;
    }
    let user = String::decode(&mut r).ok()?;
    let service = String::decode(&mut r).ok()?;
    let method = String::decode(&mut r).ok()?;
    if method != "publickey" {
        return None;
    }
    Some(SignedData::UserAuth { user, service })
}

/// Human-readable summary of what a sign request covers, for the challenge
/// prompt. Understands the userauth request blob and the SSHSIG format.
pub fn describe_data(data: &[u8]) -> Option<String> {
    match classify_data(data) {
        SignedData::UserAuth { user, service } => Some(format!("{service} login as {user:?}")),
        SignedData::SshSig { namespace } => Some(format!("signature in namespace {namespace:?}")),
        SignedData::Other => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rsa_hash_follows_flags() {
        use super::*;
        assert_eq!(rsa_hash(0), None);
        assert_eq!(rsa_hash(SSH_AGENT_RSA_SHA2_256), Some(HashAlg::Sha256));
        assert_eq!(rsa_hash(SSH_AGENT_RSA_SHA2_512), Some(HashAlg::Sha512));
        assert_eq!(rsa_hash(6), Some(HashAlg::Sha256));
    }

    use super::*;
    use ssh_key::public::{Ed25519PublicKey, KeyData};

    fn key(byte: u8, comment: &str) -> PublicKey {
        PublicKey::new(KeyData::Ed25519(Ed25519PublicKey([byte; 32])), comment)
    }

    /// The constraint-extension bytes for one valid destination constraint:
    /// from the origin to `example.com`, identified by `key(7, "")`.
    fn destination_extension() -> Vec<u8> {
        let host_key = key(7, "");
        let mut hostkeys = Vec::new();
        host_key.to_bytes().unwrap().encode(&mut hostkeys).unwrap();
        0u8.encode(&mut hostkeys).unwrap();

        let mut from = Vec::new();
        "".encode(&mut from).unwrap();
        "".encode(&mut from).unwrap();
        Vec::<u8>::new().encode(&mut from).unwrap();

        let mut to = Vec::new();
        "".encode(&mut to).unwrap();
        "example.com".encode(&mut to).unwrap();
        Vec::<u8>::new().encode(&mut to).unwrap();
        to.extend_from_slice(&hostkeys);

        let mut constraint = Vec::new();
        from.encode(&mut constraint).unwrap();
        to.encode(&mut constraint).unwrap();
        Vec::<u8>::new().encode(&mut constraint).unwrap();

        let mut body = Vec::new();
        constraint.encode(&mut body).unwrap();

        let mut out = Vec::new();
        SSH_AGENT_CONSTRAIN_EXTENSION.encode(&mut out).unwrap();
        destination::RESTRICT_DESTINATION.encode(&mut out).unwrap();
        body.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn parses_request_identities() {
        assert_eq!(parse_request(&[11]).unwrap(), Request::RequestIdentities);
    }

    #[test]
    fn parses_sign_request_with_flags() {
        let mut body = vec![13u8];
        b"KEY".as_slice().encode(&mut body).unwrap();
        b"DATA".as_slice().encode(&mut body).unwrap();
        4u32.encode(&mut body).unwrap();
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::Sign {
                key_blob: b"KEY".to_vec(),
                data: b"DATA".to_vec(),
                flags: 4
            }
        );
        // Truncated flags are a malformed request.
        body.truncate(body.len() - 1);
        assert!(matches!(parse_request(&body), Err(WireError::Malformed(_))));
    }

    #[test]
    fn legacy_and_extension_requests() {
        assert_eq!(parse_request(&[1]).unwrap(), Request::RequestRsaIdentities);
        let mut ping = vec![SSH_AGENTC_EXTENSION];
        "ping".encode(&mut ping).unwrap();
        ping.extend_from_slice(&[1, 2]);
        assert_eq!(
            parse_request(&ping).unwrap(),
            Request::Extension {
                name: "ping".to_owned(),
                data: vec![1, 2],
            }
        );
        // A name with no payload is still a valid extension request.
        let mut empty = vec![SSH_AGENTC_EXTENSION];
        "query@openssh.com".encode(&mut empty).unwrap();
        assert_eq!(
            parse_request(&empty).unwrap(),
            Request::Extension {
                name: "query@openssh.com".to_owned(),
                data: Vec::new(),
            }
        );
        // A missing name string is malformed, not an extension failure.
        assert!(matches!(
            parse_request(&[SSH_AGENTC_EXTENSION]),
            Err(WireError::Malformed(_))
        ));
        assert_eq!(rsa_identities_answer(), vec![2, 0, 0, 0, 0]);
        assert_eq!(extension_failure(), vec![28]);
    }

    #[test]
    fn lock_requests_carry_the_passphrase() {
        let mut body = vec![SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut body).unwrap();
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::Lock(Zeroizing::new(b"hunter2".to_vec()))
        );
        body[0] = SSH_AGENTC_UNLOCK;
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::Unlock(Zeroizing::new(b"hunter2".to_vec()))
        );
        assert!(matches!(
            parse_request(&[SSH_AGENTC_LOCK, 0, 0]),
            Err(WireError::Malformed(_))
        ));
        assert_eq!(success(), vec![6]);
    }

    #[test]
    fn smartcard_add_and_remove_requests() {
        let mut body = vec![SSH_AGENTC_ADD_SMARTCARD_KEY];
        b"ferris@example.com".as_slice().encode(&mut body).unwrap();
        b"pin".as_slice().encode(&mut body).unwrap();
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::AddSmartcardKey {
                provider: b"ferris@example.com".to_vec(),
                pin: Zeroizing::new(b"pin".to_vec()),
                lifetime: None,
                confirm: false,
                destination: Vec::new(),
                certs: None,
            }
        );

        let mut constrained = body.clone();
        constrained[0] = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED;
        SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        60u32.encode(&mut constrained).unwrap();
        assert_eq!(
            parse_request(&constrained).unwrap(),
            Request::AddSmartcardKey {
                provider: b"ferris@example.com".to_vec(),
                pin: Zeroizing::new(b"pin".to_vec()),
                lifetime: Some(60),
                confirm: false,
                destination: Vec::new(),
                certs: None,
            }
        );

        // `ssh-add -c` asks for confirmation before each use; the constraint is
        // carried through for the signature path to honour.
        let mut confirm = constrained.clone();
        SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut confirm).unwrap();
        match parse_request(&confirm).unwrap() {
            Request::AddSmartcardKey { confirm, .. } => assert!(confirm),
            other => panic!("unexpected request {other:?}"),
        }

        // `ssh-add -h` attaches a destination constraint.
        let mut extension = body.clone();
        extension[0] = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED;
        extension.extend_from_slice(&destination_extension());
        match parse_request(&extension).unwrap() {
            Request::AddSmartcardKey { destination, .. } => {
                assert_eq!(destination.len(), 1);
                assert_eq!(destination[0].to.hostname.as_deref(), Some("example.com"));
            }
            other => panic!("unexpected request {other:?}"),
        }

        let mut unknown = body.clone();
        unknown[0] = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED;
        9u8.encode(&mut unknown).unwrap();
        assert!(matches!(
            parse_request(&unknown),
            Err(WireError::UnsupportedConstraint(9))
        ));

        let mut remove = vec![SSH_AGENTC_REMOVE_SMARTCARD_KEY];
        b"ferris@example.com"
            .as_slice()
            .encode(&mut remove)
            .unwrap();
        b"".as_slice().encode(&mut remove).unwrap();
        let want = Request::RemoveSmartcardKey {
            provider: b"ferris@example.com".to_vec(),
        };
        assert_eq!(parse_request(&remove).unwrap(), want);
        // A missing trailing PIN is tolerated for older clients.
        remove.truncate(remove.len() - 4);
        assert_eq!(parse_request(&remove).unwrap(), want);
    }

    #[test]
    fn add_and_remove_identity_requests() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use ssh_key::private::Ed25519Keypair;

        let pair = Ed25519Keypair::from_seed(&[0x11; 32]);
        let public = PublicKey::new(KeyData::Ed25519(pair.public), "ferris@example.com");
        let blob = public.to_bytes().unwrap();

        let mut add = vec![SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519".encode(&mut add).unwrap();
        pair.encode(&mut add).unwrap();
        "ferris@example.com".encode(&mut add).unwrap();
        match parse_request(&add).unwrap() {
            Request::AddIdentity {
                key,
                cert,
                lifetime,
                ..
            } => {
                assert_eq!(key.public_key().comment(), "ferris@example.com");
                assert_eq!(key.key_blob(), blob);
                assert_eq!(cert, None);
                assert_eq!(lifetime, None);
            }
            other => panic!("unexpected request {other:?}"),
        }

        // Trailing bytes after the comment are rejected.
        let mut trailing = add.clone();
        trailing.push(0);
        assert!(matches!(
            parse_request(&trailing),
            Err(WireError::TrailingData)
        ));

        // The constrained add carries a lifetime.
        let mut constrained = add.clone();
        constrained[0] = SSH2_AGENTC_ADD_ID_CONSTRAINED;
        SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        60u32.encode(&mut constrained).unwrap();
        match parse_request(&constrained).unwrap() {
            Request::AddIdentity { lifetime, .. } => assert_eq!(lifetime, Some(60)),
            other => panic!("unexpected request {other:?}"),
        }
        // A confirm constraint is carried through for the signature path.
        let mut confirm = constrained;
        SSH_AGENT_CONSTRAIN_CONFIRM.encode(&mut confirm).unwrap();
        match parse_request(&confirm).unwrap() {
            Request::AddIdentity { confirm, .. } => assert!(confirm),
            other => panic!("unexpected request {other:?}"),
        }

        // Security keys need a decoder from the agent's owner: the built-in
        // registry does not know them.
        use ssh_key::private::SkEd25519;
        use ssh_key::public::SkEd25519 as SkEd25519Public;
        let public = SkEd25519Public::new(Ed25519PublicKey([0x42; 32]), "ssh:");
        let sk_pair = SkEd25519::new(public, 0x01, [1u8, 2, 3]).unwrap();
        let mut sk = vec![SSH2_AGENTC_ADD_IDENTITY];
        "sk-ssh-ed25519@openssh.com".encode(&mut sk).unwrap();
        sk_pair.encode(&mut sk).unwrap();
        "ferris@example.com".encode(&mut sk).unwrap();
        assert!(matches!(
            parse_request(&sk),
            Err(WireError::Key(KeyDecodeError::UnsupportedType(_)))
        ));

        // The `sk-provider@openssh.com` extension `ssh-add` attaches to FIDO
        // keys is accepted and ignored.
        let mut constrained = add.clone();
        constrained[0] = SSH2_AGENTC_ADD_ID_CONSTRAINED;
        SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut constrained)
            .unwrap();
        "sk-provider@openssh.com".encode(&mut constrained).unwrap();
        "internal".encode(&mut constrained).unwrap();
        assert!(matches!(
            parse_request(&constrained).unwrap(),
            Request::AddIdentity { .. }
        ));

        // A supported type with a malformed body is likewise a decode
        // error, not a crash.
        let mut ecdsa = vec![SSH2_AGENTC_ADD_IDENTITY];
        "ecdsa-sha2-nistp256".encode(&mut ecdsa).unwrap();
        assert!(matches!(
            parse_request(&ecdsa),
            Err(WireError::Key(KeyDecodeError::Malformed(
                "ecdsa-sha2-nistp256"
            )))
        ));

        // DSA is only a known key type with the `dsa` feature.
        let mut dss = vec![SSH2_AGENTC_ADD_IDENTITY];
        "ssh-dss".encode(&mut dss).unwrap();
        #[cfg(feature = "dsa")]
        assert!(matches!(
            parse_request(&dss),
            Err(WireError::Key(KeyDecodeError::Malformed("ssh-dss")))
        ));
        #[cfg(not(feature = "dsa"))]
        assert!(matches!(
            parse_request(&dss),
            Err(WireError::Key(KeyDecodeError::UnsupportedType(_)))
        ));

        // An `ssh-rsa` add is decoded into a local key.
        let sk =
            rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../tests/data/rsa2048.pem")).unwrap();
        let rsa_pair = ssh_key::private::RsaKeypair::try_from(&sk).unwrap();
        let mut rsa = vec![SSH2_AGENTC_ADD_IDENTITY];
        "ssh-rsa".encode(&mut rsa).unwrap();
        rsa_pair.encode(&mut rsa).unwrap();
        "old@example.com".encode(&mut rsa).unwrap();
        match parse_request(&rsa).unwrap() {
            Request::AddIdentity { key, lifetime, .. } => {
                assert_eq!(key.public_key().comment(), "old@example.com");
                assert_eq!(
                    key.public_key().algorithm(),
                    ssh_key::Algorithm::Rsa { hash: None }
                );
                assert_eq!(lifetime, None);
            }
            other => panic!("unexpected request {other:?}"),
        }

        let mut remove = vec![SSH2_AGENTC_REMOVE_IDENTITY];
        blob.encode(&mut remove).unwrap();
        assert_eq!(
            parse_request(&remove).unwrap(),
            Request::RemoveIdentity { key_blob: blob }
        );
        assert_eq!(
            parse_request(&[SSH_AGENTC_REMOVE_ALL_IDENTITIES]).unwrap(),
            Request::RemoveAllIdentities
        );
    }

    #[test]
    fn certificate_adds_and_associated_certs() {
        use crate::testing::{cert_body, certify};
        use ssh_key::private::Ed25519Keypair;

        let pair = Ed25519Keypair::from_seed(&[0x11; 32]);
        let cert = certify(&KeyData::Ed25519(pair.public));
        let mut private = Vec::new();
        pair.encode(&mut private).unwrap();
        let mut add = vec![SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519-cert-v01@openssh.com".encode(&mut add).unwrap();
        add.extend(cert_body(&cert, &private, "ferris@example.com"));
        match parse_request(&add).unwrap() {
            Request::AddIdentity {
                key,
                cert: Some(got),
                lifetime: None,
                ..
            } => {
                assert_eq!(*got, cert);
                assert_eq!(key.public_key().comment(), "ferris@example.com");
            }
            other => panic!("unexpected request {other:?}"),
        }

        let mut associated = Vec::new();
        SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut associated)
            .unwrap();
        cert::ASSOCIATED_CERTS.encode(&mut associated).unwrap();
        0u8.encode(&mut associated).unwrap();
        let mut list = Vec::new();
        cert.blob().encode(&mut list).unwrap();
        list.encode(&mut associated).unwrap();

        let mut card = vec![SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED];
        b"ferris@example.com".as_slice().encode(&mut card).unwrap();
        b"".as_slice().encode(&mut card).unwrap();
        card.extend_from_slice(&associated);
        match parse_request(&card).unwrap() {
            Request::AddSmartcardKey {
                certs: Some(certs), ..
            } => {
                assert!(!certs.certs_only);
                assert_eq!(certs.certs, vec![cert.clone()]);
            }
            other => panic!("unexpected request {other:?}"),
        }

        // A private key add cannot carry associated certificates.
        let mut constrained = add;
        constrained[0] = SSH2_AGENTC_ADD_ID_CONSTRAINED;
        constrained.extend_from_slice(&associated);
        assert!(matches!(
            parse_request(&constrained),
            Err(WireError::UnsupportedExtension(name)) if name == cert::ASSOCIATED_CERTS
        ));
    }

    #[test]
    fn request_names_do_not_leak_secrets() {
        let lock = Request::Lock(b"hunter2".to_vec().into());
        assert_eq!(lock.name(), "lock");
        assert_eq!(Request::Unlock(b"hunter2".to_vec().into()).name(), "unlock");
        assert_eq!(Request::RemoveAllIdentities.name(), "remove-all-identities");
        assert_eq!(Request::Unsupported(200).name(), "unsupported");
    }

    #[test]
    fn unknown_and_empty_requests() {
        assert_eq!(
            parse_request(&[200, 1, 2]).unwrap(),
            Request::Unsupported(200)
        );
        // A truncated identity add is a local-key error, not a panic.
        assert!(matches!(
            parse_request(&[SSH2_AGENTC_ADD_IDENTITY, 1, 2]),
            Err(WireError::Malformed(_))
        ));
        assert!(matches!(parse_request(&[]), Err(WireError::Empty)));
    }

    #[test]
    fn identities_answer_layout() {
        let keys = [key(1, "one"), key(2, "two")];
        let out = identities_answer(&keys.iter().map(listed).collect::<Vec<_>>());
        assert_eq!(out[0], 12);
        assert_eq!(&out[1..5], &2u32.to_be_bytes());
        let mut r = &out[5..];
        for k in &keys {
            let blob = Vec::<u8>::decode(&mut r).unwrap();
            assert_eq!(blob, k.to_bytes().unwrap());
            let comment = String::decode(&mut r).unwrap();
            assert_eq!(comment, k.comment());
        }
        assert!(r.is_empty());
        assert_eq!(identities_answer(&[]), vec![12, 0, 0, 0, 0]);
    }

    #[test]
    fn sign_response_wraps_signature_blob() {
        let sig = Signature::new(ssh_key::Algorithm::Ed25519, vec![9u8; 64]).unwrap();
        let out = sign_response(&sig);
        assert_eq!(out[0], 14);
        let mut r = &out[1..];
        let blob = Vec::<u8>::decode(&mut r).unwrap();
        assert!(r.is_empty());
        let mut b = blob.as_slice();
        assert_eq!(String::decode(&mut b).unwrap(), "ssh-ed25519");
        assert_eq!(Vec::<u8>::decode(&mut b).unwrap(), vec![9u8; 64]);
    }

    /// An `sk-ecdsa` signature carries its flags/counter after the signature
    /// string. `ssh-key` 0.6.7 writes them inside the string, so the agent
    /// encodes the reply itself; it must decode back unchanged.
    #[test]
    fn sign_response_encodes_sk_ecdsa_per_u2f_spec() {
        use ssh_key::Mpint;
        let mut data = Vec::new();
        Mpint::from_positive_bytes(&[0x01; 32])
            .unwrap()
            .encode(&mut data)
            .unwrap();
        Mpint::from_positive_bytes(&[0x02; 32])
            .unwrap()
            .encode(&mut data)
            .unwrap();
        data.push(0x01);
        data.extend_from_slice(&7u32.to_be_bytes());
        let sig = Signature::new(Algorithm::SkEcdsaSha2NistP256, data).unwrap();

        let reply = sign_response(&sig);
        assert_eq!(reply[0], SSH2_AGENT_SIGN_RESPONSE);
        let mut r = &reply[1..];
        let blob = Vec::<u8>::decode(&mut r).unwrap();
        let decoded = Signature::try_from(blob.as_slice()).unwrap();
        assert_eq!(decoded.algorithm(), Algorithm::SkEcdsaSha2NistP256);
        assert_eq!(decoded.as_bytes(), sig.as_bytes());
    }

    #[test]
    fn frames_round_trip_and_reject_oversize() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(buf, b"\x00\x00\x00\x05hello");
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r).unwrap(), None);

        let huge = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_frame(&mut huge.as_slice()),
            Err(FrameError::Wire(WireError::FrameTooLarge(_)))
        ));
        assert!(read_frame(&mut b"\x00\x00\x00\x05hel".as_slice()).is_err());
    }

    #[test]
    fn describes_userauth_and_sshsig() {
        let mut blob = Vec::new();
        [1u8; 32].as_slice().encode(&mut blob).unwrap();
        50u8.encode(&mut blob).unwrap();
        "ferris".encode(&mut blob).unwrap();
        "ssh-connection".encode(&mut blob).unwrap();
        "publickey".encode(&mut blob).unwrap();
        assert_eq!(
            describe_data(&blob).unwrap(),
            "ssh-connection login as \"ferris\""
        );

        let mut sshsig = b"SSHSIG".to_vec();
        "git".encode(&mut sshsig).unwrap();
        assert_eq!(
            describe_data(&sshsig).unwrap(),
            "signature in namespace \"git\""
        );

        assert_eq!(describe_data(b"garbage"), None);
    }
}
