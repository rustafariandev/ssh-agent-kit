//! OpenSSH certificates (`PROTOCOL.certkeys`) the agent serves alongside its
//! keys.
//!
//! A certificate is listed as an identity of its own and signs with the key it
//! certifies, as in OpenSSH's agent. It reaches the agent three ways:
//!
//! - `ssh-add FILE` sends the `-cert.pub` next to a private key as an
//!   `ADD_IDENTITY` whose key type is `<type>-cert-v01@openssh.com` (decoded by
//!   [`decode_cert_add`]);
//! - `ssh-add -s IDENTITY CERT…` attaches certificates to a token key through
//!   the `associated-certs-v00@openssh.com` constraint
//!   ([`parse_associated_certs`]);
//! - the agent's owner loads them at startup ([`CertKey::read_file`],
//!   [`Agent::with_certificates`](crate::Agent::with_certificates)).
//!
//! Every certificate's CA signature is checked when it is loaded, as OpenSSH
//! does; whether the CA is trusted is for the server to decide.

use crate::keytype::{KeyDecodeError, KeyRegistry};
use crate::signer::{self, SignerRef};
use ssh_encoding::base64::{Base64, Encoding};
use ssh_encoding::{Decode, Encode};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Certificate, PublicKey, Signature};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Suffix of every OpenSSH certificate key type.
pub const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// The constraint `ssh-add -s` uses to attach certificates to a provider's keys.
pub const ASSOCIATED_CERTS: &str = "associated-certs-v00@openssh.com";

#[derive(Debug, Error)]
pub enum CertError {
    #[error("malformed certificate")]
    Malformed,
    #[error("certificate's CA signature does not verify")]
    BadSignature,
    #[error("certificate does not certify the key it was added with")]
    KeyMismatch,
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}:{line}: {source}")]
    Line {
        path: PathBuf,
        line: usize,
        source: Box<CertError>,
    },
}

/// A certificate, kept with the exact bytes it arrived in so sign and remove
/// requests (which name it by those bytes) match, and it is listed unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertKey {
    cert: Certificate,
    blob: Vec<u8>,
    /// The comment of the `-cert.pub` line it was read from, if any.
    comment: String,
}

impl CertKey {
    /// Parse a binary certificate and check its CA signature.
    pub fn from_blob(blob: &[u8]) -> Result<Self, CertError> {
        let cert = Certificate::from_bytes(blob)
            .or_else(|e| {
                let clamped = clamp_validity(blob).ok_or(e)?;
                Certificate::from_bytes(&clamped)
            })
            .map_err(|_| CertError::Malformed)?;
        verify_ca_signature(&cert, blob)?;
        Ok(CertKey {
            cert,
            blob: blob.to_vec(),
            comment: String::new(),
        })
    }

    /// Parse one line of a `-cert.pub` file: `<type> <base64> [comment]`.
    pub fn from_openssh_line(line: &str) -> Result<Self, CertError> {
        let mut fields = line.split_whitespace();
        let key_type = fields.next().ok_or(CertError::Malformed)?;
        let data = fields.next().ok_or(CertError::Malformed)?;
        if !key_type.ends_with(CERT_SUFFIX) {
            return Err(CertError::Malformed);
        }
        let blob = Base64::decode_vec(data).map_err(|_| CertError::Malformed)?;
        let mut key = Self::from_blob(&blob)?;
        if key.cert.algorithm().to_certificate_type() != key_type {
            return Err(CertError::Malformed);
        }
        key.comment = fields.collect::<Vec<_>>().join(" ");
        Ok(key)
    }

    /// Every certificate in `path`, one per line; blank lines and `#`
    /// comments are skipped.
    pub fn read_file(path: &Path) -> Result<Vec<Self>, CertError> {
        let text = std::fs::read_to_string(path).map_err(|source| CertError::Read {
            path: path.to_owned(),
            source,
        })?;
        text.lines()
            .enumerate()
            .map(|(n, line)| (n + 1, line.trim()))
            .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
            .map(|(n, line)| {
                Self::from_openssh_line(line).map_err(|e| CertError::Line {
                    path: path.to_owned(),
                    line: n,
                    source: Box::new(e),
                })
            })
            .collect()
    }

    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// The certificate's wire blob, as listed and as sign requests name it.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The comment of the `-cert.pub` line, empty for a certificate that
    /// came over the wire.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// The key the certificate certifies.
    pub fn public_key(&self) -> &KeyData {
        self.cert.public_key()
    }

    /// Whether `key` is the key the certificate certifies.
    pub fn certifies(&self, key: &PublicKey) -> bool {
        key.key_data() == self.public_key()
    }

    /// Whether the certificate's validity has ended.
    pub fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        now >= self.cert.valid_before()
    }

    /// The certificate in `-cert.pub` form, with `comment`.
    pub fn to_openssh(&self, comment: &str) -> String {
        let mut line = format!(
            "{} {}",
            self.cert.algorithm().to_certificate_type(),
            Base64::encode_string(&self.blob)
        );
        if !comment.is_empty() {
            line.push(' ');
            line.push_str(comment);
        }
        line
    }
}

/// `blob` with validity times past `i64::MAX` lowered to it, or `None` if
/// none are (or the blob does not get that far).
///
/// `ssh-keygen -s` without `-V` writes a certificate valid forever, whose
/// `valid_before` is `2^64 - 1`; `ssh-key` 0.6.7 refuses any time above
/// `i64::MAX`. The parse uses the lowered copy, which changes nothing in
/// practice, while the CA signature is still checked over the original.
fn clamp_validity(blob: &[u8]) -> Option<Vec<u8>> {
    const MAX: u64 = i64::MAX as u64;
    let mut r = blob;
    let base = Algorithm::new_certificate(&String::decode(&mut r).ok()?).ok()?;
    Vec::<u8>::decode(&mut r).ok()?; // nonce
    // The certified key's fields, read as a plain key of the base type.
    let mut key = Vec::new();
    base.as_str().encode(&mut key).ok()?;
    let header = key.len();
    key.extend_from_slice(r);
    let mut k = key.as_slice();
    KeyData::decode(&mut k).ok()?;
    r = &r[key.len() - header - k.len()..];
    u64::decode(&mut r).ok()?; // serial
    u32::decode(&mut r).ok()?; // type
    String::decode(&mut r).ok()?; // key id
    Vec::<u8>::decode(&mut r).ok()?; // principals
    let at = blob.len() - r.len();
    let mut out = blob.get(..at + 16)?.to_vec();
    let mut clamped = false;
    for field in out[at..].as_chunks_mut::<8>().0 {
        if u64::from_be_bytes(*field) > MAX {
            field.copy_from_slice(&MAX.to_be_bytes());
            clamped = true;
        }
    }
    out.extend_from_slice(&blob[at + 16..]);
    clamped.then_some(out)
}

/// Check the CA's signature over the certificate. The signed part is the blob
/// up to the final signature string.
fn verify_ca_signature(cert: &Certificate, blob: &[u8]) -> Result<(), CertError> {
    let sig_len = cert
        .signature()
        .encoded_len_prefixed()
        .map_err(|_| CertError::Malformed)?;
    let signed = blob
        .len()
        .checked_sub(sig_len)
        .map(|end| &blob[..end])
        .ok_or(CertError::Malformed)?;
    let ca = PublicKey::from(cert.signature_key().clone());
    let sig: &Signature = cert.signature();
    signer::verify(&ca, signed, sig).map_err(|_| CertError::BadSignature)
}

/// Decode the body of an `ADD_IDENTITY` request for a certificate key type:
/// the certificate blob, then the private fields, then the comment.
///
/// OpenSSH leaves out of that body the public fields the certificate already
/// carries, except for `ssh-ed25519`, whose private fields always start with
/// the public key. So the public fields are taken from the certificate and put
/// in front of the rest, and the plain key type's decoder in `registry` reads
/// the result as it would an ordinary add.
pub fn decode_cert_add(
    registry: &KeyRegistry,
    key_type: &str,
    reader: &mut &[u8],
) -> Result<(SignerRef, CertKey), KeyDecodeError> {
    let blob = Vec::<u8>::decode(reader).map_err(|_| malformed())?;
    let cert = CertKey::from_blob(&blob).map_err(|e| {
        tracing::warn!(error = %e, "refusing certificate");
        malformed()
    })?;
    if cert.certificate().algorithm().to_certificate_type() != key_type {
        return Err(malformed());
    }
    let algorithm = cert.public_key().algorithm();
    let base = algorithm.as_str();
    // The copy holds the private key: wipe it after.
    let mut body = Zeroizing::new(if base == "ssh-ed25519" {
        Vec::new()
    } else {
        public_fields(cert.public_key()).ok_or_else(malformed)?
    });
    let prefix = body.len();
    body.extend_from_slice(reader);
    let mut rest = body.as_slice();
    let key = registry.decode(base, &mut rest)?;
    let consumed = body.len() - rest.len();
    if consumed < prefix {
        return Err(malformed());
    }
    *reader = &reader[consumed - prefix..];
    if key.public_key().key_data() != cert.public_key() {
        tracing::warn!(error = %CertError::KeyMismatch, "refusing certificate");
        return Err(malformed());
    }
    Ok((key, cert))
}

/// The public fields that start `key`'s private body in a plain add: its
/// wire encoding without the leading key type string, except that RSA's
/// private body puts the modulus before the exponent.
fn public_fields(key: &KeyData) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if let KeyData::Rsa(rsa) = key {
        rsa.n.encode(&mut out).ok()?;
        rsa.e.encode(&mut out).ok()?;
        return Some(out);
    }
    key.encode(&mut out).ok()?;
    let mut r = out.as_slice();
    String::decode(&mut r).ok()?;
    Some(r.to_vec())
}

fn malformed() -> KeyDecodeError {
    KeyDecodeError::Malformed("certificate")
}

/// The `associated-certs-v00@openssh.com` constraint of `ssh-add -s CERT…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociatedCerts {
    /// `ssh-add -C`: serve only the certificates, not the plain key.
    pub certs_only: bool,
    pub certs: Vec<CertKey>,
}

/// Decode the constraint's value (after its name): a boolean, then a string
/// holding the certificate blobs, each itself a string.
pub fn parse_associated_certs(reader: &mut &[u8]) -> Result<AssociatedCerts, KeyDecodeError> {
    let certs_only = u8::decode(reader).map_err(|_| malformed())? != 0;
    let list = Vec::<u8>::decode(reader).map_err(|_| malformed())?;
    let mut r = list.as_slice();
    let mut certs = Vec::new();
    while !r.is_empty() {
        let blob = Vec::<u8>::decode(&mut r).map_err(|_| malformed())?;
        let cert = CertKey::from_blob(&blob).map_err(|e| {
            tracing::warn!(error = %e, "refusing certificate");
            malformed()
        })?;
        certs.push(cert);
    }
    Ok(AssociatedCerts { certs_only, certs })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ssh_key::PrivateKey;
    use ssh_key::certificate::Builder;
    use ssh_key::private::Ed25519Keypair;

    pub(crate) use crate::testing::{certify, certify_until};

    fn ed25519(seed: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_seed(&[seed; 32])
    }

    #[test]
    fn blobs_and_lines_round_trip() {
        let cert = certify(&KeyData::Ed25519(ed25519(1).public));
        let line = cert.to_openssh("ferris@example.com");
        assert!(line.starts_with("ssh-ed25519-cert-v01@openssh.com "));
        assert!(line.ends_with(" ferris@example.com"));
        let parsed = CertKey::from_openssh_line(&line).unwrap();
        assert_eq!(parsed.blob(), cert.blob());
        assert_eq!(parsed.comment(), "ferris@example.com");
        assert!(!cert.expired());
        assert!(certify_until(&KeyData::Ed25519(ed25519(1).public), 1).expired());
        // A plain public key line is not a certificate.
        let plain = PublicKey::new(KeyData::Ed25519(ed25519(1).public), "");
        assert!(CertKey::from_openssh_line(&plain.to_openssh().unwrap()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("certs");
        std::fs::write(&path, format!("# mine\n\n{line}\n")).unwrap();
        assert_eq!(CertKey::read_file(&path).unwrap(), vec![parsed]);
        std::fs::write(&path, "garbage\n").unwrap();
        assert!(matches!(
            CertKey::read_file(&path),
            Err(CertError::Line { line: 1, .. })
        ));
    }

    /// `ssh-keygen -s` without `-V` makes a certificate valid forever, with a
    /// `valid_before` that `ssh-key` alone refuses to parse.
    #[test]
    fn a_certificate_valid_forever_is_accepted() {
        let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[0xCA; 32]));
        let key = KeyData::Ed25519(ed25519(1).public);
        let mut builder = Builder::new([7u8; 16], key, 0, 1).unwrap();
        builder.valid_principal("ferris").unwrap();
        let blob = builder.sign(&ca).unwrap().to_bytes().unwrap();
        // Rewrite valid_before (the 8 bytes before the critical options,
        // which here are empty, as are the extensions and reserved field)
        // and sign again over the result, as ssh-keygen would.
        let sig_len = Certificate::from_bytes(&blob)
            .unwrap()
            .signature()
            .encoded_len_prefixed()
            .unwrap();
        let mut tbs = blob[..blob.len() - sig_len].to_vec();
        let ca_len = ca.public_key().key_data().encoded_len_prefixed().unwrap();
        let at = tbs.len() - ca_len - 12 - 8;
        tbs[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        let sig: Signature = signature::Signer::sign(&ca, &tbs);
        let mut forever = tbs;
        sig.encode_prefixed(&mut forever).unwrap();
        assert!(
            Certificate::from_bytes(&forever).is_err(),
            "ssh-key refuses it"
        );

        let cert = CertKey::from_blob(&forever).unwrap();
        assert_eq!(cert.blob(), forever);
        assert!(!cert.expired());
        assert!(matches!(
            CertKey::from_blob(&blob[..blob.len() - 1]),
            Err(CertError::Malformed)
        ));
    }

    #[test]
    fn a_tampered_certificate_is_refused() {
        let cert = certify(&KeyData::Ed25519(ed25519(1).public));
        let mut blob = cert.blob().to_vec();
        // The last byte belongs to the CA's signature.
        *blob.last_mut().unwrap() ^= 1;
        assert!(matches!(
            CertKey::from_blob(&blob),
            Err(CertError::BadSignature)
        ));
        assert!(matches!(
            CertKey::from_blob(&blob[..10]),
            Err(CertError::Malformed)
        ));
    }

    use crate::testing::cert_body;

    fn decode(key_type: &str, body: &[u8]) -> Result<(SignerRef, CertKey), KeyDecodeError> {
        let mut r = body;
        let out = decode_cert_add(&KeyRegistry::builtin(), key_type, &mut r)?;
        assert!(r.is_empty());
        Ok(out)
    }

    #[test]
    fn decodes_an_ed25519_certificate_add() {
        let pair = ed25519(1);
        let cert = certify(&KeyData::Ed25519(pair.public));
        let mut private = Vec::new();
        pair.encode(&mut private).unwrap();
        let body = cert_body(&cert, &private, "ferris@example.com");
        let (key, got) = decode("ssh-ed25519-cert-v01@openssh.com", &body).unwrap();
        assert_eq!(got, cert);
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        assert!(cert.certifies(key.public_key()));

        // The private key must be the certified one.
        let mut other = Vec::new();
        ed25519(2).encode(&mut other).unwrap();
        let body = cert_body(&cert, &other, "");
        assert!(decode("ssh-ed25519-cert-v01@openssh.com", &body).is_err());
        // And the type must name the certificate's.
        let body = cert_body(&cert, &private, "");
        assert!(decode("ssh-rsa-cert-v01@openssh.com", &body).is_err());
    }

    #[test]
    fn decodes_an_rsa_certificate_add() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::traits::PrivateKeyParts;
        use ssh_key::Mpint;
        let sk =
            rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../tests/data/rsa2048.pem")).unwrap();
        let pair = ssh_key::private::RsaKeypair::try_from(&sk).unwrap();
        let cert = certify(&KeyData::Rsa(pair.public.clone()));
        // Without the public `n e`: `d iqmp p q`.
        let mpint = |n: &rsa::BigUint| Mpint::from_positive_bytes(&n.to_bytes_be()).unwrap();
        let mut private = Vec::new();
        mpint(sk.d()).encode(&mut private).unwrap();
        pair.private.iqmp.encode(&mut private).unwrap();
        mpint(&sk.primes()[0]).encode(&mut private).unwrap();
        mpint(&sk.primes()[1]).encode(&mut private).unwrap();
        let body = cert_body(&cert, &private, "old@example.com");
        let (key, _) = decode("ssh-rsa-cert-v01@openssh.com", &body).unwrap();
        assert!(cert.certifies(key.public_key()));
        assert_eq!(key.public_key().comment(), "old@example.com");
    }

    #[test]
    fn decodes_an_ecdsa_certificate_add() {
        use ssh_key::private::EcdsaKeypair;
        let pair =
            EcdsaKeypair::random(&mut rand_core::OsRng, ssh_key::EcdsaCurve::NistP256).unwrap();
        let cert = certify(&KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::from(
            &pair,
        )));
        // Without the curve and point: just the scalar.
        let EcdsaKeypair::NistP256 {
            private: scalar, ..
        } = &pair
        else {
            unreachable!()
        };
        let mut private = Vec::new();
        scalar.encode(&mut private).unwrap();
        let body = cert_body(&cert, &private, "");
        let (key, _) = decode("ecdsa-sha2-nistp256-cert-v01@openssh.com", &body).unwrap();
        assert!(cert.certifies(key.public_key()));
    }

    #[test]
    fn parses_associated_certificates() {
        let one = certify(&KeyData::Ed25519(ed25519(1).public));
        let two = certify(&KeyData::Ed25519(ed25519(2).public));
        let mut list = Vec::new();
        one.blob().encode(&mut list).unwrap();
        two.blob().encode(&mut list).unwrap();
        let mut body = vec![1u8];
        list.encode(&mut body).unwrap();
        let mut r = body.as_slice();
        let got = parse_associated_certs(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(
            got,
            AssociatedCerts {
                certs_only: true,
                certs: vec![one, two]
            }
        );
        assert!(parse_associated_certs(&mut [0u8].as_slice()).is_err());
    }
}
