//! Local (software) private keys the agent holds in memory.
//!
//! A [`LocalKey`] is a private key the agent signs with directly, with no
//! device and no challenge. Keys arrive over the agent protocol as an
//! `SSH2_AGENTC_ADD_IDENTITY` request (`ssh-add ~/.ssh/id_ed25519`); see
//! [`crate::wire`]. New key types are added by implementing [`LocalKey`]
//! and a [`KeyDecoder`](crate::keytype::KeyDecoder) registered on the agent,
//! without touching the server.

use crate::keytype::KeyDecodeError;
use crate::signer::{self, BoxError, VerifyError};
use rand_core::OsRng;
use rsa::Pkcs1v15Sign;
use sha2::{Digest, Sha256, Sha512};
use signature::Signer;
use ssh_encoding::{Decode, Encode, Reader};
#[cfg(feature = "dsa")]
use ssh_key::private::DsaKeypair;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
#[cfg(feature = "dsa")]
use ssh_key::public::DsaPublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Mpint, PublicKey, Signature};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Why a local key could not sign.
#[derive(Debug, Error)]
pub enum LocalKeyError {
    #[error("signing with a local key failed: {0}")]
    Sign(#[from] signature::Error),
    #[error("cannot encode the signature: {0}")]
    Signature(#[from] ssh_key::Error),
    #[error("RSA signing failed: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("cannot sign with an unsupported RSA digest")]
    UnsupportedHash,
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// A private key held in memory that the agent signs with itself, with no
/// device and no challenge.
///
/// Implementations should not expose the secret half through `fmt::Debug`.
pub trait LocalKey: Send + Sync {
    /// The matching public key. Its comment is the identity the agent lists.
    fn public_key(&self) -> &PublicKey;

    /// Sign `data` in software, returning a complete SSH signature. `hash`
    /// selects the RSA digest (`sha2-256` or `sha2-512`); other key types
    /// ignore it.
    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError>;

    /// Check `sig` over `data` against [`Self::public_key`]. The agent calls
    /// this after every [`Self::sign`], so a faulty signature never leaves.
    fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), LocalKeyError> {
        Ok(signer::verify(self.public_key(), data, sig)?)
    }

    /// Wire blob used to match sign and remove requests.
    fn key_blob(&self) -> Vec<u8> {
        self.public_key().to_bytes().expect("vec write")
    }
}

/// A boxed [`LocalKey`] with value semantics.
///
/// `PartialEq`/`Eq` compare only the public key, so a request that carries a
/// trait object can still derive them; `Debug` shows the public key only.
pub struct LocalKeyRef(Box<dyn LocalKey>);

impl LocalKeyRef {
    pub fn new(key: impl LocalKey + 'static) -> Self {
        LocalKeyRef(Box::new(key))
    }

    pub fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    pub fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError> {
        self.0.sign(data, hash)
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), LocalKeyError> {
        self.0.verify(data, sig)
    }

    pub fn key_blob(&self) -> Vec<u8> {
        self.0.key_blob()
    }

    pub fn comment(&self) -> &str {
        self.0.public_key().comment()
    }

    pub fn into_inner(self) -> Box<dyn LocalKey> {
        self.0
    }
}

impl fmt::Debug for LocalKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalKeyRef")
            .field(self.0.public_key())
            .finish()
    }
}

impl PartialEq for LocalKeyRef {
    fn eq(&self, other: &Self) -> bool {
        self.0.key_blob() == other.0.key_blob()
    }
}

impl Eq for LocalKeyRef {}

/// A local key signs in software, and checks signatures with its own
/// [`LocalKey::verify`].
impl signer::Signer for LocalKeyRef {
    fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        let sig = self.0.sign(data, hash)?;
        tracing::info!(comment = self.comment(), "signed with local key");
        Ok(sig)
    }

    fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), BoxError> {
        Ok(self.0.verify(data, sig)?)
    }

    fn key_blob(&self) -> Vec<u8> {
        self.0.key_blob()
    }
}

/// A plain ed25519 private key.
///
/// The seed is expanded into an [`Ed25519Keypair`], which is zeroized when the
/// key is dropped.
pub struct Ed25519LocalKey {
    pair: Ed25519Keypair,
    public: PublicKey,
}

impl Ed25519LocalKey {
    fn from_pair(pair: Ed25519Keypair, comment: &str) -> Self {
        let public = PublicKey::new(KeyData::Ed25519(pair.public), comment);
        Ed25519LocalKey { pair, public }
    }
}

impl LocalKey for Ed25519LocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, LocalKeyError> {
        Ok(Signer::try_sign(&self.pair, data)?)
    }
}

impl fmt::Debug for Ed25519LocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519LocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// A plain RSA private key.
///
/// The SSH wire form carries `n`, `e`, `d`, `iqmp`, `p` and `q`; the key is
/// rebuilt with the `rsa` crate, which recomputes the CRT parameters and
/// zeroizes every secret when dropped. OpenSSH labels RSA signatures with the
/// requested digest, so [`LocalKey::sign`] packs a PKCS#1 v1.5 signature under
/// `rsa-sha2-256` or `rsa-sha2-512`.
pub struct RsaLocalKey {
    key: rsa::RsaPrivateKey,
    public: PublicKey,
}

impl RsaLocalKey {
    fn from_pair(pair: RsaKeypair, comment: &str) -> Result<Self, KeyDecodeError> {
        let key = rsa_private_key(&pair)?;
        let public = PublicKey::new(KeyData::Rsa(pair.public), comment);
        Ok(RsaLocalKey { key, public })
    }
}

/// Smallest RSA modulus accepted, in bits, as OpenSSH enforces.
pub const MIN_RSA_BITS: usize = 1024;

/// Rebuild an [`rsa::RsaPrivateKey`] from the SSH fields, with `p` and `q` in
/// the order the wire gives them (`ssh-key`'s own conversion passes `p` twice,
/// so it is not used). A modulus under [`MIN_RSA_BITS`] is refused.
fn rsa_private_key(pair: &RsaKeypair) -> Result<rsa::RsaPrivateKey, KeyDecodeError> {
    let mpint = |m: &Mpint| {
        m.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(malformed_rsa)
    };
    let n = mpint(&pair.public.n)?;
    let bits = n.bits();
    if bits < MIN_RSA_BITS {
        return Err(KeyDecodeError::TooSmall {
            key_type: "ssh-rsa",
            bits,
            min: MIN_RSA_BITS,
        });
    }
    rsa::RsaPrivateKey::from_components(
        n,
        mpint(&pair.public.e)?,
        mpint(&pair.private.d)?,
        vec![mpint(&pair.private.p)?, mpint(&pair.private.q)?],
    )
    .map_err(|_| malformed_rsa())
}

fn malformed_rsa() -> KeyDecodeError {
    KeyDecodeError::Malformed("ssh-rsa")
}

impl LocalKey for RsaLocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError> {
        let (scheme, digest) = rsa_scheme(data, hash)?;
        // Blinded, to keep the private exponent out of the timing.
        let raw = self.key.sign_with_rng(&mut OsRng, scheme, &digest)?;
        Ok(Signature::new(Algorithm::Rsa { hash: Some(hash) }, raw)?)
    }

    /// Verify with the `rsa` crate directly: `ssh-key`'s verifier only takes
    /// 2048- to 4096-bit moduli, while OpenSSH keys run from 1024 bits up.
    fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), LocalKeyError> {
        let Algorithm::Rsa { hash: Some(hash) } = sig.algorithm() else {
            return Err(VerifyError.into());
        };
        let (scheme, digest) = rsa_scheme(data, hash)?;
        self.key
            .to_public_key()
            .verify(scheme, &digest, sig.as_bytes())
            .map_err(|_| VerifyError.into())
    }
}

/// The PKCS#1 v1.5 scheme and digest of `data` for an `rsa-sha2-*` signature.
fn rsa_scheme(data: &[u8], hash: HashAlg) -> Result<(Pkcs1v15Sign, Vec<u8>), LocalKeyError> {
    match hash {
        HashAlg::Sha256 => Ok((Pkcs1v15Sign::new::<Sha256>(), Sha256::digest(data).to_vec())),
        HashAlg::Sha512 => Ok((Pkcs1v15Sign::new::<Sha512>(), Sha512::digest(data).to_vec())),
        _ => Err(LocalKeyError::UnsupportedHash),
    }
}

impl fmt::Debug for RsaLocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaLocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// A plain ECDSA private key on a NIST curve (`ecdsa-sha2-nistp256`,
/// `-nistp384` or `-nistp521`).
///
/// The scalar is held by [`EcdsaKeypair`], which zeroizes it when dropped.
/// Signing applies the curve's own digest (SHA-256, SHA-384 or SHA-512), as
/// OpenSSH does; `ssh-key` takes care of the SSH `r || s` mpint encoding.
pub struct EcdsaLocalKey {
    pair: EcdsaKeypair,
    public: PublicKey,
}

impl EcdsaLocalKey {
    fn from_pair(pair: EcdsaKeypair, comment: &str) -> Self {
        let public = PublicKey::new(KeyData::Ecdsa(EcdsaPublicKey::from(&pair)), comment);
        EcdsaLocalKey { pair, public }
    }
}

impl LocalKey for EcdsaLocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, LocalKeyError> {
        Ok(Signer::try_sign(&self.pair, data)?)
    }
}

impl fmt::Debug for EcdsaLocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaLocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// A plain DSA private key (`ssh-dss`), with the `dsa` feature.
///
/// The scalar is held by [`DsaKeypair`], which zeroizes it when dropped.
/// Signing uses SHA-1, the only digest DSA ever used with SSH, so the
/// `sha2-256`/`sha2-512` request flag does not apply.
#[cfg(feature = "dsa")]
pub struct DsaLocalKey {
    pair: DsaKeypair,
    public: PublicKey,
}

#[cfg(feature = "dsa")]
impl DsaLocalKey {
    fn from_pair(pair: DsaKeypair, comment: &str) -> Self {
        let public = PublicKey::new(KeyData::Dsa(DsaPublicKey::from(&pair)), comment);
        DsaLocalKey { pair, public }
    }
}

#[cfg(feature = "dsa")]
impl LocalKey for DsaLocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, LocalKeyError> {
        Ok(Signer::try_sign(&self.pair, data)?)
    }
}

#[cfg(feature = "dsa")]
impl fmt::Debug for DsaLocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaLocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Decode the type-specific private fields of an `ADD_IDENTITY` request body,
/// plus the trailing comment, leaving the reader just past the comment.
///
/// These are the built-in key types. A caller can add or replace a key type
/// with a [`KeyDecoder`](crate::keytype::KeyDecoder) registered on the agent.
pub fn decode(key_type: &str, reader: &mut impl Reader) -> Result<LocalKeyRef, KeyDecodeError> {
    match key_type {
        "ssh-ed25519" => {
            // The agent's private fields are the public key followed by the
            // 64-byte `seed || public`, which is exactly the keypair encoding.
            let pair = Ed25519Keypair::decode(reader).map_err(|_| malformed_ed25519())?;
            let comment = String::decode(reader).map_err(|_| malformed_ed25519())?;
            Ok(LocalKeyRef::new(Ed25519LocalKey::from_pair(pair, &comment)))
        }
        "ssh-rsa" => {
            // The agent's RSA private fields are `n e d iqmp p q`, which is
            // exactly the keypair encoding, followed by the comment.
            let pair = RsaKeypair::decode(reader).map_err(|_| malformed_rsa())?;
            let comment = String::decode(reader).map_err(|_| malformed_rsa())?;
            Ok(LocalKeyRef::new(RsaLocalKey::from_pair(pair, &comment)?))
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            // The agent's ECDSA private fields are the curve name and public
            // point followed by the private scalar, which is the keypair
            // encoding, then the comment. The curve is carried in the body,
            // so it must agree with the key type that named it.
            let (curve, field_size) = ecdsa_curve(key_type).expect("matched above");
            let pair = ecdsa_keypair(reader, field_size).ok_or_else(|| malformed_ecdsa(curve))?;
            if pair.curve() != curve {
                return Err(malformed_ecdsa(curve));
            }
            let comment = String::decode(reader).map_err(|_| malformed_ecdsa(curve))?;
            Ok(LocalKeyRef::new(EcdsaLocalKey::from_pair(pair, &comment)))
        }
        #[cfg(feature = "dsa")]
        "ssh-dss" => {
            // The agent's DSA private fields are `p q g y x`, which is exactly
            // the keypair encoding, followed by the comment.
            let pair = DsaKeypair::decode(reader).map_err(|_| malformed_dsa())?;
            let comment = String::decode(reader).map_err(|_| malformed_dsa())?;
            Ok(LocalKeyRef::new(DsaLocalKey::from_pair(pair, &comment)))
        }
        other => Err(KeyDecodeError::UnsupportedType(other.to_owned())),
    }
}

/// The [`EcdsaCurve`] and field size in bytes named by an `ecdsa-sha2-*`
/// key type.
fn ecdsa_curve(key_type: &str) -> Option<(EcdsaCurve, usize)> {
    match key_type {
        "ecdsa-sha2-nistp256" => Some((EcdsaCurve::NistP256, 32)),
        "ecdsa-sha2-nistp384" => Some((EcdsaCurve::NistP384, 48)),
        "ecdsa-sha2-nistp521" => Some((EcdsaCurve::NistP521, 66)),
        _ => None,
    }
}

/// Decode an [`EcdsaKeypair`] from the agent's curve name, public point and
/// private scalar, left-padding the scalar to the field size first: OpenSSH
/// sends the scalar as a minimal mpint, but `ssh-key`'s decoder only accepts
/// a whole field element (plus at most one sign byte), so a short scalar —
/// half of all P-521 keys — would otherwise be refused as malformed. The
/// re-decode re-derives the curve from the embedded name, so padding cannot
/// pass a key off as a different curve.
fn ecdsa_keypair(reader: &mut impl Reader, field_size: usize) -> Option<EcdsaKeypair> {
    let name = String::decode(reader).ok()?;
    let point = Vec::<u8>::decode(reader).ok()?;
    // The scalar is secret: every copy is wiped on drop, and buffers are
    // sized up front so no reallocation leaves one behind.
    let scalar = Zeroizing::new(Vec::<u8>::decode(reader).ok()?);
    if scalar.len() > field_size + 1 {
        return None;
    }
    let mut padded = Zeroizing::new(Vec::with_capacity(field_size + 1));
    padded.resize(field_size.saturating_sub(scalar.len()), 0);
    padded.extend_from_slice(&scalar);
    let mut body = Zeroizing::new(Vec::with_capacity(
        name.len() + point.len() + padded.len() + 12,
    ));
    name.encode(&mut *body).ok()?;
    point.encode(&mut *body).ok()?;
    padded.encode(&mut *body).ok()?;
    EcdsaKeypair::decode(&mut body.as_slice()).ok()
}

fn malformed_ed25519() -> KeyDecodeError {
    KeyDecodeError::Malformed("ssh-ed25519")
}

/// The malformed-body error for an `ecdsa-sha2-*` key type, named by curve.
fn malformed_ecdsa(curve: EcdsaCurve) -> KeyDecodeError {
    let key_type = match curve {
        EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
        EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
        EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
    };
    KeyDecodeError::Malformed(key_type)
}

#[cfg(feature = "dsa")]
fn malformed_dsa() -> KeyDecodeError {
    KeyDecodeError::Malformed("ssh-dss")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;

    fn keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_seed(&[0x42; 32])
    }

    fn encoded_body(pair: &Ed25519Keypair, comment: &str) -> Vec<u8> {
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        body
    }

    #[test]
    fn decodes_signs_and_verifies_an_ed25519_key() {
        let pair = keypair();
        let body = encoded_body(&pair, "ferris@example.com");
        let key = decode("ssh-ed25519", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        assert_eq!(
            key.public_key().key_data().ed25519().unwrap().0,
            pair.public.0
        );

        let sig = key.sign(b"hello", HashAlg::Sha512).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
        signer::verify(key.public_key(), b"hello", &sig).unwrap();
        assert!(signer::verify(key.public_key(), b"other", &sig).is_err());
    }

    #[test]
    fn rejects_unknown_types_and_truncated_keys() {
        let mut empty: &[u8] = &[];
        assert!(matches!(
            decode("sk-ssh-ed25519@openssh.com", &mut empty),
            Err(KeyDecodeError::UnsupportedType(t)) if t == "sk-ssh-ed25519@openssh.com"
        ));
        let pair = keypair();
        let mut body = encoded_body(&pair, "c");
        body.truncate(10);
        assert!(matches!(
            decode("ssh-ed25519", &mut body.as_slice()),
            Err(KeyDecodeError::Malformed(_))
        ));
        let mut rsa: &[u8] = &[];
        assert!(matches!(
            decode("ssh-rsa", &mut rsa),
            Err(KeyDecodeError::Malformed("ssh-rsa"))
        ));
        let mut ecdsa: &[u8] = &[];
        assert!(matches!(
            decode("ecdsa-sha2-nistp384", &mut ecdsa),
            Err(KeyDecodeError::Malformed("ecdsa-sha2-nistp384"))
        ));
        let mut dsa: &[u8] = &[];
        #[cfg(feature = "dsa")]
        assert!(matches!(
            decode("ssh-dss", &mut dsa),
            Err(KeyDecodeError::Malformed("ssh-dss"))
        ));
        // Without the `dsa` feature, DSA is not a known key type at all.
        #[cfg(not(feature = "dsa"))]
        assert!(matches!(
            decode("ssh-dss", &mut dsa),
            Err(KeyDecodeError::UnsupportedType(t)) if t == "ssh-dss"
        ));
    }

    /// Build the agent's `ssh-rsa` private-key body from a known key and check
    /// that it decodes, signs each supported digest and verifies.
    #[test]
    fn decodes_signs_and_verifies_an_rsa_key() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        let sk =
            rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../tests/data/rsa2048.pem")).unwrap();
        let pair = RsaKeypair::try_from(&sk).unwrap();
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();

        let key = decode("ssh-rsa", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        let n = key.public_key().key_data().rsa().unwrap().n.clone();
        assert_eq!(
            n.as_positive_bytes().unwrap(),
            sk.n().to_bytes_be().as_slice()
        );

        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let sig = key.sign(b"hello", hash).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            assert_eq!(sig.as_bytes().len(), 256);
            signer::verify(key.public_key(), b"hello", &sig).unwrap();
            assert!(signer::verify(key.public_key(), b"other", &sig).is_err());
        }

        let debug = format!("{key:?}");
        assert!(debug.contains("LocalKeyRef"), "{debug}");
    }

    /// RSA keys outside the 2048–4096-bit range `ssh-key` verifies with still
    /// sign and verify: OpenSSH accepts 1024 bits and up, with no upper bound.
    #[test]
    fn signs_and_verifies_small_and_large_rsa_keys() {
        use rsa::pkcs1::DecodeRsaPrivateKey;

        for (pem, bytes) in [
            (include_str!("../tests/data/rsa1024.pem"), 128),
            (include_str!("../tests/data/rsa8192.pem"), 1024),
        ] {
            let sk = rsa::RsaPrivateKey::from_pkcs1_pem(pem).unwrap();
            let pair = RsaKeypair::try_from(&sk).unwrap();
            let mut body = Vec::new();
            pair.encode(&mut body).unwrap();
            "ferris@example.com".encode(&mut body).unwrap();
            let key = decode("ssh-rsa", &mut body.as_slice()).unwrap();
            for hash in [HashAlg::Sha256, HashAlg::Sha512] {
                let sig = key.sign(b"hello", hash).unwrap();
                assert_eq!(sig.as_bytes().len(), bytes);
                key.verify(b"hello", &sig).unwrap();
                assert!(key.verify(b"other", &sig).is_err());
            }
        }
    }

    /// An RSA key under 1024 bits is refused, as OpenSSH refuses it.
    #[test]
    fn rejects_an_rsa_key_below_1024_bits() {
        let sk = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 768).unwrap();
        let pair = RsaKeypair::try_from(&sk).unwrap();
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        "weak@example.com".encode(&mut body).unwrap();
        assert!(matches!(
            decode("ssh-rsa", &mut body.as_slice()),
            Err(KeyDecodeError::TooSmall {
                key_type: "ssh-rsa",
                bits: 768,
                min: 1024,
            })
        ));
    }

    /// Build the agent's `ecdsa-sha2-*` private-key body for each NIST curve
    /// and check that it decodes, signs with the curve's digest and verifies.
    #[test]
    fn decodes_signs_and_verifies_ecdsa_keys_on_all_curves() {
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            let algorithm = Algorithm::Ecdsa { curve };
            let key_type = algorithm.as_str();
            let pair = EcdsaKeypair::random(&mut rand_core::OsRng, curve).unwrap();
            let mut body = Vec::new();
            pair.encode(&mut body).unwrap();
            "ferris@example.com".encode(&mut body).unwrap();

            let key = decode(key_type, &mut body.as_slice()).unwrap();
            assert_eq!(key.public_key().comment(), "ferris@example.com");
            assert_eq!(key.public_key().algorithm(), algorithm, "{key_type}");

            let sig = key.sign(b"hello", HashAlg::Sha512).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Ecdsa { curve });
            signer::verify(key.public_key(), b"hello", &sig).unwrap();
            assert!(signer::verify(key.public_key(), b"other", &sig).is_err());

            let debug = format!("{key:?}");
            assert!(debug.contains("LocalKeyRef"), "{debug}");
        }
    }

    /// The type-specific `Debug` of a local ECDSA key shows only the public
    /// half, so the private scalar never reaches a log.
    #[test]
    fn ecdsa_debug_hides_the_secret() {
        let pair = EcdsaKeypair::random(&mut rand_core::OsRng, EcdsaCurve::NistP256).unwrap();
        let secret = hex::encode(pair.private_key_bytes());
        let key = EcdsaLocalKey::from_pair(pair, "ferris@example.com");
        let debug = format!("{key:?}");
        assert!(debug.contains("EcdsaLocalKey"), "{debug}");
        assert!(!debug.contains(&secret), "{debug}");
    }

    /// A body whose curve disagrees with the key type that named it is refused
    /// rather than served under the wrong algorithm.
    #[test]
    fn rejects_ecdsa_curve_mismatch() {
        let pair = EcdsaKeypair::random(&mut rand_core::OsRng, EcdsaCurve::NistP384).unwrap();
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();
        assert!(matches!(
            decode("ecdsa-sha2-nistp256", &mut body.as_slice()),
            Err(KeyDecodeError::Malformed("ecdsa-sha2-nistp256"))
        ));
    }

    /// OpenSSH sends the private scalar as a minimal mpint, so a P-521 key
    /// whose top byte is zero (half of all keys) arrives as a 65-byte body.
    /// The decode left-pads it rather than refusing the key as malformed.
    #[test]
    fn decodes_a_p521_key_with_a_short_scalar() {
        let pair = std::iter::repeat_with(|| {
            EcdsaKeypair::random(&mut rand_core::OsRng, EcdsaCurve::NistP521).unwrap()
        })
        .find(|p| p.private_key_bytes()[0] == 0)
        .expect("a few draws find a top-zero scalar");
        let mut body = Vec::new();
        "nistp521".encode(&mut body).unwrap();
        pair.public_key_bytes().encode(&mut body).unwrap();
        pair.private_key_bytes()[1..].encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();

        let key = decode("ecdsa-sha2-nistp521", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        let sig = key.sign(b"hello", HashAlg::Sha512).unwrap();
        signer::verify(key.public_key(), b"hello", &sig).unwrap();
    }

    /// A DSA key decodes, signs with SHA-1 and verifies.
    #[cfg(feature = "dsa")]
    #[test]
    fn decodes_signs_and_verifies_a_dsa_key() {
        let pair = DsaKeypair::random(&mut rand_core::OsRng).unwrap();
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();

        let key = decode("ssh-dss", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        assert_eq!(key.public_key().algorithm(), Algorithm::Dsa);
        let sig = key.sign(b"hello", HashAlg::Sha256).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Dsa);
        signer::verify(key.public_key(), b"hello", &sig).unwrap();
        assert!(signer::verify(key.public_key(), b"other", &sig).is_err());
    }

    #[test]
    fn equality_and_debug_ignore_the_secret() {
        let a = decode(
            "ssh-ed25519",
            &mut encoded_body(&keypair(), "one").as_slice(),
        )
        .unwrap();
        let b = decode(
            "ssh-ed25519",
            &mut encoded_body(&keypair(), "one").as_slice(),
        )
        .unwrap();
        let other = Ed25519Keypair::from_seed(&[0x43; 32]);
        let c = decode("ssh-ed25519", &mut encoded_body(&other, "one").as_slice()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let debug = format!("{a:?}");
        assert!(debug.contains("LocalKeyRef"), "{debug}");
        // The seed itself never appears in the debug output.
        assert!(!debug.contains(&hex::encode([0x42u8; 32])), "{debug}");
    }
}
