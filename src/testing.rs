//! Test doubles for agents built on this crate. Available in this crate's
//! tests and, to other crates, with the `test-util` feature.

use crate::backend::Backend;
use crate::cert::CertKey;
use crate::policy::{Confirm, ConfirmRequest};
use crate::signer::SignerRef;
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
use ssh_key::certificate::Builder;
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::KeyData;
use std::collections::VecDeque;
use std::sync::Mutex;

/// A certificate for `key`, signed by a fixed ed25519 CA, valid until
/// `valid_before`, with key id and principal `ferris`.
pub fn certify_until(key: &KeyData, valid_before: u64) -> CertKey {
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[0xCA; 32]));
    let mut builder = Builder::new([7u8; 16], key.clone(), 0, valid_before).unwrap();
    builder.key_id("ferris").unwrap();
    builder.valid_principal("ferris").unwrap();
    let cert = builder.sign(&ca).unwrap();
    CertKey::from_blob(&cert.to_bytes().unwrap()).unwrap()
}

/// A certificate for `key` that never expires; see [`certify_until`].
pub fn certify(key: &KeyData) -> CertKey {
    certify_until(key, u64::MAX >> 1)
}

/// The `ADD_IDENTITY` body ssh-add sends for a certificate: the blob, the
/// private fields (`private`), the comment.
pub fn cert_body(cert: &CertKey, private: &[u8], comment: &str) -> Vec<u8> {
    let mut body = Vec::new();
    cert.blob().encode(&mut body).unwrap();
    body.extend_from_slice(private);
    comment.encode(&mut body).unwrap();
    body
}

/// Answers confirmations from a script, recording each request. With the
/// script used up, it gives no answer.
#[derive(Default)]
pub struct RecordingConfirm {
    answers: Mutex<VecDeque<Option<bool>>>,
    pub requests: Mutex<Vec<ConfirmRequest>>,
}

impl RecordingConfirm {
    pub fn answering(answers: impl IntoIterator<Item = Option<bool>>) -> Self {
        RecordingConfirm {
            answers: Mutex::new(answers.into_iter().collect()),
            requests: Mutex::default(),
        }
    }
}

impl Confirm for RecordingConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        self.requests.lock().unwrap().push(request.clone());
        self.answers.lock().unwrap().pop_front().flatten()
    }
}

/// A backend serving a fixed, removable list of keys.
#[derive(Default)]
pub struct MemoryBackend(pub Mutex<Vec<SignerRef>>);

impl MemoryBackend {
    pub fn new(keys: impl IntoIterator<Item = SignerRef>) -> Self {
        MemoryBackend(Mutex::new(keys.into_iter().collect()))
    }
}

impl Backend for MemoryBackend {
    fn identities(&self) -> Vec<SignerRef> {
        self.0.lock().unwrap().clone()
    }

    fn remove(&self, key_blob: &[u8]) -> bool {
        let mut keys = self.0.lock().unwrap();
        let before = keys.len();
        keys.retain(|k| k.key_blob() != key_blob);
        keys.len() != before
    }

    fn remove_all(&self) {
        self.0.lock().unwrap().clear();
    }
}
