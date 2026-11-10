//! Signing-certificate attestation for `buzz-android-fcm`.
//!
//! v1 binds an ECDSA P-256 installation key to the gateway-configured APK
//! signing-certificate SHA-256. This is not Play Integrity and not a hardware
//! root of trust. The caller must sign the exact NIP-PL transcript and name
//! the configured digest. Token provenance remains the same bootstrap
//! assumption as APNs.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_ATTESTATION_BYTES: usize = 8 * 1024;
const MAX_ASSERTION_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub key_id: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub counter: u32,
}

#[derive(Debug, Error)]
pub enum SigningCertError {
    #[error("invalid signing-cert attestation or assertion")]
    Invalid,
}

#[derive(Clone)]
pub struct SigningCertVerifier {
    signing_cert_sha256: [u8; 32],
}

#[derive(Deserialize)]
struct AttestationBody {
    v: u8,
    alg: String,
    signing_cert_sha256: String,
    public_key: String,
    signature: String,
}

#[derive(Deserialize)]
struct AssertionBody {
    v: u8,
    alg: String,
    counter: u32,
    signature: String,
}

impl SigningCertVerifier {
    pub fn new(signing_cert_sha256_hex: &str) -> Result<Self, SigningCertError> {
        let signing_cert_sha256 = parse_sha256_hex(signing_cert_sha256_hex)?;
        Ok(Self {
            signing_cert_sha256,
        })
    }

    pub fn expected_sha256_hex(&self) -> String {
        hex::encode(self.signing_cert_sha256)
    }

    pub fn verify_attestation(
        &self,
        attestation_b64: &str,
        key_id_b64: &str,
        client_data: &[u8],
    ) -> Result<VerifiedAttestation, SigningCertError> {
        let raw = STANDARD
            .decode(attestation_b64)
            .map_err(|_| SigningCertError::Invalid)?;
        if raw.is_empty() || raw.len() > MAX_ATTESTATION_BYTES {
            return Err(SigningCertError::Invalid);
        }
        let body: AttestationBody =
            serde_json::from_slice(&raw).map_err(|_| SigningCertError::Invalid)?;
        if body.v != 1 || body.alg != "ES256" {
            return Err(SigningCertError::Invalid);
        }
        let named = parse_sha256_hex(&body.signing_cert_sha256)?;
        if named != self.signing_cert_sha256 {
            return Err(SigningCertError::Invalid);
        }
        let public_key = STANDARD
            .decode(&body.public_key)
            .map_err(|_| SigningCertError::Invalid)?;
        let key_id = STANDARD
            .decode(key_id_b64)
            .map_err(|_| SigningCertError::Invalid)?;
        if key_id != Sha256::digest(&public_key).as_slice() {
            return Err(SigningCertError::Invalid);
        }
        verify_p256_signature(&public_key, client_data, &body.signature)?;
        Ok(VerifiedAttestation {
            key_id,
            public_key,
        })
    }

    pub fn verify_assertion(
        &self,
        assertion_b64: &str,
        client_data: &[u8],
        public_key: &[u8],
        previous_counter: u32,
    ) -> Result<VerifiedAssertion, SigningCertError> {
        let raw = STANDARD
            .decode(assertion_b64)
            .map_err(|_| SigningCertError::Invalid)?;
        if raw.is_empty() || raw.len() > MAX_ASSERTION_BYTES {
            return Err(SigningCertError::Invalid);
        }
        let body: AssertionBody =
            serde_json::from_slice(&raw).map_err(|_| SigningCertError::Invalid)?;
        if body.v != 1 || body.alg != "ES256" || body.counter <= previous_counter {
            return Err(SigningCertError::Invalid);
        }
        verify_p256_signature(public_key, client_data, &body.signature)?;
        Ok(VerifiedAssertion {
            counter: body.counter,
        })
    }
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], SigningCertError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(SigningCertError::Invalid);
    }
    let bytes = hex::decode(value).map_err(|_| SigningCertError::Invalid)?;
    bytes.try_into().map_err(|_| SigningCertError::Invalid)
}

fn verify_p256_signature(
    public_key: &[u8],
    message: &[u8],
    signature_b64: &str,
) -> Result<(), SigningCertError> {
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| SigningCertError::Invalid)?;
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| SigningCertError::Invalid)?;
    let signature = Signature::from_der(&signature_bytes)
        .or_else(|_| Signature::from_slice(&signature_bytes))
        .map_err(|_| SigningCertError::Invalid)?;
    let digest = Sha256::digest(message);
    verifying_key
        .verify(&digest, &signature)
        .map_err(|_| SigningCertError::Invalid)?;
    Ok(())
}

/// Build a v1 attestation JSON object for tests and the Flutter encoder.
pub fn encode_attestation(
    signing_cert_sha256_hex: &str,
    public_key: &[u8],
    signature_der: &[u8],
) -> Result<Vec<u8>, SigningCertError> {
    parse_sha256_hex(signing_cert_sha256_hex)?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "alg": "ES256",
        "signing_cert_sha256": signing_cert_sha256_hex,
        "public_key": STANDARD.encode(public_key),
        "signature": STANDARD.encode(signature_der),
    }))
    .expect("attestation json"))
}

pub fn encode_assertion(counter: u32, signature_der: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "alg": "ES256",
        "counter": counter,
        "signature": STANDARD.encode(signature_der),
    }))
    .expect("assertion json")
}

pub fn key_id_for_public_key(public_key: &[u8]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    const CERT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn keypair() -> (SigningKey, Vec<u8>) {
        let signing = SigningKey::from_slice(&[0x01; 32]).expect("fixed P-256 scalar");
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (signing, public)
    }

    fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(message);
        let signature: Signature = key.sign(&digest);
        signature.to_der().as_bytes().to_vec()
    }

    #[test]
    fn accepts_a_transcript_signed_by_the_named_cert() {
        let verifier = SigningCertVerifier::new(CERT).unwrap();
        let (signing, public) = keypair();
        let transcript = b"buzz.push.enroll.v1\n{\"v\":1}";
        let attestation = encode_attestation(CERT, &public, &sign(&signing, transcript)).unwrap();
        let key_id = STANDARD.encode(key_id_for_public_key(&public));
        let verified = verifier
            .verify_attestation(&STANDARD.encode(&attestation), &key_id, transcript)
            .unwrap();
        assert_eq!(verified.public_key, public);
        assert_eq!(verified.key_id, key_id_for_public_key(&public));
    }

    #[test]
    fn rejects_a_mismatched_signing_cert_digest() {
        let verifier = SigningCertVerifier::new(CERT).unwrap();
        let (signing, public) = keypair();
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let attestation = encode_attestation(other, &public, &sign(&signing, b"t")).unwrap();
        let key_id = STANDARD.encode(key_id_for_public_key(&public));
        assert!(verifier
            .verify_attestation(&STANDARD.encode(attestation), &key_id, b"t")
            .is_err());
    }

    #[test]
    fn assertion_counter_must_strictly_increase() {
        let verifier = SigningCertVerifier::new(CERT).unwrap();
        let (signing, public) = keypair();
        let transcript = b"buzz.push.delegate.v1\n{}";
        let assertion = encode_assertion(3, &sign(&signing, transcript));
        assert!(verifier
            .verify_assertion(&STANDARD.encode(&assertion), transcript, &public, 3)
            .is_err());
        let verified = verifier
            .verify_assertion(&STANDARD.encode(assertion), transcript, &public, 2)
            .unwrap();
        assert_eq!(verified.counter, 3);
    }
}
