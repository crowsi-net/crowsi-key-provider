use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{KeyAlgorithm, KeyProperty, KeyPurpose, KeySource};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareAttestation {
    pub source: KeySource,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: KeyPurpose,
    pub algorithm: KeyAlgorithm,
    pub properties: BTreeSet<KeyProperty>,
    pub attestation_digest_sha256: String,
    pub challenge_digest_sha256: String,
    pub attestation_envelope_base64: String,
    pub attestation_signature_base64: String,
    pub attestation_chain_ref: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

impl std::fmt::Debug for HardwareAttestation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HardwareAttestation")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("purpose", &self.purpose)
            .field("attestation_digest_sha256", &self.attestation_digest_sha256)
            .field("challenge_digest_sha256", &self.challenge_digest_sha256)
            .field("evidence", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHardwareAttestation {
    pub attestation: HardwareAttestation,
    pub verifier_key_id: String,
    pub trust_revision: u64,
    pub verifications: BTreeSet<AttestationVerification>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttestationVerification {
    VendorChain,
    PublicKeyBinding,
    Challenge,
    Signature,
    EvidenceFieldsDerived,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSummary {
    pub source: KeySource,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: KeyPurpose,
    pub algorithm: KeyAlgorithm,
    pub properties: BTreeSet<KeyProperty>,
    pub attestation_digest_sha256: String,
    pub challenge_digest_sha256: String,
    pub attestation_chain_ref: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

impl From<&HardwareAttestation> for AttestationSummary {
    fn from(value: &HardwareAttestation) -> Self {
        Self {
            source: value.source,
            key_id: value.key_id.clone(),
            key_version: value.key_version.clone(),
            public_key_spki_sha256: value.public_key_spki_sha256.clone(),
            purpose: value.purpose,
            algorithm: value.algorithm,
            properties: value.properties.clone(),
            attestation_digest_sha256: value.attestation_digest_sha256.clone(),
            challenge_digest_sha256: value.challenge_digest_sha256.clone(),
            attestation_chain_ref: value.attestation_chain_ref.clone(),
            issued_at_epoch_s: value.issued_at_epoch_s,
            expires_at_epoch_s: value.expires_at_epoch_s,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResponseV2 {
    pub schema: String,
    pub request_id: String,
    pub digest_sha256: String,
    pub signature: Vec<u8>,
    pub attestation: AttestationSummary,
    pub key_operation_performed: bool,
    pub external_actions: bool,
}
