use sha2::{Digest, Sha256};

use crate::{KeyError, KeyPolicy, SigningRequestV1};

const CHALLENGE_SCHEMA: &str = "crowsi://keys/attestation-challenge/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationChallenge {
    pub schema: &'static str,
    pub request_id: String,
    pub request_nonce: String,
    pub server_nonce_hex: String,
    pub signing_digest_sha256: String,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: &'static str,
    pub verifier_key_id: String,
    pub trust_revision: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub digest_sha256: String,
}

impl AttestationChallenge {
    pub(crate) fn new(
        policy: &KeyPolicy,
        request: &SigningRequestV1,
        now: u64,
    ) -> Result<Self, KeyError> {
        Self::with_deadline(policy, request, now, request.expires_at_epoch_s)
    }

    pub(crate) fn for_recovery(
        policy: &KeyPolicy,
        request: &SigningRequestV1,
        now: u64,
        recovery_deadline_epoch_s: u64,
    ) -> Result<Self, KeyError> {
        Self::with_deadline(policy, request, now, recovery_deadline_epoch_s)
    }

    fn with_deadline(
        policy: &KeyPolicy,
        request: &SigningRequestV1,
        now: u64,
        deadline_epoch_s: u64,
    ) -> Result<Self, KeyError> {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| KeyError::ChallengeUnavailable)?;
        let expires = deadline_epoch_s.min(now.saturating_add(policy.max_attestation_ttl_seconds));
        if expires <= now {
            return Err(KeyError::RecoveryWindowExpired);
        }
        let mut value = Self {
            schema: CHALLENGE_SCHEMA,
            request_id: request.request_id.clone(),
            request_nonce: request.nonce.clone(),
            server_nonce_hex: hex(&random),
            signing_digest_sha256: request.digest_sha256.clone(),
            key_id: policy.key_id.clone(),
            key_version: policy.key_version.clone(),
            public_key_spki_sha256: policy.public_key_spki_sha256.clone(),
            purpose: policy.purpose.as_str(),
            verifier_key_id: policy.attestation_verifier_key_id.clone(),
            trust_revision: policy.attestation_trust_revision,
            issued_at_epoch_s: now,
            expires_at_epoch_s: expires,
            digest_sha256: String::new(),
        };
        value.digest_sha256 = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> String {
        let mut hash = Sha256::new();
        for field in [
            self.schema,
            &self.request_id,
            &self.request_nonce,
            &self.server_nonce_hex,
            &self.signing_digest_sha256,
            &self.key_id,
            &self.key_version,
            &self.public_key_spki_sha256,
            self.purpose,
            &self.verifier_key_id,
        ] {
            hash.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(self.trust_revision.to_be_bytes());
        hash.update(self.issued_at_epoch_s.to_be_bytes());
        hash.update(self.expires_at_epoch_s.to_be_bytes());
        format!("{:x}", hash.finalize())
    }
}

fn hex(value: &[u8]) -> String {
    const SYMBOLS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(SYMBOLS[usize::from(byte >> 4)]));
        output.push(char::from(SYMBOLS[usize::from(byte & 0x0f)]));
    }
    output
}
