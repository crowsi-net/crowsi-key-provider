use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareRoleBinding, HardwareRoleClaim,
    IndependentKeyVerifier, KeyError, RoleBindingVerification, VerifiedHardwareAttestation,
    VerifiedHardwareRoleBinding,
};

use super::fixtures::verified_evidence;

pub struct TestVerifier;

impl TestVerifier {
    pub const fn ready() -> Self {
        Self
    }
}

impl IndependentKeyVerifier for TestVerifier {
    fn verify_role_binding(
        &mut self,
        value: &HardwareRoleBinding,
        _: &HardwareRoleClaim,
    ) -> Result<VerifiedHardwareRoleBinding, KeyError> {
        Ok(VerifiedHardwareRoleBinding {
            binding: value.clone(),
            verifier_key_id: "vendor-attestation-root".into(),
            trust_revision: 1,
            verifications: [
                RoleBindingVerification::HardwareSealed,
                RoleBindingVerification::PublicKeyBinding,
                RoleBindingVerification::RoleClaim,
                RoleBindingVerification::Signature,
                RoleBindingVerification::DurableCounter,
            ]
            .into(),
        })
    }

    fn verify_attestation(
        &mut self,
        value: &HardwareAttestation,
        challenge: &AttestationChallenge,
    ) -> Result<VerifiedHardwareAttestation, KeyError> {
        Ok(VerifiedHardwareAttestation {
            attestation: value.clone(),
            verifier_key_id: "vendor-attestation-root".into(),
            trust_revision: 1,
            verifications: verified_evidence(
                value.challenge_digest_sha256 == challenge.digest_sha256,
            ),
        })
    }

    fn verify_signature(
        &mut self,
        key: &VerifiedHardwareAttestation,
        _: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, KeyError> {
        Ok(key.attestation.public_key_spki_sha256 == "c".repeat(64) && signature == [7; 64])
    }
}
