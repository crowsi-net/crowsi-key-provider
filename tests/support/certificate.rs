use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareKeyPort, HardwareOperationClaim,
    HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation, IndependentKeyVerifier,
    KeyAlgorithm, KeyError, KeyProperty, KeyPurpose, KeySource, VerifiedHardwareAttestation,
    VerifiedHardwareRoleBinding,
};

use super::{TestVerifier, claimed_operation, role_binding};

pub struct CertificatePort {
    purpose: KeyPurpose,
    spki: String,
}

impl CertificatePort {
    pub fn new(purpose: KeyPurpose, spki: String) -> Self {
        Self { purpose, spki }
    }
}

impl HardwareKeyPort for CertificatePort {
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        Ok(role_binding(claim))
    }

    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        Ok(claimed_operation(operation))
    }

    fn attest(
        &mut self,
        key_id: &str,
        key_version: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError> {
        Ok(HardwareAttestation {
            source: KeySource::Tpm2,
            key_id: key_id.into(),
            key_version: key_version.into(),
            public_key_spki_sha256: self.spki.clone(),
            purpose: self.purpose,
            algorithm: KeyAlgorithm::EcdsaP256Sha256P1363LowS,
            properties: [
                KeyProperty::HardwareBacked,
                KeyProperty::NonExportable,
                KeyProperty::RoleScoped,
                KeyProperty::AttestationChainVerified,
            ]
            .into(),
            attestation_digest_sha256:
                "0592cedeabbf836d8d1c7456417c7653ac208f71e904d3d0ab37faf711021aff".into(),
            challenge_digest_sha256: challenge.digest_sha256.clone(),
            attestation_envelope_base64: "QUFBQUFBQUFBQUFB".into(),
            attestation_signature_base64: "QkJCQkJCQkJCQkJC".into(),
            attestation_chain_ref: "vendor-chain-version-1".into(),
            issued_at_epoch_s: challenge.issued_at_epoch_s,
            expires_at_epoch_s: challenge.expires_at_epoch_s,
        })
    }

    fn sign_digest(&mut self, _: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        Ok(vec![7; 64])
    }

    fn recover_signature(
        &mut self,
        _: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        Ok(None)
    }
}

pub struct CertificateVerifier {
    spki: String,
}

impl CertificateVerifier {
    pub fn new(spki: String) -> Self {
        Self { spki }
    }
}

impl IndependentKeyVerifier for CertificateVerifier {
    fn verify_role_binding(
        &mut self,
        value: &HardwareRoleBinding,
        claim: &HardwareRoleClaim,
    ) -> Result<VerifiedHardwareRoleBinding, KeyError> {
        TestVerifier::ready().verify_role_binding(value, claim)
    }

    fn verify_attestation(
        &mut self,
        value: &HardwareAttestation,
        challenge: &AttestationChallenge,
    ) -> Result<VerifiedHardwareAttestation, KeyError> {
        TestVerifier::ready().verify_attestation(value, challenge)
    }

    fn verify_signature(
        &mut self,
        key: &VerifiedHardwareAttestation,
        _: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, KeyError> {
        Ok(key.attestation.public_key_spki_sha256 == self.spki && signature == [7; 64])
    }
}
