use crowsi_key_provider::{
    AttestationChallenge, AttestationVerification, HardwareAttestation, HardwareOperationClaim,
    HardwareOperationDisposition, HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation,
    KeyAlgorithm, KeyProperty, KeyPurpose, KeySource,
};

use crate::support::NOW;

pub fn role_binding(claim: &HardwareRoleClaim) -> HardwareRoleBinding {
    HardwareRoleBinding {
        claim_digest_sha256: claim.claim_digest_sha256.clone(),
        hardware_binding_ref: "hardware-binding:test-key".into(),
        current_fence: 0,
    }
}

pub fn claimed_operation(operation: &HardwareSigningOperation) -> HardwareOperationClaim {
    HardwareOperationClaim {
        operation_id: operation.operation_id.clone(),
        request_binding_sha256: operation.request_binding_sha256.clone(),
        ledger_instance_id: operation.ledger_instance_id.clone(),
        role_claim_digest_sha256: operation.role_claim_digest_sha256.clone(),
        previous_hardware_fence: operation.previous_hardware_fence,
        hardware_fence: operation.hardware_fence,
        disposition: HardwareOperationDisposition::Claimed,
    }
}

pub fn verified_evidence(
    challenge_matches: bool,
) -> std::collections::BTreeSet<AttestationVerification> {
    let mut result: std::collections::BTreeSet<_> = [
        AttestationVerification::VendorChain,
        AttestationVerification::PublicKeyBinding,
        AttestationVerification::Signature,
        AttestationVerification::EvidenceFieldsDerived,
    ]
    .into();
    if challenge_matches {
        result.insert(AttestationVerification::Challenge);
    }
    result
}

pub fn attestation() -> HardwareAttestation {
    HardwareAttestation {
        source: KeySource::Tpm2,
        key_id: "release-key".into(),
        key_version: "release-key-version-1".into(),
        public_key_spki_sha256: "c".repeat(64),
        purpose: KeyPurpose::Release,
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
        challenge_digest_sha256: String::new(),
        attestation_envelope_base64: "QUFBQUFBQUFBQUFB".into(),
        attestation_signature_base64: "QkJCQkJCQkJCQkJC".into(),
        attestation_chain_ref: "vendor-chain-version-1".into(),
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 10,
    }
}

pub fn bind_to_challenge(value: &mut HardwareAttestation, challenge: &AttestationChallenge) {
    value
        .challenge_digest_sha256
        .clone_from(&challenge.digest_sha256);
    value.issued_at_epoch_s = challenge.issued_at_epoch_s;
    value.expires_at_epoch_s = challenge.expires_at_epoch_s;
}
