use crate::{
    HardwareRoleBinding, HardwareRoleClaim, KeyError, KeyPolicy, ProviderLedgerBinding,
    RoleBindingVerification, VerifiedHardwareRoleBinding,
    request_value::{is_digest, valid_id},
    role_claim,
};

pub(crate) fn validate_ledger_binding(
    policy: &KeyPolicy,
    value: &ProviderLedgerBinding,
) -> Result<(), KeyError> {
    let valid = ledger_id(&value.ledger_instance_id)
        && value.role_manifest_digest_sha256 == policy.role_manifest_digest_sha256
        && is_digest(&value.role_manifest_digest_sha256);
    valid.then_some(()).ok_or(KeyError::RoleBindingRejected)
}

pub(crate) fn validate_role_binding(
    policy: &KeyPolicy,
    claim: &HardwareRoleClaim,
    raw: &HardwareRoleBinding,
    verified: &VerifiedHardwareRoleBinding,
) -> Result<(), KeyError> {
    let required = [
        RoleBindingVerification::HardwareSealed,
        RoleBindingVerification::PublicKeyBinding,
        RoleBindingVerification::RoleClaim,
        RoleBindingVerification::Signature,
        RoleBindingVerification::DurableCounter,
    ];
    let exact = claim.claim_digest_sha256 == role_claim::digest(claim)
        && raw.claim_digest_sha256 == claim.claim_digest_sha256
        && verified.binding == *raw
        && verified.verifier_key_id == policy.attestation_verifier_key_id
        && verified.trust_revision == policy.attestation_trust_revision
        && required
            .iter()
            .all(|item| verified.verifications.contains(item))
        && valid_id(&raw.hardware_binding_ref);
    exact.then_some(()).ok_or(KeyError::RoleBindingRejected)
}

fn ledger_id(value: &str) -> bool {
    value
        .strip_prefix("ledger-instance:")
        .is_some_and(is_digest)
}
