use sha2::{Digest, Sha256};

use crate::{HardwareRoleClaim, HardwareSigningOperation, KeyError, KeyPolicy, SigningRequestV1};

pub(crate) fn build(
    policy: &KeyPolicy,
    request: &SigningRequestV1,
    claim: &HardwareRoleClaim,
    hardware_fence: u64,
) -> Result<HardwareSigningOperation, KeyError> {
    let recovery_deadline_epoch_s = request
        .expires_at_epoch_s
        .checked_add(policy.max_recovery_ttl_seconds)
        .ok_or(KeyError::RequestRejected)?;
    let next_fence = hardware_fence
        .checked_add(1)
        .ok_or(KeyError::HardwareFenceRejected)?;
    let binding = request_binding(policy, request);
    Ok(HardwareSigningOperation {
        operation_id: operation_id(&claim.ledger_instance_id, &binding),
        request_binding_sha256: binding,
        ledger_instance_id: claim.ledger_instance_id.clone(),
        role_claim_digest_sha256: claim.claim_digest_sha256.clone(),
        key_id: policy.key_id.clone(),
        key_version: policy.key_version.clone(),
        public_key_spki_sha256: policy.public_key_spki_sha256.clone(),
        purpose: policy.purpose,
        algorithm: policy.algorithm,
        digest_sha256: request.digest_sha256.clone(),
        request_issued_at_epoch_s: request.issued_at_epoch_s,
        request_expires_at_epoch_s: request.expires_at_epoch_s,
        recovery_deadline_epoch_s,
        previous_hardware_fence: hardware_fence,
        hardware_fence: next_fence,
    })
}

pub(crate) fn request_binding(policy: &KeyPolicy, request: &SigningRequestV1) -> String {
    let mut hash = Sha256::new();
    for value in [
        request.schema.as_str(),
        &request.request_id,
        &request.nonce,
        &request.security_domain,
        &request.deployment_id,
        &request.workload_id,
        &request.key_id,
        request.purpose.as_str(),
        &request.digest_sha256,
        &policy.key_version,
        &policy.public_key_spki_sha256,
        policy.source.as_str(),
        policy.algorithm.as_str(),
        &policy.attestation_verifier_key_id,
        &policy.role_manifest_digest_sha256,
    ] {
        hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(request.issued_at_epoch_s.to_be_bytes());
    hash.update(request.expires_at_epoch_s.to_be_bytes());
    hash.update(policy.attestation_trust_revision.to_be_bytes());
    hash.update(policy.max_recovery_ttl_seconds.to_be_bytes());
    format!("{:x}", hash.finalize())
}

pub(crate) fn operation_id(ledger_instance_id: &str, request_binding: &str) -> String {
    let mut hash = Sha256::new();
    for value in [
        "crowsi-hardware-operation-v2",
        ledger_instance_id,
        request_binding,
    ] {
        hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("hardware-operation:{:x}", hash.finalize())
}
