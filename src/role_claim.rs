use sha2::{Digest, Sha256};

use crate::{HardwareRoleClaim, KeyPolicy, ProviderLedgerBinding};

pub(crate) fn build(policy: &KeyPolicy, ledger: &ProviderLedgerBinding) -> HardwareRoleClaim {
    let mut claim = HardwareRoleClaim {
        security_domain: policy.security_domain.clone(),
        deployment_id: policy.deployment_id.clone(),
        workload_id: policy.workload_id.clone(),
        key_id: policy.key_id.clone(),
        key_version: policy.key_version.clone(),
        public_key_spki_sha256: policy.public_key_spki_sha256.clone(),
        purpose: policy.purpose,
        source: policy.source,
        algorithm: policy.algorithm,
        ledger_instance_id: ledger.ledger_instance_id.clone(),
        role_manifest_digest_sha256: policy.role_manifest_digest_sha256.clone(),
        claim_digest_sha256: String::new(),
    };
    claim.claim_digest_sha256 = digest(&claim);
    claim
}

pub(crate) fn digest(value: &HardwareRoleClaim) -> String {
    let mut hash = Sha256::new();
    for field in [
        "crowsi-hardware-role-claim-v1",
        value.security_domain.as_str(),
        &value.deployment_id,
        &value.workload_id,
        &value.key_id,
        &value.key_version,
        &value.public_key_spki_sha256,
        value.purpose.as_str(),
        value.source.as_str(),
        value.algorithm.as_str(),
        &value.ledger_instance_id,
        &value.role_manifest_digest_sha256,
    ] {
        hash.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
