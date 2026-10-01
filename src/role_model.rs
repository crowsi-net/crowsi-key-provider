use std::collections::BTreeSet;

use crate::{KeyAlgorithm, KeyPurpose, KeySource};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderLedgerBinding {
    pub ledger_instance_id: String,
    pub role_manifest_digest_sha256: String,
    pub hardware_fence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareRoleClaim {
    pub security_domain: String,
    pub deployment_id: String,
    pub workload_id: String,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: KeyPurpose,
    pub source: KeySource,
    pub algorithm: KeyAlgorithm,
    pub ledger_instance_id: String,
    pub role_manifest_digest_sha256: String,
    pub claim_digest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareRoleBinding {
    pub claim_digest_sha256: String,
    pub hardware_binding_ref: String,
    pub current_fence: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RoleBindingVerification {
    HardwareSealed,
    PublicKeyBinding,
    RoleClaim,
    Signature,
    DurableCounter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHardwareRoleBinding {
    pub binding: HardwareRoleBinding,
    pub verifier_key_id: String,
    pub trust_revision: u64,
    pub verifications: BTreeSet<RoleBindingVerification>,
}
