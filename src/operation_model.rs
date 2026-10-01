use crate::{KeyAlgorithm, KeyPurpose};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareSigningOperation {
    pub operation_id: String,
    pub request_binding_sha256: String,
    pub ledger_instance_id: String,
    pub role_claim_digest_sha256: String,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: KeyPurpose,
    pub algorithm: KeyAlgorithm,
    pub digest_sha256: String,
    pub request_issued_at_epoch_s: u64,
    pub request_expires_at_epoch_s: u64,
    pub recovery_deadline_epoch_s: u64,
    pub previous_hardware_fence: u64,
    pub hardware_fence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareOperationDisposition {
    Claimed,
    Existing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareOperationClaim {
    pub operation_id: String,
    pub request_binding_sha256: String,
    pub ledger_instance_id: String,
    pub role_claim_digest_sha256: String,
    pub previous_hardware_fence: u64,
    pub hardware_fence: u64,
    pub disposition: HardwareOperationDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningAttemptState {
    InvocationPending,
    ResultUnknown,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningAttempt {
    pub operation: HardwareSigningOperation,
    pub state: SigningAttemptState,
    pub signature: Option<Vec<u8>>,
}
