use crate::{
    HardwareSigningOperation, KeyAlgorithm, KeyPurpose, SigningAttempt, SigningAttemptState,
};

pub(super) fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<SigningAttempt> {
    let purpose: String = row.get(7)?;
    let algorithm: String = row.get(8)?;
    let state: String = row.get(15)?;
    Ok(SigningAttempt {
        operation: HardwareSigningOperation {
            request_binding_sha256: row.get(0)?,
            operation_id: row.get(1)?,
            ledger_instance_id: row.get(2)?,
            role_claim_digest_sha256: row.get(3)?,
            key_id: row.get(4)?,
            key_version: row.get(5)?,
            public_key_spki_sha256: row.get(6)?,
            purpose: parse_purpose(&purpose)?,
            algorithm: parse_algorithm(&algorithm)?,
            digest_sha256: row.get(9)?,
            request_issued_at_epoch_s: row.get(10)?,
            request_expires_at_epoch_s: row.get(11)?,
            recovery_deadline_epoch_s: row.get(12)?,
            previous_hardware_fence: row.get(13)?,
            hardware_fence: row.get(14)?,
        },
        state: parse_state(&state)?,
        signature: row.get(16)?,
    })
}

fn parse_state(value: &str) -> rusqlite::Result<SigningAttemptState> {
    match value {
        "invocation-pending" => Ok(SigningAttemptState::InvocationPending),
        "result-unknown" => Ok(SigningAttemptState::ResultUnknown),
        "completed" => Ok(SigningAttemptState::Completed),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn parse_algorithm(value: &str) -> rusqlite::Result<KeyAlgorithm> {
    (value == KeyAlgorithm::EcdsaP256Sha256P1363LowS.as_str())
        .then_some(KeyAlgorithm::EcdsaP256Sha256P1363LowS)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn parse_purpose(value: &str) -> rusqlite::Result<KeyPurpose> {
    match value {
        "policy-administration" => Ok(KeyPurpose::PolicyAdministration),
        "coordinator-checkpoint" => Ok(KeyPurpose::CoordinatorCheckpoint),
        "pep-enforcement-receipt" => Ok(KeyPurpose::PepEnforcementReceipt),
        "independent-readback-report" => Ok(KeyPurpose::IndependentReadbackReport),
        "workload-certificate-issuance" => Ok(KeyPurpose::WorkloadCertificateIssuance),
        "certificate-authority-receipt" => Ok(KeyPurpose::CertificateAuthorityReceipt),
        "certificate-manager-commit-receipt" => Ok(KeyPurpose::CertificateManagerCommitReceipt),
        "certificate-manager-handoff-receipt" => Ok(KeyPurpose::CertificateManagerHandoffReceipt),
        "release" => Ok(KeyPurpose::Release),
        "rescue-recovery" => Ok(KeyPurpose::RescueRecovery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
