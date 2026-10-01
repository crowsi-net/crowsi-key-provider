use rusqlite::{Connection, params};

use crate::{HardwareSigningOperation, KeyError};

pub(super) fn mark_unknown(
    connection: &Connection,
    operation: &HardwareSigningOperation,
) -> Result<(), KeyError> {
    let changed = connection
        .execute(
            "UPDATE signing_attempt SET state=CASE
             WHEN state='completed' THEN state ELSE 'result-unknown' END
             WHERE operation_id=?1 AND request_binding_sha256=?2
             AND ledger_instance_id=?3 AND role_claim_digest_sha256=?4
             AND signing_digest_sha256=?5 AND key_id=?6 AND key_version=?7
             AND public_key_spki_sha256=?8 AND purpose=?9 AND algorithm=?10
             AND request_issued_at_epoch_s=?11 AND request_expires_at_epoch_s=?12
             AND recovery_deadline_epoch_s=?13
             AND previous_hardware_fence=?14 AND hardware_fence=?15",
            params![
                operation.operation_id,
                operation.request_binding_sha256,
                operation.ledger_instance_id,
                operation.role_claim_digest_sha256,
                operation.digest_sha256,
                operation.key_id,
                operation.key_version,
                operation.public_key_spki_sha256,
                operation.purpose.as_str(),
                operation.algorithm.as_str(),
                operation.request_issued_at_epoch_s,
                operation.request_expires_at_epoch_s,
                operation.recovery_deadline_epoch_s,
                operation.previous_hardware_fence,
                operation.hardware_fence,
            ],
        )
        .map_err(|_| KeyError::LedgerUnavailable)?;
    one(changed)
}

pub(super) fn complete(
    connection: &Connection,
    operation: &HardwareSigningOperation,
    signature: &[u8],
) -> Result<(), KeyError> {
    if signature.len() != operation.algorithm.signature_length() {
        return Err(KeyError::LedgerUnavailable);
    }
    let changed = connection
        .execute(
            "UPDATE signing_attempt SET state='completed',signature=?16
             WHERE operation_id=?1 AND request_binding_sha256=?2
             AND ledger_instance_id=?3 AND role_claim_digest_sha256=?4
             AND signing_digest_sha256=?5 AND key_id=?6 AND key_version=?7
             AND public_key_spki_sha256=?8 AND purpose=?9 AND algorithm=?10
             AND request_issued_at_epoch_s=?11 AND request_expires_at_epoch_s=?12
             AND recovery_deadline_epoch_s=?13
             AND previous_hardware_fence=?14 AND hardware_fence=?15
             AND (state!='completed' OR signature=?16)",
            params![
                operation.operation_id,
                operation.request_binding_sha256,
                operation.ledger_instance_id,
                operation.role_claim_digest_sha256,
                operation.digest_sha256,
                operation.key_id,
                operation.key_version,
                operation.public_key_spki_sha256,
                operation.purpose.as_str(),
                operation.algorithm.as_str(),
                operation.request_issued_at_epoch_s,
                operation.request_expires_at_epoch_s,
                operation.recovery_deadline_epoch_s,
                operation.previous_hardware_fence,
                operation.hardware_fence,
                signature,
            ],
        )
        .map_err(|_| KeyError::LedgerUnavailable)?;
    one(changed)
}

fn one(changed: usize) -> Result<(), KeyError> {
    (changed == 1)
        .then_some(())
        .ok_or(KeyError::LedgerUnavailable)
}
