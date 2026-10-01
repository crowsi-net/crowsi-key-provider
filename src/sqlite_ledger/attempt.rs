use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{HardwareSigningOperation, KeyError, SigningAttempt, SigningAttemptJournal};

use super::{SqliteReplayLedger, attempt_decode, attempt_write, constraint, digest};

impl SigningAttemptJournal for SqliteReplayLedger {
    fn begin_signing_attempt(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyError::LedgerUnavailable)?;
        let replay = transaction.execute(
            "INSERT INTO signing_replay(request_hash, nonce_hash, challenge_hash)
             VALUES (?1, ?2, ?3)",
            params![digest(request_id), digest(nonce), digest(challenge_digest)],
        );
        if let Err(error) = replay {
            return if constraint(&error) {
                Err(KeyError::ReplayRejected)
            } else {
                Err(KeyError::LedgerUnavailable)
            };
        }
        transaction
            .execute(
                "INSERT INTO signing_attempt VALUES(
                 ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                 'invocation-pending',NULL)",
                params![
                    digest(request_id),
                    operation.request_binding_sha256,
                    operation.operation_id,
                    operation.ledger_instance_id,
                    operation.role_claim_digest_sha256,
                    operation.key_id,
                    operation.key_version,
                    operation.public_key_spki_sha256,
                    operation.purpose.as_str(),
                    operation.algorithm.as_str(),
                    operation.digest_sha256,
                    operation.request_issued_at_epoch_s,
                    operation.request_expires_at_epoch_s,
                    operation.recovery_deadline_epoch_s,
                    operation.previous_hardware_fence,
                    operation.hardware_fence,
                ],
            )
            .map_err(|_| KeyError::LedgerUnavailable)?;
        transaction
            .commit()
            .map_err(|_| KeyError::LedgerUnavailable)
    }

    fn load_signing_attempt(
        &mut self,
        request_id: &str,
        request_binding_sha256: &str,
    ) -> Result<Option<SigningAttempt>, KeyError> {
        let found = self
            .connection
            .query_row(
                "SELECT request_binding_sha256,operation_id,ledger_instance_id,
                 role_claim_digest_sha256,key_id,key_version,
                 public_key_spki_sha256,purpose,algorithm,signing_digest_sha256,
                 request_issued_at_epoch_s,request_expires_at_epoch_s,
                 recovery_deadline_epoch_s,previous_hardware_fence,
                 hardware_fence,state,signature
                 FROM signing_attempt WHERE request_hash=?1",
                [digest(request_id)],
                attempt_decode::read,
            )
            .optional()
            .map_err(|_| KeyError::LedgerUnavailable)?;
        match found {
            Some(value) if value.operation.request_binding_sha256 != request_binding_sha256 => {
                Err(KeyError::ReplayRejected)
            }
            value => Ok(value),
        }
    }

    fn mark_signing_result_unknown(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        attempt_write::mark_unknown(&self.connection, operation)
    }

    fn complete_signing_attempt(
        &mut self,
        operation: &HardwareSigningOperation,
        signature: &[u8],
    ) -> Result<(), KeyError> {
        attempt_write::complete(&self.connection, operation, signature)
    }
}
