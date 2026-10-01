use crate::{
    AttestationChallenge, HardwareKeyPort, IndependentKeyVerifier, KeyError,
    ProviderBindingJournal, ReplayLedger, SigningAttemptJournal, SigningAttemptState,
    SigningRequestV1, SigningResponseV2, TrustedClock, signing_operation,
    validation::{validate_attestation, validate_request_binding},
};

use super::KeyProvider;

impl<P, V, L, C> KeyProvider<P, V, L, C>
where
    P: HardwareKeyPort,
    V: IndependentKeyVerifier,
    L: ReplayLedger + SigningAttemptJournal + ProviderBindingJournal,
    C: TrustedClock,
{
    /// Resolves an ambiguous attempt by durable or hardware readback only.
    ///
    /// # Errors
    ///
    /// Rejects changed requests, missing attempts, unsupported readback, and
    /// any result that cannot be independently verified.
    pub fn recover(&mut self, request: &SigningRequestV1) -> Result<SigningResponseV2, KeyError> {
        let now = self.trusted_now()?;
        let digest = validate_request_binding(&self.policy, request)?;
        let binding = signing_operation::request_binding(&self.policy, request);
        let attempt = self
            .ledger
            .load_signing_attempt(&request.request_id, &binding)?
            .ok_or(KeyError::RecoveryNotFound)?;
        if !self.operation_matches(request, &attempt.operation) {
            return Err(KeyError::ReplayRejected);
        }
        if now >= attempt.operation.recovery_deadline_epoch_s {
            return Err(KeyError::RecoveryWindowExpired);
        }
        let challenge = AttestationChallenge::for_recovery(
            &self.policy,
            request,
            now,
            attempt.operation.recovery_deadline_epoch_s,
        )?;
        let attestation =
            self.port
                .attest(&request.key_id, &self.policy.key_version, &challenge)?;
        let verified = self.verifier.verify_attestation(&attestation, &challenge)?;
        validate_attestation(&self.policy, &attestation, &verified, &challenge, now)?;
        let signature = match (attempt.state, attempt.signature) {
            (SigningAttemptState::Completed, Some(value)) => value,
            (SigningAttemptState::InvocationPending | SigningAttemptState::ResultUnknown, None) => {
                self.read_back(&attempt.operation)?
            }
            _ => return Err(KeyError::LedgerUnavailable),
        };
        if !self.signature_is_valid(&verified, &digest, &signature) {
            return self.unknown(&attempt.operation);
        }
        self.ledger
            .complete_signing_attempt(&attempt.operation, &signature)
            .map_err(|_| KeyError::HardwareResultUnknown)?;
        if self.recovery_only {
            self.advance_fence(&attempt.operation)?;
        }
        Ok(Self::response(request, signature, &attestation))
    }

    fn read_back(
        &mut self,
        operation: &crate::HardwareSigningOperation,
    ) -> Result<Vec<u8>, KeyError> {
        match self.port.recover_signature(operation) {
            Ok(Some(value)) => Ok(value),
            Err(KeyError::RecoveryUnsupported) => {
                let _ = self.ledger.mark_signing_result_unknown(operation);
                Err(KeyError::RecoveryUnsupported)
            }
            Ok(None) | Err(_) => self.unknown(operation),
        }
    }

    fn operation_matches(
        &self,
        request: &SigningRequestV1,
        value: &crate::HardwareSigningOperation,
    ) -> bool {
        value.request_binding_sha256 == signing_operation::request_binding(&self.policy, request)
            && value.operation_id
                == signing_operation::operation_id(
                    &self.role_claim.ledger_instance_id,
                    &value.request_binding_sha256,
                )
            && value.key_id == self.policy.key_id
            && value.ledger_instance_id == self.role_claim.ledger_instance_id
            && value.role_claim_digest_sha256 == self.role_claim.claim_digest_sha256
            && value.key_version == self.policy.key_version
            && value.public_key_spki_sha256 == self.policy.public_key_spki_sha256
            && value.purpose == self.policy.purpose
            && value.algorithm == self.policy.algorithm
            && value.digest_sha256 == request.digest_sha256
            && value.request_issued_at_epoch_s == request.issued_at_epoch_s
            && value.request_expires_at_epoch_s == request.expires_at_epoch_s
            && value.recovery_deadline_epoch_s
                == request
                    .expires_at_epoch_s
                    .checked_add(self.policy.max_recovery_ttl_seconds)
                    .unwrap_or_default()
            && value.hardware_fence
                == value
                    .previous_hardware_fence
                    .checked_add(1)
                    .unwrap_or_default()
            && value.hardware_fence <= self.hardware_fence
            && (!self.recovery_only
                || (value.previous_hardware_fence == self.ledger_fence
                    && value.hardware_fence == self.hardware_fence))
    }
}
