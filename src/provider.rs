use crate::{
    AttestationChallenge, HardwareKeyPort, HardwareOperationDisposition, HardwareRoleClaim,
    IndependentKeyVerifier, KeyError, KeyPolicy, ProviderBindingJournal, ReplayLedger,
    SigningAttemptJournal, SigningRequestV1, SigningResponseV2, TrustedClock, signing_operation,
    validation::{validate_attestation, validate_request},
};

const RESPONSE_SCHEMA: &str = "crowsi://keys/signing-response/v2";

mod open;
mod recovery;
mod support;

pub struct KeyProvider<P, V, L, C> {
    pub(super) policy: KeyPolicy,
    pub(super) port: P,
    pub(super) verifier: V,
    pub(super) ledger: L,
    pub(super) clock: C,
    pub(super) last_now: Option<u64>,
    pub(super) role_claim: HardwareRoleClaim,
    pub(super) ledger_fence: u64,
    pub(super) hardware_fence: u64,
    pub(super) recovery_only: bool,
}

impl<P, V, L, C> KeyProvider<P, V, L, C>
where
    P: HardwareKeyPort,
    V: IndependentKeyVerifier,
    L: ReplayLedger + SigningAttemptJournal + ProviderBindingJournal,
    C: TrustedClock,
{
    /// Performs one policy-bound hardware signing operation.
    ///
    /// # Errors
    ///
    /// Rejects invalid requests, attestation failures, replays, and unknown results.
    pub fn sign(&mut self, request: &SigningRequestV1) -> Result<SigningResponseV2, KeyError> {
        if self.recovery_only {
            return Err(KeyError::HardwareFenceRejected);
        }
        let now = self.trusted_now()?;
        let digest = validate_request(&self.policy, request, now)?;
        let challenge = AttestationChallenge::new(&self.policy, request, now)?;
        let attestation =
            self.port
                .attest(&request.key_id, &self.policy.key_version, &challenge)?;
        let verified_attestation = self.verifier.verify_attestation(&attestation, &challenge)?;
        validate_attestation(
            &self.policy,
            &attestation,
            &verified_attestation,
            &challenge,
            now,
        )?;
        let signing_now = self.trusted_now()?;
        validate_request(&self.policy, request, signing_now)?;
        validate_attestation(
            &self.policy,
            &attestation,
            &verified_attestation,
            &challenge,
            signing_now,
        )?;
        let operation =
            signing_operation::build(&self.policy, request, &self.role_claim, self.hardware_fence)?;
        self.ledger.begin_signing_attempt(
            &request.request_id,
            &request.nonce,
            &challenge.digest_sha256,
            &operation,
        )?;
        let claim = match self.port.claim_operation(&operation) {
            Ok(value) if Self::valid_operation_claim(&operation, &value) => value,
            Ok(_) | Err(KeyError::HardwareResultUnknown) => return self.unknown(&operation),
            Err(error) => return Err(error),
        };
        if self.advance_fence(&operation).is_err() {
            return self.unknown(&operation);
        }
        let signature = match claim.disposition {
            HardwareOperationDisposition::Claimed => {
                let Ok(value) = self.port.sign_digest(&operation) else {
                    return self.unknown(&operation);
                };
                value
            }
            HardwareOperationDisposition::Existing => match self.port.recover_signature(&operation)
            {
                Ok(Some(value)) => value,
                Err(KeyError::RecoveryUnsupported) => {
                    let _ = self.ledger.mark_signing_result_unknown(&operation);
                    return Err(KeyError::RecoveryUnsupported);
                }
                Ok(None) | Err(_) => return self.unknown(&operation),
            },
        };
        if !self.signature_is_valid(&verified_attestation, &digest, &signature) {
            return self.unknown(&operation);
        }
        if self
            .ledger
            .complete_signing_attempt(&operation, &signature)
            .is_err()
        {
            return Err(KeyError::HardwareResultUnknown);
        }
        Ok(Self::response(request, signature, &attestation))
    }
}
