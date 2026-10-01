use crate::{
    HardwareKeyPort, HardwareOperationClaim, IndependentKeyVerifier, KeyError,
    ProviderBindingJournal, ReplayLedger, SigningAttemptJournal, SigningRequestV1,
    SigningResponseV2, TrustedClock,
};

use super::{KeyProvider, RESPONSE_SCHEMA};

impl<P, V, L, C> KeyProvider<P, V, L, C>
where
    P: HardwareKeyPort,
    V: IndependentKeyVerifier,
    L: ReplayLedger + SigningAttemptJournal + ProviderBindingJournal,
    C: TrustedClock,
{
    pub(super) fn valid_operation_claim(
        operation: &crate::HardwareSigningOperation,
        claim: &HardwareOperationClaim,
    ) -> bool {
        claim.operation_id == operation.operation_id
            && claim.request_binding_sha256 == operation.request_binding_sha256
            && claim.ledger_instance_id == operation.ledger_instance_id
            && claim.role_claim_digest_sha256 == operation.role_claim_digest_sha256
            && claim.previous_hardware_fence == operation.previous_hardware_fence
            && claim.hardware_fence == operation.hardware_fence
    }

    pub(super) fn advance_fence(
        &mut self,
        operation: &crate::HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        self.ledger
            .advance_hardware_fence(operation.previous_hardware_fence, operation.hardware_fence)?;
        self.ledger_fence = operation.hardware_fence;
        self.hardware_fence = operation.hardware_fence;
        self.recovery_only = false;
        Ok(())
    }

    pub(super) fn trusted_now(&mut self) -> Result<u64, KeyError> {
        let now = self.clock.now_epoch_s()?;
        self.ledger.observe_time(now)?;
        if self.last_now.is_some_and(|previous| now < previous) {
            return Err(KeyError::TrustedTimeUnavailable);
        }
        self.last_now = Some(now);
        Ok(now)
    }

    pub(super) fn signature_is_valid(
        &mut self,
        key: &crate::VerifiedHardwareAttestation,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        signature.len() == self.policy.algorithm.signature_length()
            && self
                .verifier
                .verify_signature(key, digest, signature)
                .unwrap_or(false)
    }

    pub(super) fn unknown<T>(
        &mut self,
        operation: &crate::HardwareSigningOperation,
    ) -> Result<T, KeyError> {
        let _ = self.ledger.mark_signing_result_unknown(operation);
        Err(KeyError::HardwareResultUnknown)
    }

    pub(super) fn response(
        request: &SigningRequestV1,
        signature: Vec<u8>,
        attestation: &crate::HardwareAttestation,
    ) -> SigningResponseV2 {
        SigningResponseV2 {
            schema: RESPONSE_SCHEMA.into(),
            request_id: request.request_id.clone(),
            digest_sha256: request.digest_sha256.clone(),
            signature,
            attestation: attestation.into(),
            key_operation_performed: true,
            external_actions: false,
        }
    }
}
