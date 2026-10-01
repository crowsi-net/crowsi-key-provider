use crowsi_key_provider::{
    HardwareSigningOperation, KeyError, SigningAttempt, SigningAttemptJournal, SigningAttemptState,
};

use super::MemoryLedger;
use crowsi_key_provider::ReplayLedger;

impl SigningAttemptJournal for MemoryLedger {
    fn begin_signing_attempt(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        self.reserve(request_id, nonce, challenge_digest)?;
        self.attempts.insert(
            request_id.into(),
            SigningAttempt {
                operation: operation.clone(),
                state: SigningAttemptState::InvocationPending,
                signature: None,
            },
        );
        Ok(())
    }

    fn load_signing_attempt(
        &mut self,
        request_id: &str,
        binding: &str,
    ) -> Result<Option<SigningAttempt>, KeyError> {
        let result = self.attempts.get(request_id).cloned();
        if result
            .as_ref()
            .is_some_and(|value| value.operation.request_binding_sha256 != binding)
        {
            return Err(KeyError::ReplayRejected);
        }
        Ok(result)
    }

    fn mark_signing_result_unknown(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        let attempt = self.exact_attempt(operation)?;
        if attempt.state != SigningAttemptState::Completed {
            attempt.state = SigningAttemptState::ResultUnknown;
        }
        Ok(())
    }

    fn complete_signing_attempt(
        &mut self,
        operation: &HardwareSigningOperation,
        signature: &[u8],
    ) -> Result<(), KeyError> {
        let attempt = self.exact_attempt(operation)?;
        if attempt
            .signature
            .as_ref()
            .is_some_and(|value| value != signature)
        {
            return Err(KeyError::LedgerUnavailable);
        }
        attempt.state = SigningAttemptState::Completed;
        attempt.signature = Some(signature.to_vec());
        Ok(())
    }
}
