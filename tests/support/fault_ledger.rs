use crowsi_key_provider::{
    HardwareSigningOperation, KeyError, ProviderBindingJournal, ProviderLedgerBinding,
    ReplayLedger, SigningAttempt, SigningAttemptJournal, SqliteReplayLedger,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FailurePoint {
    Fence,
    Completion,
}

pub struct FailOnceLedger {
    inner: SqliteReplayLedger,
    point: FailurePoint,
    failed: bool,
}

impl FailOnceLedger {
    pub const fn fence(inner: SqliteReplayLedger) -> Self {
        Self {
            inner,
            point: FailurePoint::Fence,
            failed: false,
        }
    }

    pub const fn completion(inner: SqliteReplayLedger) -> Self {
        Self {
            inner,
            point: FailurePoint::Completion,
            failed: false,
        }
    }

    fn fail(&mut self, point: FailurePoint) -> bool {
        if self.point == point && !self.failed {
            self.failed = true;
            return true;
        }
        false
    }
}

impl ProviderBindingJournal for FailOnceLedger {
    fn provider_binding(&mut self) -> Result<ProviderLedgerBinding, KeyError> {
        self.inner.provider_binding()
    }

    fn advance_hardware_fence(&mut self, expected: u64, current: u64) -> Result<(), KeyError> {
        if self.fail(FailurePoint::Fence) {
            return Err(KeyError::LedgerUnavailable);
        }
        self.inner.advance_hardware_fence(expected, current)
    }
}

impl ReplayLedger for FailOnceLedger {
    fn observe_time(&mut self, now: u64) -> Result<(), KeyError> {
        self.inner.observe_time(now)
    }

    fn reserve(&mut self, request: &str, nonce: &str, challenge: &str) -> Result<(), KeyError> {
        self.inner.reserve(request, nonce, challenge)
    }
}

impl SigningAttemptJournal for FailOnceLedger {
    fn begin_signing_attempt(
        &mut self,
        request: &str,
        nonce: &str,
        challenge: &str,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        self.inner
            .begin_signing_attempt(request, nonce, challenge, operation)
    }

    fn load_signing_attempt(
        &mut self,
        request: &str,
        binding: &str,
    ) -> Result<Option<SigningAttempt>, KeyError> {
        self.inner.load_signing_attempt(request, binding)
    }

    fn mark_signing_result_unknown(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError> {
        self.inner.mark_signing_result_unknown(operation)
    }

    fn complete_signing_attempt(
        &mut self,
        operation: &HardwareSigningOperation,
        signature: &[u8],
    ) -> Result<(), KeyError> {
        if self.fail(FailurePoint::Completion) {
            return Err(KeyError::LedgerUnavailable);
        }
        self.inner.complete_signing_attempt(operation, signature)
    }
}
