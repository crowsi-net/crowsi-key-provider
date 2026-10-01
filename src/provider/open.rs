use crate::{
    HardwareKeyPort, IndependentKeyVerifier, KeyError, KeyPolicy, ProviderBindingJournal,
    ReplayLedger, SigningAttemptJournal, TrustedClock, role_claim, role_validation,
    validation::validate_policy,
};

use super::KeyProvider;

impl<P, V, L, C> KeyProvider<P, V, L, C>
where
    P: HardwareKeyPort,
    V: IndependentKeyVerifier,
    L: ReplayLedger + SigningAttemptJournal + ProviderBindingJournal,
    C: TrustedClock,
{
    /// Opens a provider only after independently verifying its sealed role.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy, changed ledger identity, role reuse, or fence drift.
    pub fn open(
        policy: KeyPolicy,
        mut port: P,
        mut verifier: V,
        mut ledger: L,
        clock: C,
    ) -> Result<Self, KeyError> {
        validate_policy(&policy)?;
        let ledger_binding = ledger.provider_binding()?;
        role_validation::validate_ledger_binding(&policy, &ledger_binding)?;
        let role_claim = role_claim::build(&policy, &ledger_binding);
        let raw = port.bind_or_verify_role(&role_claim)?;
        let verification = verifier.verify_role_binding(&raw, &role_claim)?;
        role_validation::validate_role_binding(&policy, &role_claim, &raw, &verification)?;
        let recovery_only = match raw.current_fence.checked_sub(ledger_binding.hardware_fence) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(KeyError::HardwareFenceRejected),
        };
        Ok(Self {
            policy,
            port,
            verifier,
            ledger,
            clock,
            last_now: None,
            role_claim,
            ledger_fence: ledger_binding.hardware_fence,
            hardware_fence: raw.current_fence,
            recovery_only,
        })
    }
}
