use crowsi_key_provider::{KeyError, ProviderBindingJournal, ProviderLedgerBinding};

use super::MemoryLedger;

impl ProviderBindingJournal for MemoryLedger {
    fn provider_binding(&mut self) -> Result<ProviderLedgerBinding, KeyError> {
        Ok(self.binding.clone())
    }

    fn advance_hardware_fence(&mut self, expected: u64, current: u64) -> Result<(), KeyError> {
        if current != expected + 1 {
            return Err(KeyError::HardwareFenceRejected);
        }
        if self.binding.hardware_fence == expected {
            self.binding.hardware_fence = current;
        }
        (self.binding.hardware_fence == current)
            .then_some(())
            .ok_or(KeyError::HardwareFenceRejected)
    }
}
