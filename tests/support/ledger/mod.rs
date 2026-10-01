use std::collections::{BTreeMap, BTreeSet};

use crowsi_key_provider::{
    HardwareSigningOperation, KeyError, ProviderLedgerBinding, SigningAttempt,
};

mod attempt;
mod binding;
mod replay;

pub struct MemoryLedger {
    pub(super) requests: BTreeSet<String>,
    pub(super) nonces: BTreeSet<String>,
    pub(super) challenges: BTreeSet<String>,
    pub(super) clock_watermark: Option<u64>,
    pub(super) attempts: BTreeMap<String, SigningAttempt>,
    pub(super) binding: ProviderLedgerBinding,
}

impl Default for MemoryLedger {
    fn default() -> Self {
        Self {
            requests: BTreeSet::new(),
            nonces: BTreeSet::new(),
            challenges: BTreeSet::new(),
            clock_watermark: None,
            attempts: BTreeMap::new(),
            binding: ProviderLedgerBinding {
                ledger_instance_id: format!("ledger-instance:{}", "1".repeat(64)),
                role_manifest_digest_sha256: "e".repeat(64),
                hardware_fence: 0,
            },
        }
    }
}

impl MemoryLedger {
    pub(super) fn exact_attempt(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<&mut SigningAttempt, KeyError> {
        self.attempts
            .values_mut()
            .find(|value| value.operation == *operation)
            .ok_or(KeyError::LedgerUnavailable)
    }
}
