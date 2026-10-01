use rusqlite::params;

use crate::{KeyError, ProviderBindingJournal, ProviderLedgerBinding};

use super::SqliteReplayLedger;

impl ProviderBindingJournal for SqliteReplayLedger {
    fn provider_binding(&mut self) -> Result<ProviderLedgerBinding, KeyError> {
        self.connection
            .query_row(
                "SELECT ledger_instance_id,role_manifest_digest_sha256,hardware_fence
                 FROM ledger_binding WHERE singleton=1",
                [],
                |row| {
                    Ok(ProviderLedgerBinding {
                        ledger_instance_id: row.get(0)?,
                        role_manifest_digest_sha256: row.get(1)?,
                        hardware_fence: row.get(2)?,
                    })
                },
            )
            .map_err(|_| KeyError::LedgerUnavailable)
    }

    fn advance_hardware_fence(&mut self, expected: u64, current: u64) -> Result<(), KeyError> {
        if current
            != expected
                .checked_add(1)
                .ok_or(KeyError::HardwareFenceRejected)?
        {
            return Err(KeyError::HardwareFenceRejected);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE ledger_binding SET hardware_fence=?1
                 WHERE singleton=1 AND hardware_fence=?2",
                params![current, expected],
            )
            .map_err(|_| KeyError::LedgerUnavailable)?;
        if changed == 1 {
            return Ok(());
        }
        let observed = self.provider_binding()?.hardware_fence;
        (observed == current)
            .then_some(())
            .ok_or(KeyError::HardwareFenceRejected)
    }
}
