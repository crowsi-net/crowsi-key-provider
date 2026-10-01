use std::path::Path;

use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{KeyError, KeyPolicy, ReplayLedger, ledger_binding, secure_path, sqlite_schema};

mod attempt;
mod attempt_decode;
mod attempt_write;
mod binding;

/// Durable one-attempt ledger used before a hardware key operation.
pub struct SqliteReplayLedger {
    pub(super) connection: Connection,
}

impl SqliteReplayLedger {
    /// Opens an owner-only `SQLite` ledger and creates its closed schema.
    ///
    /// # Errors
    ///
    /// Fails for symlinks, non-files, insecure storage setup, or `SQLite` errors.
    pub fn open(path: impl AsRef<Path>, policy: &KeyPolicy) -> Result<Self, KeyError> {
        let path = path.as_ref();
        let existed = secure_path::prepare_file(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE;
        let mut connection =
            Connection::open_with_flags(path, flags).map_err(|_| KeyError::LedgerUnavailable)?;
        if existed
            && (!sqlite_schema::version_matches(&connection)
                || !sqlite_schema::schema_matches(&connection))
        {
            return Err(KeyError::LedgerUnavailable);
        }
        connection
            .execute_batch(&format!(
                "PRAGMA trusted_schema=OFF;
                 PRAGMA foreign_keys=ON;
                 PRAGMA application_id=1129466704;
                 PRAGMA user_version=5;
                 {}
                 {}
                 {}
                 {}",
                sqlite_schema::REPLAY_DDL,
                sqlite_schema::CLOCK_DDL,
                sqlite_schema::BINDING_DDL,
                sqlite_schema::ATTEMPT_DDL,
            ))
            .map_err(|_| KeyError::LedgerUnavailable)?;
        if !sqlite_schema::schema_matches(&connection) {
            return Err(KeyError::LedgerUnavailable);
        }
        ledger_binding::bind(&mut connection, policy, !existed)?;
        Ok(Self { connection })
    }
}

impl ReplayLedger for SqliteReplayLedger {
    fn observe_time(&mut self, now_epoch_s: u64) -> Result<(), KeyError> {
        let now = i64::try_from(now_epoch_s).map_err(|_| KeyError::TrustedTimeUnavailable)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyError::LedgerUnavailable)?;
        let previous = transaction
            .query_row(
                "SELECT epoch_s FROM trusted_clock_watermark WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| KeyError::LedgerUnavailable)?;
        if previous.is_some_and(|value| now < value) {
            return Err(KeyError::TrustedTimeUnavailable);
        }
        transaction
            .execute(
                "INSERT INTO trusted_clock_watermark(singleton, epoch_s) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET epoch_s=excluded.epoch_s",
                [now],
            )
            .map_err(|_| KeyError::LedgerUnavailable)?;
        transaction
            .commit()
            .map_err(|_| KeyError::LedgerUnavailable)
    }

    fn reserve(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
    ) -> Result<(), KeyError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyError::LedgerUnavailable)?;
        let result = transaction.execute(
            "INSERT INTO signing_replay(request_hash, nonce_hash, challenge_hash)
             VALUES (?1, ?2, ?3)",
            params![digest(request_id), digest(nonce), digest(challenge_digest)],
        );
        match result {
            Ok(1) => transaction
                .commit()
                .map_err(|_| KeyError::LedgerUnavailable),
            Err(error) if constraint(&error) => Err(KeyError::ReplayRejected),
            _ => Err(KeyError::LedgerUnavailable),
        }
    }
}

pub(super) fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

pub(super) fn constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(value, _)
            if value.code == ErrorCode::ConstraintViolation
    )
}
