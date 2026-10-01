#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, ProviderBindingJournal, SqliteReplayLedger};

#[test]
fn a_deleted_attempt_journal_is_not_silently_reinitialized() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deleted-attempt.sqlite3");
    SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("DROP TABLE signing_attempt", [])
        .unwrap();
    drop(connection);
    assert_eq!(
        SqliteReplayLedger::open(&path, &support::policy()).err(),
        Some(KeyError::LedgerUnavailable)
    );
}

#[test]
fn legacy_v4_is_rejected_instead_of_implicitly_migrated() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.sqlite3");
    SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.pragma_update(None, "user_version", 4).unwrap();
    drop(connection);
    assert_eq!(
        SqliteReplayLedger::open(&path, &support::policy()).err(),
        Some(KeyError::LedgerUnavailable)
    );
}

#[test]
fn every_new_ledger_receives_a_distinct_csprng_instance_identifier() {
    let directory = tempfile::tempdir().unwrap();
    let mut first =
        SqliteReplayLedger::open(directory.path().join("first.sqlite3"), &support::policy())
            .unwrap();
    let mut second =
        SqliteReplayLedger::open(directory.path().join("second.sqlite3"), &support::policy())
            .unwrap();
    let first_id = first.provider_binding().unwrap().ledger_instance_id;
    let second_id = second.provider_binding().unwrap().ledger_instance_id;

    for value in [&first_id, &second_id] {
        assert_eq!(value.len(), 80);
        assert!(value.starts_with("ledger-instance:"));
        assert!(
            value[16..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
    }
    assert_ne!(first_id, second_id);
}
