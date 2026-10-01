use crowsi_key_provider::{KeyError, ReplayLedger, SqliteReplayLedger};
use std::os::unix::fs::PermissionsExt;

#[allow(dead_code)]
use crate::support;

#[test]
fn reservations_survive_restart_and_bind_both_identifiers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite3");
    {
        let mut ledger = SqliteReplayLedger::open(&path, &support::policy()).unwrap();
        ledger
            .reserve("request-alpha", "nonce-alpha", &"a".repeat(64))
            .unwrap();
    }
    let mut reopened = SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    assert_eq!(
        reopened.reserve("request-alpha", "nonce-other", &"b".repeat(64)),
        Err(KeyError::ReplayRejected)
    );
    assert_eq!(
        reopened.reserve("request-other", "nonce-alpha", &"b".repeat(64)),
        Err(KeyError::ReplayRejected)
    );
    reopened
        .reserve("request-other", "nonce-other", &"b".repeat(64))
        .unwrap();
}

#[test]
fn symlink_ledger_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.sqlite3");
    SqliteReplayLedger::open(&target, &support::policy()).unwrap();
    let link = directory.path().join("link.sqlite3");
    std::os::unix::fs::symlink(target, &link).unwrap();
    assert!(matches!(
        SqliteReplayLedger::open(link, &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
}

#[test]
fn lookalike_database_schema_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lookalike.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA application_id=1129466704;
             PRAGMA user_version=1;
             CREATE TABLE signing_replay(request_hash BLOB PRIMARY KEY);",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteReplayLedger::open(path, &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
}

#[test]
fn relative_or_public_parent_paths_are_rejected() {
    assert!(matches!(
        SqliteReplayLedger::open("relative.sqlite3", &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        SqliteReplayLedger::open(directory.path().join("replay.sqlite3"), &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
}

#[test]
fn an_existing_permissive_file_is_rejected_without_silent_chmod() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite3");
    std::fs::write(&path, b"not trusted").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        SqliteReplayLedger::open(&path, &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn a_symlinked_parent_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let private = root.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&private, &linked).unwrap();
    assert!(matches!(
        SqliteReplayLedger::open(linked.join("replay.sqlite3"), &support::policy()),
        Err(KeyError::LedgerUnavailable)
    ));
}

#[test]
fn trusted_time_watermark_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("clock.sqlite3");
    {
        let mut ledger = SqliteReplayLedger::open(&path, &support::policy()).unwrap();
        ledger.observe_time(1_800_000_000).unwrap();
    }
    let mut reopened = SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    assert_eq!(
        reopened.observe_time(1_799_999_999),
        Err(KeyError::TrustedTimeUnavailable)
    );
    reopened.observe_time(1_800_000_001).unwrap();
}

#[test]
fn a_ledger_cannot_be_reused_for_another_key_or_trust_domain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bound.sqlite3");
    SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    let mut changed = support::policy();
    changed.key_version = "release-key-version-2".into();
    assert_eq!(
        SqliteReplayLedger::open(&path, &changed).err(),
        Some(KeyError::LedgerUnavailable)
    );
    let mut changed_manifest = support::policy();
    changed_manifest.role_manifest_digest_sha256 = "f".repeat(64);
    assert_eq!(
        SqliteReplayLedger::open(&path, &changed_manifest).err(),
        Some(KeyError::LedgerUnavailable)
    );
}

#[test]
fn a_deleted_policy_binding_is_not_silently_reinitialized() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deleted-binding.sqlite3");
    SqliteReplayLedger::open(&path, &support::policy()).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("DELETE FROM ledger_binding", [])
        .unwrap();
    drop(connection);
    assert_eq!(
        SqliteReplayLedger::open(&path, &support::policy()).err(),
        Some(KeyError::LedgerUnavailable)
    );
}
