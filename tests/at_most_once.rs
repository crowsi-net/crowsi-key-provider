#[allow(dead_code)]
use crate::support;

use std::sync::{Arc, Barrier};

use crowsi_key_provider::{KeyError, KeyProvider, SqliteReplayLedger};
use support::{HardwareProbe, RecoverablePort, SignBehavior, TestVerifier, clock, policy, request};

#[test]
fn cloned_ledgers_racing_the_same_request_never_sign_twice() {
    let (_directory, first_path, clone_path) = cloned_ledger_paths();
    let probe = HardwareProbe::default();
    let first = provider(&first_path, probe.clone());
    let clone = provider(&clone_path, probe.clone());
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = barrier.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        let mut value = first;
        value.sign(&request())
    });
    let clone_thread = std::thread::spawn(move || {
        barrier.wait();
        let mut value = clone;
        value.sign(&request())
    });
    let results = [first_thread.join().unwrap(), clone_thread.join().unwrap()];

    assert_eq!(probe.counts().0, 1);
    assert!(results.iter().any(Result::is_ok));
    assert!(
        results.iter().all(|value| {
            value.is_ok() || matches!(value, Err(KeyError::HardwareResultUnknown))
        })
    );
    assert_eq!(
        recover(&first_path, probe.clone()),
        recover(&clone_path, probe)
    );
}

#[test]
fn stale_clone_cannot_claim_a_different_request_or_advance_the_counter() {
    let (_directory, first_path, clone_path) = cloned_ledger_paths();
    let probe = HardwareProbe::default();
    let mut first = provider(&first_path, probe.clone());
    let mut clone = provider(&clone_path, probe.clone());
    first.sign(&request()).unwrap();

    let mut changed = request();
    changed.request_id = "request-b".into();
    changed.nonce = "nonce-bravo".into();
    assert_eq!(clone.sign(&changed), Err(KeyError::HardwareFenceRejected));
    assert_eq!(probe.counts().0, 1);
}

fn provider(
    path: &std::path::Path,
    probe: HardwareProbe,
) -> KeyProvider<RecoverablePort, TestVerifier, SqliteReplayLedger, support::FixedClock> {
    let ledger = SqliteReplayLedger::open(path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe);
    KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap()
}

fn recover(path: &std::path::Path, probe: HardwareProbe) -> Vec<u8> {
    let mut value = provider(path, probe);
    value.recover(&request()).unwrap().signature
}

fn cloned_ledger_paths() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.sqlite3");
    let clone = directory.path().join("clone.sqlite3");
    drop(SqliteReplayLedger::open(&first, &policy()).unwrap());
    std::fs::copy(&first, &clone).unwrap();
    (directory, first, clone)
}
