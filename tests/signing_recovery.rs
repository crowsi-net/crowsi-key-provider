#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, KeyProvider, SqliteReplayLedger};
use support::{
    FailOnceLedger, FixedClock, HardwareProbe, NOW, RecoverablePort, SignBehavior, TestVerifier,
    clock, policy, request,
};

#[test]
fn response_loss_reads_the_completed_journal_without_signing_or_hardware_recovery() {
    let (directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
        let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock())
            .unwrap()
            .sign(&request())
            .unwrap();
    }
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let response = KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock())
        .unwrap()
        .recover(&request())
        .unwrap();
    assert_eq!(response.signature, [7; 64]);
    assert_eq!(probe.counts(), (1, 0));
    drop(directory);
}

#[test]
fn crash_after_sign_recovers_the_exact_hardware_operation_after_restart() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
        let port = RecoverablePort::new(SignBehavior::LoseResponse, probe.clone());
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        assert_eq!(
            provider.sign(&request()),
            Err(KeyError::HardwareResultUnknown)
        );
    }
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock())
        .unwrap()
        .recover(&request())
        .unwrap();
    assert_eq!(probe.counts(), (1, 1));
}

#[test]
fn exact_attempt_can_recover_after_request_expiry_within_the_bounded_window() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    create_unknown(&path, &probe, SignBehavior::LoseResponse);
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    KeyProvider::open(
        policy(),
        port,
        TestVerifier::ready(),
        ledger,
        FixedClock(vec![NOW + 11]),
    )
    .unwrap()
    .recover(&request())
    .unwrap();
    assert_eq!(probe.counts(), (1, 1));
}

#[test]
fn recovery_window_expiry_never_invokes_hardware_readback() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    create_unknown(&path, &probe, SignBehavior::LoseResponse);
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider = KeyProvider::open(
        policy(),
        port,
        TestVerifier::ready(),
        ledger,
        FixedClock(vec![NOW + 3_610]),
    )
    .unwrap();
    assert_eq!(
        provider.recover(&request()),
        Err(KeyError::RecoveryWindowExpired)
    );
    assert_eq!(probe.counts(), (1, 0));
}

#[test]
fn crash_before_journal_commit_is_recovered_without_a_second_sign() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger =
            FailOnceLedger::completion(SqliteReplayLedger::open(&path, &policy()).unwrap());
        let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        assert_eq!(
            provider.sign(&request()),
            Err(KeyError::HardwareResultUnknown)
        );
    }
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock())
        .unwrap()
        .recover(&request())
        .unwrap();
    assert_eq!(probe.counts(), (1, 1));
}

fn create_unknown(path: &std::path::Path, probe: &HardwareProbe, behavior: SignBehavior) {
    let ledger = SqliteReplayLedger::open(path, &policy()).unwrap();
    let port = RecoverablePort::new(behavior, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
}

fn ledger_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovery.sqlite3");
    (directory, path)
}
