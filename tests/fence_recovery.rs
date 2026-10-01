#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, KeyProvider, ProviderBindingJournal, SqliteReplayLedger};
use support::{
    FailOnceLedger, HardwareProbe, RecoverablePort, SignBehavior, Tamper, TamperingPort,
    TestVerifier, clock, policy, request,
};

#[test]
fn hardware_claim_before_database_fence_enters_readback_only_recovery() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger = FailOnceLedger::fence(SqliteReplayLedger::open(&path, &policy()).unwrap());
        let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        assert_eq!(
            provider.sign(&request()),
            Err(KeyError::HardwareResultUnknown)
        );
    }
    assert_eq!(probe.counts(), (0, 0));
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(
        provider.recover(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::HardwareFenceRejected)
    );
    assert_eq!(probe.counts(), (0, 1));
    drop(provider);
    let mut ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    assert_eq!(ledger.provider_binding().unwrap().hardware_fence, 0);
}

#[test]
fn database_fence_before_unknown_sign_never_reinvokes_signing() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
        let port = RecoverablePort::new(SignBehavior::RemainUnknown, probe.clone());
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        assert_eq!(
            provider.sign(&request()),
            Err(KeyError::HardwareResultUnknown)
        );
    }
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(
        provider.recover(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
    assert_eq!(provider.sign(&request()), Err(KeyError::ReplayRejected));
    assert_eq!(probe.counts(), (1, 1));
}

#[test]
fn hardware_more_than_one_fence_ahead_is_rejected_on_open() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    drop(KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap());
    probe.force_fence(2);

    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe);
    assert!(matches!(
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()),
        Err(KeyError::HardwareFenceRejected)
    ));
}

#[test]
fn hardware_counter_rollback_is_rejected_on_open() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    {
        let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
        let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        provider.sign(&request()).unwrap();
    }
    probe.force_fence(0);
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe);
    assert!(matches!(
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()),
        Err(KeyError::HardwareFenceRejected)
    ));
}

#[test]
fn a_tampered_operation_claim_fails_closed_before_signing() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = TamperingPort::new(Tamper::OperationClaim, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
    assert_eq!(probe.counts().0, 0);
}

fn ledger_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fence.sqlite3");
    (directory, path)
}
