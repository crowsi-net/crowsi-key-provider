#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, KeyProvider, SqliteReplayLedger};
use support::{HardwareProbe, RecoverablePort, SignBehavior, TestVerifier, clock, policy, request};

#[test]
fn changed_replay_is_rejected_before_hardware_readback() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    create_unknown(&path, &probe, SignBehavior::LoseResponse);
    let mut changed = request();
    changed.digest_sha256 = "a".repeat(64);
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(provider.recover(&changed), Err(KeyError::ReplayRejected));
    assert_eq!(probe.counts(), (1, 0));
}

#[test]
fn unresolved_or_unsupported_readback_remains_blocked() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    create_unknown(&path, &probe, SignBehavior::RemainUnknown);
    for unsupported in [false, true] {
        let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
        let port = if unsupported {
            RecoverablePort::unsupported(SignBehavior::Return, probe.clone())
        } else {
            RecoverablePort::new(SignBehavior::Return, probe.clone())
        };
        let mut provider =
            KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
        let expected = if unsupported {
            KeyError::RecoveryUnsupported
        } else {
            KeyError::HardwareResultUnknown
        };
        assert_eq!(provider.recover(&request()), Err(expected));
    }
    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(provider.sign(&request()), Err(KeyError::ReplayRejected));
    assert_eq!(probe.counts().0, 1);
}

#[test]
fn substituted_readback_signature_is_never_committed_or_resigned() {
    let (_directory, path) = ledger_path();
    let probe = HardwareProbe::default();
    create_unknown(&path, &probe, SignBehavior::LoseResponse);
    let operation_id = probe.operation_id().unwrap();
    probe.substitute_signature(&operation_id, vec![8; 64]);

    let ledger = SqliteReplayLedger::open(&path, &policy()).unwrap();
    let port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let mut provider =
        KeyProvider::open(policy(), port, TestVerifier::ready(), ledger, clock()).unwrap();
    assert_eq!(
        provider.recover(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
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
