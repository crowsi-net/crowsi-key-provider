#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, KeyProvider, KeyPurpose, SqliteReplayLedger};
use support::{
    HardwareProbe, MemoryLedger, RecoverablePort, SignBehavior, Tamper, TamperingPort,
    TestVerifier, clock, policy,
};

#[test]
fn physical_key_cannot_be_rebound_to_another_ledger_instance() {
    let directory = tempfile::tempdir().unwrap();
    let probe = HardwareProbe::default();
    let first_path = directory.path().join("first.sqlite3");
    let first_ledger = SqliteReplayLedger::open(&first_path, &policy()).unwrap();
    let first_port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let _provider = KeyProvider::open(
        policy(),
        first_port,
        TestVerifier::ready(),
        first_ledger,
        clock(),
    )
    .unwrap();

    let second_path = directory.path().join("second.sqlite3");
    let second_ledger = SqliteReplayLedger::open(&second_path, &policy()).unwrap();
    let second_port = RecoverablePort::new(SignBehavior::Return, probe);
    assert!(matches!(
        KeyProvider::open(
            policy(),
            second_port,
            TestVerifier::ready(),
            second_ledger,
            clock()
        ),
        Err(KeyError::RoleBindingRejected)
    ));
}

#[test]
fn physical_key_cannot_be_reused_for_another_purpose() {
    let probe = HardwareProbe::default();
    let first_port = RecoverablePort::new(SignBehavior::Return, probe.clone());
    let _provider = KeyProvider::open(
        policy(),
        first_port,
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    let mut changed = policy();
    changed.purpose = KeyPurpose::WorkloadCertificateIssuance;
    let second_port = RecoverablePort::new(SignBehavior::Return, probe);
    assert!(matches!(
        KeyProvider::open(
            changed,
            second_port,
            TestVerifier::ready(),
            MemoryLedger::default(),
            clock()
        ),
        Err(KeyError::RoleBindingRejected)
    ));
}

#[test]
fn independently_verified_role_claim_must_match_the_raw_binding() {
    let probe = HardwareProbe::default();
    let port = TamperingPort::new(Tamper::RoleClaim, probe);
    assert!(matches!(
        KeyProvider::open(
            policy(),
            port,
            TestVerifier::ready(),
            MemoryLedger::default(),
            clock()
        ),
        Err(KeyError::RoleBindingRejected)
    ));
}
