use crate::support;

use crowsi_key_provider::{KeyError, KeyProperty, KeyProvider};
use support::{FixedClock, MemoryLedger, NOW, TestPort, TestVerifier, clock, policy, request};

#[test]
fn exact_hardware_bound_request_signs_once() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();
    let response = provider.sign(&request()).unwrap();
    assert_eq!(response.request_id, "request-a");
    assert_eq!(response.signature.len(), 64);
    assert!(
        response
            .attestation
            .properties
            .contains(&KeyProperty::HardwareBacked)
    );
    assert!(
        response
            .attestation
            .properties
            .contains(&KeyProperty::NonExportable)
    );
    assert!(provider.sign(&request()).is_err());
}

#[test]
fn identity_purpose_digest_and_time_are_exact() {
    for mutate in [
        |value: &mut crowsi_key_provider::SigningRequestV1| value.key_id = "other".into(),
        |value: &mut crowsi_key_provider::SigningRequestV1| value.workload_id = "other".into(),
        |value: &mut crowsi_key_provider::SigningRequestV1| {
            value.purpose = crowsi_key_provider::KeyPurpose::WorkloadCertificateIssuance;
        },
        |value: &mut crowsi_key_provider::SigningRequestV1| value.expires_at_epoch_s = NOW,
        |value: &mut crowsi_key_provider::SigningRequestV1| value.digest_sha256 = "bad".into(),
    ] {
        let mut value = request();
        mutate(&mut value);
        let mut provider = KeyProvider::open(
            policy(),
            TestPort::ready(),
            TestVerifier::ready(),
            MemoryLedger::default(),
            clock(),
        )
        .unwrap();
        assert_eq!(provider.sign(&value), Err(KeyError::RequestRejected));
    }
}

#[test]
fn workload_uses_the_shared_spiffe_profile() {
    let mut accepted_policy = policy();
    accepted_policy.workload_id = "spiffe://crowsi.example/Release_Team/worker.01".into();
    let mut accepted_request = request();
    accepted_request.workload_id = accepted_policy.workload_id.clone();
    let mut accepted = KeyProvider::open(
        accepted_policy,
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();
    assert!(accepted.sign(&accepted_request).is_ok());

    let mut rejected_policy = policy();
    rejected_policy.workload_id = "spiffe://CROWSI/release/worker".into();
    let rejected = KeyProvider::open(
        rejected_policy,
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    );
    assert!(matches!(rejected, Err(KeyError::RequestRejected)));
}

#[test]
fn unverifiable_or_exportable_key_is_rejected_before_signing() {
    for port in [TestPort::exportable(), TestPort::unverified()] {
        let mut provider = KeyProvider::open(
            policy(),
            port,
            TestVerifier::ready(),
            MemoryLedger::default(),
            clock(),
        )
        .unwrap();
        assert!(matches!(
            provider.sign(&request()),
            Err(KeyError::AttestationRejected)
        ));
    }
}

#[test]
fn hardware_unknown_result_is_not_retried() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::failing(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();
    assert!(matches!(
        provider.sign(&request()),
        Err(KeyError::HardwareResultUnknown)
    ));
    assert!(matches!(
        provider.sign(&request()),
        Err(KeyError::ReplayRejected)
    ));
}

#[test]
fn expiry_during_pre_sign_checks_prevents_the_key_operation() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        FixedClock(vec![NOW, NOW + 11]),
    )
    .unwrap();
    assert_eq!(provider.sign(&request()), Err(KeyError::RequestRejected));
}

#[test]
fn clock_rollback_is_rejected_before_a_second_key_operation() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        FixedClock(vec![NOW, NOW, NOW - 1]),
    )
    .unwrap();
    provider.sign(&request()).unwrap();
    let mut second = request();
    second.request_id = "request-b".into();
    second.nonce = "nonce-bravo".into();
    assert_eq!(
        provider.sign(&second),
        Err(KeyError::TrustedTimeUnavailable)
    );
}
