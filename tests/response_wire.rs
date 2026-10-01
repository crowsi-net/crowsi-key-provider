#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyProvider, SigningResponseV2};
use support::{MemoryLedger, TestPort, TestVerifier, clock, policy, request};

#[test]
fn v2_response_round_trips_without_raw_attestation_evidence() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::ready(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();
    let response = provider.sign(&request()).unwrap();
    let wire = serde_json::to_vec(&response).unwrap();
    let decoded: SigningResponseV2 = serde_json::from_slice(&wire).unwrap();

    assert_eq!(decoded, response);
    assert!(
        !String::from_utf8(wire)
            .unwrap()
            .contains("attestation_envelope")
    );
}
