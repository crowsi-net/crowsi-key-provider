#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{KeyError, KeyProvider};
use support::{MemoryLedger, TestPort, TestVerifier, clock, policy, request};

#[test]
fn every_post_invocation_error_is_unknown_and_consumes_replay() {
    let mut provider = KeyProvider::open(
        policy(),
        TestPort::misreporting(),
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
    assert_eq!(provider.sign(&request()), Err(KeyError::ReplayRejected));
}
