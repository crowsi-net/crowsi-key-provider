#[allow(dead_code)]
use crate::support;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareKeyPort, HardwareOperationClaim,
    HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation, KeyError, KeyProvider,
};
use support::{MemoryLedger, TestVerifier, clock, policy, request};

struct IgnoringPort {
    calls: Arc<AtomicUsize>,
    challenge_matches: bool,
    evidence_digest_matches: bool,
}

impl HardwareKeyPort for IgnoringPort {
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        Ok(support::role_binding(claim))
    }

    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        Ok(support::claimed_operation(operation))
    }

    fn attest(
        &mut self,
        _: &str,
        _: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(challenge.server_nonce_hex.len(), 64);
        assert!(
            challenge
                .server_nonce_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        Ok(HardwareAttestation {
            source: crowsi_key_provider::KeySource::Tpm2,
            key_id: "release-key".into(),
            key_version: "release-key-version-1".into(),
            public_key_spki_sha256: "c".repeat(64),
            purpose: crowsi_key_provider::KeyPurpose::Release,
            algorithm: crowsi_key_provider::KeyAlgorithm::EcdsaP256Sha256P1363LowS,
            properties: [
                crowsi_key_provider::KeyProperty::HardwareBacked,
                crowsi_key_provider::KeyProperty::NonExportable,
                crowsi_key_provider::KeyProperty::RoleScoped,
                crowsi_key_provider::KeyProperty::AttestationChainVerified,
            ]
            .into(),
            attestation_digest_sha256: if self.evidence_digest_matches {
                "0592cedeabbf836d8d1c7456417c7653ac208f71e904d3d0ab37faf711021aff".into()
            } else {
                "a".repeat(64)
            },
            challenge_digest_sha256: if self.challenge_matches {
                challenge.digest_sha256.clone()
            } else {
                "d".repeat(64)
            },
            attestation_envelope_base64: "QUFBQUFBQUFBQUFB".into(),
            attestation_signature_base64: "QkJCQkJCQkJCQkJC".into(),
            attestation_chain_ref: "vendor-chain-version-1".into(),
            issued_at_epoch_s: support::NOW,
            expires_at_epoch_s: support::NOW + 10,
        })
    }

    fn sign_digest(&mut self, _: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        self.calls.fetch_add(100, Ordering::SeqCst);
        Ok(vec![7; 64])
    }

    fn recover_signature(
        &mut self,
        _: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        Ok(None)
    }
}

#[test]
fn an_attestation_for_another_challenge_cannot_reach_signing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let port = IgnoringPort {
        calls: Arc::clone(&calls),
        challenge_matches: false,
        evidence_digest_matches: true,
    };
    let mut provider = KeyProvider::open(
        policy(),
        port,
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::AttestationRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn invalid_attestation_policy_is_rejected_before_hardware_access() {
    let calls = Arc::new(AtomicUsize::new(0));
    let port = IgnoringPort {
        calls: Arc::clone(&calls),
        challenge_matches: false,
        evidence_digest_matches: true,
    };
    let mut invalid = policy();
    invalid.max_attestation_ttl_seconds = 0;
    let provider = KeyProvider::open(
        invalid,
        port,
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    );

    assert!(matches!(provider, Err(KeyError::RequestRejected)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn envelope_digest_is_verified_independently_before_signing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let port = IgnoringPort {
        calls: Arc::clone(&calls),
        challenge_matches: true,
        evidence_digest_matches: false,
    };
    let mut provider = KeyProvider::open(
        policy(),
        port,
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::AttestationRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
