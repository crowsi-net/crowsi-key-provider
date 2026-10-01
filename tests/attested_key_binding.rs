#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{
    AttestationChallenge, AttestationVerification, HardwareAttestation, HardwareKeyPort,
    HardwareOperationClaim, HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation,
    IndependentKeyVerifier, KeyError, KeyProvider, VerifiedHardwareAttestation,
    VerifiedHardwareRoleBinding,
};
use support::{MemoryLedger, TestVerifier, clock, policy, request, verified_attestation};

struct SubstitutingPort {
    attestation: HardwareAttestation,
}

impl HardwareKeyPort for SubstitutingPort {
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
        let mut value = self.attestation.clone();
        value
            .challenge_digest_sha256
            .clone_from(&challenge.digest_sha256);
        value.issued_at_epoch_s = challenge.issued_at_epoch_s;
        value.expires_at_epoch_s = challenge.expires_at_epoch_s;
        Ok(value)
    }

    fn sign_digest(&mut self, _: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        Ok(vec![9; 64])
    }

    fn recover_signature(
        &mut self,
        _: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        Ok(None)
    }
}

struct AlteringVerifier;

impl IndependentKeyVerifier for AlteringVerifier {
    fn verify_role_binding(
        &mut self,
        value: &HardwareRoleBinding,
        claim: &HardwareRoleClaim,
    ) -> Result<VerifiedHardwareRoleBinding, KeyError> {
        let mut verifier = TestVerifier::ready();
        verifier.verify_role_binding(value, claim)
    }

    fn verify_attestation(
        &mut self,
        value: &HardwareAttestation,
        _challenge: &AttestationChallenge,
    ) -> Result<VerifiedHardwareAttestation, KeyError> {
        let mut changed = value.clone();
        changed.public_key_spki_sha256 = "d".repeat(64);
        Ok(VerifiedHardwareAttestation {
            attestation: changed,
            verifier_key_id: "vendor-attestation-root".into(),
            trust_revision: 1,
            verifications: [
                AttestationVerification::VendorChain,
                AttestationVerification::PublicKeyBinding,
                AttestationVerification::Challenge,
                AttestationVerification::Signature,
                AttestationVerification::EvidenceFieldsDerived,
            ]
            .into(),
        })
    }

    fn verify_signature(
        &mut self,
        _: &VerifiedHardwareAttestation,
        _: &[u8; 32],
        _: &[u8],
    ) -> Result<bool, KeyError> {
        Ok(true)
    }
}

#[test]
fn an_attested_key_cannot_be_substituted_during_signing() {
    let attestation = verified_attestation();
    let mut provider = KeyProvider::open(
        policy(),
        SubstitutingPort { attestation },
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::HardwareResultUnknown)
    );
}

#[test]
fn independent_verification_must_echo_the_exact_attested_key() {
    let attestation = verified_attestation();
    let mut provider = KeyProvider::open(
        policy(),
        SubstitutingPort { attestation },
        AlteringVerifier,
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::AttestationRejected)
    );
}

#[test]
fn a_stale_key_version_is_rejected_before_signing() {
    let mut attestation = verified_attestation();
    attestation.key_version = "release-key-version-0".into();
    let mut provider = KeyProvider::open(
        policy(),
        SubstitutingPort { attestation },
        TestVerifier::ready(),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap();

    assert_eq!(
        provider.sign(&request()),
        Err(KeyError::AttestationRejected)
    );
}
