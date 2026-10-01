use crowsi_key_provider::{
    KeyAlgorithm, KeyError, KeyPolicy, KeyPurpose, KeySource, SigningRequestV1, TrustedClock,
};

#[allow(dead_code)]
mod certificate;
#[allow(dead_code)]
mod fault_ledger;
#[allow(dead_code)]
mod key;
#[allow(dead_code)]
mod ledger;
#[allow(dead_code)]
mod recovery;
#[allow(dead_code)]
mod tamper;

#[allow(unused_imports)]
pub use certificate::{CertificatePort, CertificateVerifier};
#[allow(unused_imports)]
pub use fault_ledger::FailOnceLedger;
#[allow(unused_imports)]
pub use key::{TestPort, TestVerifier, claimed_operation, role_binding, verified_attestation};
#[allow(unused_imports)]
pub use ledger::MemoryLedger;
#[allow(unused_imports)]
pub use recovery::{HardwareProbe, RecoverablePort, SignBehavior};
#[allow(unused_imports)]
pub use tamper::{Tamper, TamperingPort};

pub const NOW: u64 = 1_800_000_000;

pub struct FixedClock(pub Vec<u64>);

impl TrustedClock for FixedClock {
    fn now_epoch_s(&mut self) -> Result<u64, KeyError> {
        if self.0.is_empty() {
            return Err(KeyError::TrustedTimeUnavailable);
        }
        Ok(self.0.remove(0))
    }
}

pub fn clock() -> FixedClock {
    FixedClock(vec![NOW, NOW, NOW, NOW])
}

pub fn policy() -> KeyPolicy {
    KeyPolicy {
        security_domain: "crowsi.example".into(),
        deployment_id: "deployment-a".into(),
        workload_id: "spiffe://crowsi/release/worker".into(),
        key_id: "release-key".into(),
        key_version: "release-key-version-1".into(),
        public_key_spki_sha256: "c".repeat(64),
        purpose: KeyPurpose::Release,
        source: KeySource::Tpm2,
        algorithm: KeyAlgorithm::EcdsaP256Sha256P1363LowS,
        attestation_verifier_key_id: "vendor-attestation-root".into(),
        attestation_trust_revision: 1,
        role_manifest_digest_sha256: "e".repeat(64),
        max_ttl_seconds: 30,
        max_attestation_ttl_seconds: 15,
        max_recovery_ttl_seconds: 3_600,
    }
}

pub fn request() -> SigningRequestV1 {
    SigningRequestV1 {
        schema: "crowsi://keys/signing-request/v1".into(),
        request_id: "request-a".into(),
        nonce: "nonce-alpha".into(),
        security_domain: "crowsi.example".into(),
        deployment_id: "deployment-a".into(),
        workload_id: "spiffe://crowsi/release/worker".into(),
        key_id: "release-key".into(),
        purpose: KeyPurpose::Release,
        digest_sha256: "b".repeat(64),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 10,
    }
}
