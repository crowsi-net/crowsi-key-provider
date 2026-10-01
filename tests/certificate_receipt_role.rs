#[allow(dead_code)]
use crate::support;

use crowsi_key_provider::{
    KeyAlgorithm, KeyError, KeyPolicy, KeyProvider, KeyPurpose, KeySource, SigningRequestV1,
};
use support::{CertificatePort, CertificateVerifier, FixedClock, MemoryLedger, NOW, clock};

#[test]
fn receipt_and_certificate_signing_roles_cannot_be_substituted() {
    let request = request();
    let response = provider(KeyPurpose::CertificateAuthorityReceipt)
        .sign(&request)
        .expect("authority receipt signature");
    assert_eq!(
        response.attestation.purpose,
        KeyPurpose::CertificateAuthorityReceipt
    );
    assert_eq!(
        provider(KeyPurpose::WorkloadCertificateIssuance).sign(&request),
        Err(KeyError::AttestationRejected)
    );
}

fn provider(
    attested_purpose: KeyPurpose,
) -> KeyProvider<CertificatePort, CertificateVerifier, MemoryLedger, FixedClock> {
    let spki = "d".repeat(64);
    KeyProvider::open(
        KeyPolicy {
            security_domain: "crowsi.example".into(),
            deployment_id: "deployment-a".into(),
            workload_id: "spiffe://crowsi.example/certificate/authority".into(),
            key_id: "certificate-authority-receipt-key".into(),
            key_version: "certificate-receipt-version-1".into(),
            public_key_spki_sha256: spki.clone(),
            purpose: KeyPurpose::CertificateAuthorityReceipt,
            source: KeySource::Tpm2,
            algorithm: KeyAlgorithm::EcdsaP256Sha256P1363LowS,
            attestation_verifier_key_id: "vendor-attestation-root".into(),
            attestation_trust_revision: 1,
            role_manifest_digest_sha256: "e".repeat(64),
            max_ttl_seconds: 30,
            max_attestation_ttl_seconds: 15,
            max_recovery_ttl_seconds: 3_600,
        },
        CertificatePort::new(attested_purpose, spki.clone()),
        CertificateVerifier::new(spki),
        MemoryLedger::default(),
        clock(),
    )
    .unwrap()
}

fn request() -> SigningRequestV1 {
    SigningRequestV1 {
        schema: "crowsi://keys/signing-request/v1".into(),
        request_id: "authority-receipt-request".into(),
        nonce: "authority-receipt-nonce".into(),
        security_domain: "crowsi.example".into(),
        deployment_id: "deployment-a".into(),
        workload_id: "spiffe://crowsi.example/certificate/authority".into(),
        key_id: "certificate-authority-receipt-key".into(),
        purpose: KeyPurpose::CertificateAuthorityReceipt,
        digest_sha256: "b".repeat(64),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 10,
    }
}
