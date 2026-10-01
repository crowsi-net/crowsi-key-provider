use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPurpose {
    PolicyAdministration,
    CoordinatorCheckpoint,
    PepEnforcementReceipt,
    IndependentReadbackReport,
    WorkloadCertificateIssuance,
    CertificateAuthorityReceipt,
    CertificateManagerCommitReceipt,
    CertificateManagerHandoffReceipt,
    Release,
    RescueRecovery,
}

impl KeyPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAdministration => "policy-administration",
            Self::CoordinatorCheckpoint => "coordinator-checkpoint",
            Self::PepEnforcementReceipt => "pep-enforcement-receipt",
            Self::IndependentReadbackReport => "independent-readback-report",
            Self::WorkloadCertificateIssuance => "workload-certificate-issuance",
            Self::CertificateAuthorityReceipt => "certificate-authority-receipt",
            Self::CertificateManagerCommitReceipt => "certificate-manager-commit-receipt",
            Self::CertificateManagerHandoffReceipt => "certificate-manager-handoff-receipt",
            Self::Release => "release",
            Self::RescueRecovery => "rescue-recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeySource {
    Tpm2,
    Pkcs11Hsm,
    CloudHsm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    EcdsaP256Sha256P1363LowS,
}

impl KeyAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256P1363LowS => "ecdsa-p256-sha256-p1363-low-s",
        }
    }

    #[must_use]
    pub const fn signature_length(self) -> usize {
        match self {
            Self::EcdsaP256Sha256P1363LowS => 64,
        }
    }
}

impl KeySource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tpm2 => "tpm2",
            Self::Pkcs11Hsm => "pkcs11-hsm",
            Self::CloudHsm => "cloud-hsm",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProperty {
    HardwareBacked,
    NonExportable,
    RoleScoped,
    AttestationChainVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub nonce: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub workload_id: String,
    pub key_id: String,
    pub purpose: KeyPurpose,
    pub digest_sha256: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPolicy {
    pub security_domain: String,
    pub deployment_id: String,
    pub workload_id: String,
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub purpose: KeyPurpose,
    pub source: KeySource,
    pub algorithm: KeyAlgorithm,
    pub attestation_verifier_key_id: String,
    pub attestation_trust_revision: u64,
    pub role_manifest_digest_sha256: String,
    pub max_ttl_seconds: u64,
    pub max_attestation_ttl_seconds: u64,
    pub max_recovery_ttl_seconds: u64,
}
