use crowsi_control_contracts::validate_spiffe_workload;

use crate::{
    AttestationChallenge, AttestationVerification, HardwareAttestation, KeyError, KeyPolicy,
    KeyProperty, SigningRequestV1, VerifiedHardwareAttestation,
    evidence_validation::{canonical_base64, evidence_digest_matches},
    request_value::{decode_digest, is_digest, valid_id},
};

const REQUEST_SCHEMA: &str = "crowsi://keys/signing-request/v1";
const MAX_ATTESTATION_TTL_SECONDS: u64 = 60;
const MAX_RECOVERY_TTL_SECONDS: u64 = 86_400;

pub(crate) fn validate_policy(policy: &KeyPolicy) -> Result<(), KeyError> {
    let identifiers = [
        &policy.security_domain,
        &policy.deployment_id,
        &policy.key_id,
        &policy.key_version,
        &policy.attestation_verifier_key_id,
    ]
    .into_iter()
    .all(|value| valid_id(value));
    let valid = identifiers
        && validate_spiffe_workload(&policy.workload_id).is_ok()
        && is_digest(&policy.public_key_spki_sha256)
        && is_digest(&policy.role_manifest_digest_sha256)
        && policy.attestation_trust_revision > 0
        && (1..=300).contains(&policy.max_ttl_seconds)
        && (1..=MAX_ATTESTATION_TTL_SECONDS).contains(&policy.max_attestation_ttl_seconds)
        && (1..=MAX_RECOVERY_TTL_SECONDS).contains(&policy.max_recovery_ttl_seconds);
    valid.then_some(()).ok_or(KeyError::RequestRejected)
}

pub(crate) fn validate_request(
    policy: &KeyPolicy,
    request: &SigningRequestV1,
    now: u64,
) -> Result<[u8; 32], KeyError> {
    let digest = validate_request_binding(policy, request)?;
    let time = request.issued_at_epoch_s <= now
        && request.expires_at_epoch_s > now
        && request
            .expires_at_epoch_s
            .saturating_sub(request.issued_at_epoch_s)
            <= policy.max_ttl_seconds;
    time.then_some(digest).ok_or(KeyError::RequestRejected)
}

pub(crate) fn validate_request_binding(
    policy: &KeyPolicy,
    request: &SigningRequestV1,
) -> Result<[u8; 32], KeyError> {
    validate_policy(policy)?;
    let exact = request.schema == REQUEST_SCHEMA
        && request.security_domain == policy.security_domain
        && request.deployment_id == policy.deployment_id
        && request.workload_id == policy.workload_id
        && request.key_id == policy.key_id
        && request.purpose == policy.purpose;
    let event_time = request.issued_at_epoch_s < request.expires_at_epoch_s
        && request
            .expires_at_epoch_s
            .saturating_sub(request.issued_at_epoch_s)
            <= policy.max_ttl_seconds;
    let identifiers = [
        &request.request_id,
        &request.nonce,
        &request.security_domain,
        &request.deployment_id,
        &request.key_id,
        &policy.key_version,
        &policy.attestation_verifier_key_id,
    ]
    .into_iter()
    .all(|value| valid_id(value));
    if !exact
        || !event_time
        || !identifiers
        || validate_spiffe_workload(&request.workload_id).is_err()
    {
        return Err(KeyError::RequestRejected);
    }
    decode_digest(&request.digest_sha256).ok_or(KeyError::RequestRejected)
}

pub(crate) fn validate_attestation(
    policy: &KeyPolicy,
    value: &HardwareAttestation,
    verified: &VerifiedHardwareAttestation,
    challenge: &AttestationChallenge,
    now: u64,
) -> Result<(), KeyError> {
    let required = [
        KeyProperty::HardwareBacked,
        KeyProperty::NonExportable,
        KeyProperty::RoleScoped,
        KeyProperty::AttestationChainVerified,
    ];
    let verification_required = [
        AttestationVerification::VendorChain,
        AttestationVerification::PublicKeyBinding,
        AttestationVerification::Challenge,
        AttestationVerification::Signature,
        AttestationVerification::EvidenceFieldsDerived,
    ];
    let exact = value.key_id == policy.key_id
        && value.key_version == policy.key_version
        && value.public_key_spki_sha256 == policy.public_key_spki_sha256
        && value.purpose == policy.purpose
        && value.source == policy.source
        && value.algorithm == policy.algorithm
        && value.challenge_digest_sha256 == challenge.digest_sha256
        && value.issued_at_epoch_s == challenge.issued_at_epoch_s
        && value.expires_at_epoch_s > now
        && value.expires_at_epoch_s == challenge.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= policy.max_attestation_ttl_seconds
        && is_digest(&value.public_key_spki_sha256)
        && evidence_digest_matches(
            &value.attestation_envelope_base64,
            &value.attestation_digest_sha256,
        )
        && is_digest(&value.challenge_digest_sha256)
        && canonical_base64(&value.attestation_signature_base64, 16, 4_096)
        && valid_id(&value.attestation_chain_ref)
        && verified.attestation == *value
        && verified.verifier_key_id == policy.attestation_verifier_key_id
        && verified.trust_revision == policy.attestation_trust_revision
        && verification_required
            .iter()
            .all(|item| verified.verifications.contains(item))
        && required.iter().all(|item| value.properties.contains(item));
    exact.then_some(()).ok_or(KeyError::AttestationRejected)
}
