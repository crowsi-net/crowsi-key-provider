use crowsi_key_provider::{KeyAlgorithm, KeyPurpose, SigningRequestV1};

#[test]
fn request_rejects_unknown_secret_fields() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/signing-request-v1.schema.json")).unwrap();
    assert_eq!(value["additionalProperties"], false);
    value = serde_json::json!({
        "schema": "crowsi://keys/signing-request/v1",
        "request_id": "request-alpha",
        "nonce": "nonce-alpha",
        "security_domain": "crowsi.example",
        "deployment_id": "deployment-a",
        "workload_id": "spiffe://crowsi/release/worker",
        "key_id": "release-key",
        "purpose": "release",
        "digest_sha256": "b".repeat(64),
        "issued_at_epoch_s": 1,
        "expires_at_epoch_s": 2,
        "private_key": "forbidden"
    });
    assert!(serde_json::from_value::<SigningRequestV1>(value).is_err());
}

#[test]
fn request_schema_uses_the_shared_spiffe_profile() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/signing-request-v1.schema.json")).unwrap();
    assert_eq!(
        value["$defs"]["workload_id"]["pattern"],
        crowsi_control_contracts::SPIFFE_WORKLOAD_SCHEMA_PATTERN
    );
    assert_eq!(
        value["properties"]["workload_id"]["$ref"],
        "#/$defs/workload_id"
    );
}

#[test]
fn response_and_attestation_schemas_are_closed() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/signing-response-v2.schema.json")).unwrap();
    assert_eq!(value["additionalProperties"], false);
    assert_eq!(value["$defs"]["attestation"]["additionalProperties"], false);
    assert_eq!(value["properties"]["external_actions"]["const"], false);
    assert_eq!(
        value["$defs"]["attestation"]["properties"]["algorithm"]["const"],
        "ecdsa-p256-sha256-p1363-low-s"
    );
    assert_eq!(value["properties"]["signature"]["minItems"], 64);
    assert_eq!(value["properties"]["signature"]["maxItems"], 64);
    assert_eq!(
        serde_json::to_string(&KeyAlgorithm::EcdsaP256Sha256P1363LowS).unwrap(),
        "\"ecdsa-p256-sha256-p1363-low-s\""
    );
    let required = value["$defs"]["attestation"]["required"]
        .as_array()
        .expect("attestation required fields");
    for field in [
        "key_version",
        "public_key_spki_sha256",
        "challenge_digest_sha256",
        "attestation_chain_ref",
        "issued_at_epoch_s",
        "expires_at_epoch_s",
    ] {
        assert!(required.iter().any(|item| item == field));
    }
    assert!(value["$defs"]["attestation"]["properties"]["attestation_envelope_base64"].is_null());
    assert!(value["$defs"]["attestation"]["properties"]["attestation_signature_base64"].is_null());
}

#[test]
fn hardware_purposes_cover_every_isolated_signing_role() {
    for (encoded, expected) in [
        (
            "\"pep-enforcement-receipt\"",
            KeyPurpose::PepEnforcementReceipt,
        ),
        (
            "\"independent-readback-report\"",
            KeyPurpose::IndependentReadbackReport,
        ),
        (
            "\"workload-certificate-issuance\"",
            KeyPurpose::WorkloadCertificateIssuance,
        ),
        (
            "\"certificate-authority-receipt\"",
            KeyPurpose::CertificateAuthorityReceipt,
        ),
        (
            "\"certificate-manager-commit-receipt\"",
            KeyPurpose::CertificateManagerCommitReceipt,
        ),
        (
            "\"certificate-manager-handoff-receipt\"",
            KeyPurpose::CertificateManagerHandoffReceipt,
        ),
    ] {
        assert_eq!(
            serde_json::from_str::<KeyPurpose>(encoded).unwrap(),
            expected
        );
    }
    let request: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/signing-request-v1.schema.json")).unwrap();
    let response: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/signing-response-v2.schema.json")).unwrap();
    for purpose in [
        "pep-enforcement-receipt",
        "independent-readback-report",
        "workload-certificate-issuance",
        "certificate-authority-receipt",
        "certificate-manager-commit-receipt",
        "certificate-manager-handoff-receipt",
    ] {
        assert!(
            request["properties"]["purpose"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item == purpose)
        );
        assert!(
            response["$defs"]["attestation"]["properties"]["purpose"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item == purpose)
        );
    }
}
