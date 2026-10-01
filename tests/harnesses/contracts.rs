//! Key, attestation, certificate, and schema contracts share one executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../at_most_once.rs"]
mod at_most_once;
#[path = "../attestation_challenge.rs"]
mod attestation_challenge;
#[path = "../attested_key_binding.rs"]
mod attested_key_binding;
#[path = "../certificate_receipt_role.rs"]
mod certificate_receipt_role;
#[path = "../certificate_signing_role.rs"]
mod certificate_signing_role;
#[path = "../response_wire.rs"]
mod response_wire;
#[path = "../schema.rs"]
mod schema;
#[path = "../signing_boundary.rs"]
mod signing_boundary;
