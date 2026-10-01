//! Private keys remain behind a hardware adapter boundary.

mod attestation;
mod attestation_model;
mod clock;
mod error;
mod evidence_validation;
mod ledger_binding;
mod model;
mod operation_model;
mod ports;
mod provider;
mod request_value;
mod role_claim;
mod role_model;
mod role_validation;
mod secure_path;
mod signing_operation;
mod sqlite_ledger;
mod sqlite_schema;
mod validation;

pub use attestation::AttestationChallenge;
pub use attestation_model::{
    AttestationSummary, AttestationVerification, HardwareAttestation, SigningResponseV2,
    VerifiedHardwareAttestation,
};
pub use clock::{SystemTrustedClock, TrustedClock};
pub use error::KeyError;
pub use model::{KeyAlgorithm, KeyPolicy, KeyProperty, KeyPurpose, KeySource, SigningRequestV1};
pub use operation_model::{
    HardwareOperationClaim, HardwareOperationDisposition, HardwareSigningOperation, SigningAttempt,
    SigningAttemptState,
};
pub use ports::{
    HardwareKeyPort, IndependentKeyVerifier, ProviderBindingJournal, ReplayLedger,
    SigningAttemptJournal,
};
pub use provider::KeyProvider;
pub use role_model::{
    HardwareRoleBinding, HardwareRoleClaim, ProviderLedgerBinding, RoleBindingVerification,
    VerifiedHardwareRoleBinding,
};
pub use sqlite_ledger::SqliteReplayLedger;
