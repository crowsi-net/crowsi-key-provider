use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum KeyError {
    #[error("the signing request does not exactly match policy")]
    RequestRejected,
    #[error("hardware attestation is absent, stale, or unverifiable")]
    AttestationRejected,
    #[error("request or nonce was already reserved")]
    ReplayRejected,
    #[error("the durable replay ledger is unavailable")]
    LedgerUnavailable,
    #[error("trusted time is unavailable or moved backwards")]
    TrustedTimeUnavailable,
    #[error("a cryptographically secure attestation challenge is unavailable")]
    ChallengeUnavailable,
    #[error("the durable hardware role binding is absent or changed")]
    RoleBindingRejected,
    #[error("the hardware operation fence is stale or ambiguous")]
    HardwareFenceRejected,
    #[error("the hardware operation claim does not exactly match the request")]
    OperationClaimRejected,
    #[error("the hardware operation result is unknown")]
    HardwareResultUnknown,
    #[error("the hardware adapter cannot recover an earlier operation")]
    RecoveryUnsupported,
    #[error("no exact durable signing attempt exists for recovery")]
    RecoveryNotFound,
    #[error("the bounded signing recovery window has expired")]
    RecoveryWindowExpired,
}
