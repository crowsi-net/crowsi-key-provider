use crate::{
    AttestationChallenge, HardwareAttestation, HardwareOperationClaim, HardwareRoleBinding,
    HardwareRoleClaim, HardwareSigningOperation, KeyError, ProviderLedgerBinding, SigningAttempt,
    VerifiedHardwareAttestation, VerifiedHardwareRoleBinding,
};

pub trait HardwareKeyPort {
    /// Seals or reads one immutable role claim for the physical key material.
    ///
    /// # Errors
    ///
    /// Rejects a different claim for an already-bound key or unavailable durable state.
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError>;

    /// Atomically claims one request binding under the hardware fence.
    ///
    /// An exact existing operation is returned for readback and never grants a
    /// second signing invocation.
    ///
    /// # Errors
    ///
    /// Rejects stale fences, changed operations, or unavailable durable state.
    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError>;

    /// Returns vendor evidence for one exact, non-exportable key version.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter cannot determine the current key state.
    fn attest(
        &mut self,
        key_id: &str,
        key_version: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError>;

    /// Signs one fixed-size digest inside the hardware boundary.
    ///
    /// # Errors
    ///
    /// Returns an unknown result when completion cannot be proven.
    fn sign_digest(&mut self, operation: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError>;

    /// Reads back one exact operation without invoking signing again.
    ///
    /// A production adapter that cannot prove readback support fails closed.
    ///
    /// # Errors
    ///
    /// Returns `RecoveryUnsupported` or an unknown result; it must never sign.
    fn recover_signature(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError>;
}

pub trait IndependentKeyVerifier {
    /// Independently verifies the sealed role claim and durable counter.
    ///
    /// # Errors
    ///
    /// Rejects any claim, key, signature, or counter substitution.
    fn verify_role_binding(
        &mut self,
        value: &HardwareRoleBinding,
        claim: &HardwareRoleClaim,
    ) -> Result<VerifiedHardwareRoleBinding, KeyError>;

    /// Verifies vendor evidence and its exact SPKI digest and key version.
    ///
    /// # Errors
    ///
    /// Returns an error when independent verification is unavailable.
    fn verify_attestation(
        &mut self,
        value: &HardwareAttestation,
        challenge: &AttestationChallenge,
    ) -> Result<VerifiedHardwareAttestation, KeyError>;

    /// Verifies a canonical IEEE P1363 low-S signature with the independently
    /// attested P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error when cryptographic verification cannot be completed.
    fn verify_signature(
        &mut self,
        key: &VerifiedHardwareAttestation,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, KeyError>;
}

pub trait ProviderBindingJournal {
    /// Returns the immutable ledger identity and last committed hardware fence.
    ///
    /// # Errors
    ///
    /// Rejects missing, changed, or unavailable binding state.
    fn provider_binding(&mut self) -> Result<ProviderLedgerBinding, KeyError>;

    /// Advances the local hardware fence by one exact, idempotent CAS.
    ///
    /// # Errors
    ///
    /// Rejects rollback, skipped counters, or unavailable durable state.
    fn advance_hardware_fence(&mut self, expected: u64, current: u64) -> Result<(), KeyError>;
}

pub trait ReplayLedger {
    /// Persists the trusted clock watermark before request evaluation.
    ///
    /// # Errors
    ///
    /// Rejects rollback or unavailable durable storage.
    fn observe_time(&mut self, now_epoch_s: u64) -> Result<(), KeyError>;

    /// Atomically reserves both values before a key operation.
    ///
    /// # Errors
    ///
    /// Rejects either value when it was already observed.
    fn reserve(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
    ) -> Result<(), KeyError>;
}

pub trait SigningAttemptJournal {
    /// Atomically consumes replay identifiers and journals the exact operation.
    ///
    /// # Errors
    ///
    /// Rejects any replay or unavailable durable storage.
    fn begin_signing_attempt(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError>;

    /// Loads only an attempt whose complete request binding is unchanged.
    ///
    /// # Errors
    ///
    /// Rejects a changed replay or unavailable durable storage.
    fn load_signing_attempt(
        &mut self,
        request_id: &str,
        request_binding_sha256: &str,
    ) -> Result<Option<SigningAttempt>, KeyError>;

    /// Durably records that only readback may resolve the operation.
    ///
    /// # Errors
    ///
    /// Rejects a changed operation or unavailable durable storage.
    fn mark_signing_result_unknown(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<(), KeyError>;

    /// Durably stores the exact verified P1363 result.
    ///
    /// # Errors
    ///
    /// Rejects a changed operation/result or unavailable durable storage.
    fn complete_signing_attempt(
        &mut self,
        operation: &HardwareSigningOperation,
        signature: &[u8],
    ) -> Result<(), KeyError>;
}
