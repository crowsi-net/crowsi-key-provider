use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareKeyPort, HardwareOperationClaim,
    HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation, KeyError, KeyProperty,
};

use super::fixtures::{attestation, bind_to_challenge, claimed_operation, role_binding};

pub struct TestPort {
    attestation: HardwareAttestation,
    outcome: TestPortOutcome,
}

enum TestPortOutcome {
    Signed,
    Unknown,
    MisreportedFailure,
}

impl TestPort {
    pub fn ready() -> Self {
        Self {
            attestation: attestation(),
            outcome: TestPortOutcome::Signed,
        }
    }

    pub fn exportable() -> Self {
        let mut value = attestation();
        value.properties.remove(&KeyProperty::NonExportable);
        Self {
            attestation: value,
            outcome: TestPortOutcome::Signed,
        }
    }

    pub fn unverified() -> Self {
        let mut value = attestation();
        value
            .properties
            .remove(&KeyProperty::AttestationChainVerified);
        Self {
            attestation: value,
            outcome: TestPortOutcome::Signed,
        }
    }

    pub fn failing() -> Self {
        Self {
            attestation: attestation(),
            outcome: TestPortOutcome::Unknown,
        }
    }

    pub fn misreporting() -> Self {
        Self {
            attestation: attestation(),
            outcome: TestPortOutcome::MisreportedFailure,
        }
    }
}

impl HardwareKeyPort for TestPort {
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        Ok(role_binding(claim))
    }

    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        Ok(claimed_operation(operation))
    }

    fn attest(
        &mut self,
        _: &str,
        _: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError> {
        let mut value = self.attestation.clone();
        bind_to_challenge(&mut value, challenge);
        Ok(value)
    }

    fn sign_digest(&mut self, _: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        match self.outcome {
            TestPortOutcome::Signed => Ok(vec![7; 64]),
            TestPortOutcome::Unknown => Err(KeyError::HardwareResultUnknown),
            TestPortOutcome::MisreportedFailure => Err(KeyError::RequestRejected),
        }
    }

    fn recover_signature(
        &mut self,
        _: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        Ok(None)
    }
}
