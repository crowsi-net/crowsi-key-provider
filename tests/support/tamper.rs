use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareKeyPort, HardwareOperationClaim,
    HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation, KeyError,
};

use super::{HardwareProbe, RecoverablePort, SignBehavior};

#[derive(Clone, Copy)]
pub enum Tamper {
    RoleClaim,
    OperationClaim,
}

pub struct TamperingPort {
    inner: RecoverablePort,
    tamper: Tamper,
}

impl TamperingPort {
    pub fn new(tamper: Tamper, probe: HardwareProbe) -> Self {
        Self {
            inner: RecoverablePort::new(SignBehavior::Return, probe),
            tamper,
        }
    }
}

impl HardwareKeyPort for TamperingPort {
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        let mut value = self.inner.bind_or_verify_role(claim)?;
        if matches!(self.tamper, Tamper::RoleClaim) {
            value.claim_digest_sha256 = "0".repeat(64);
        }
        Ok(value)
    }

    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        let mut value = self.inner.claim_operation(operation)?;
        if matches!(self.tamper, Tamper::OperationClaim) {
            value.request_binding_sha256 = "0".repeat(64);
        }
        Ok(value)
    }

    fn attest(
        &mut self,
        key_id: &str,
        key_version: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError> {
        self.inner.attest(key_id, key_version, challenge)
    }

    fn sign_digest(&mut self, operation: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        self.inner.sign_digest(operation)
    }

    fn recover_signature(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        self.inner.recover_signature(operation)
    }
}
