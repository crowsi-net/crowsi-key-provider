use crowsi_key_provider::{
    AttestationChallenge, HardwareAttestation, HardwareKeyPort, HardwareOperationClaim,
    HardwareRoleBinding, HardwareRoleClaim, HardwareSigningOperation, KeyError,
};

use crate::support::TestPort;

use super::{HardwareProbe, SignBehavior};

pub struct RecoverablePort {
    behavior: SignBehavior,
    recovery_supported: bool,
    probe: HardwareProbe,
}

impl RecoverablePort {
    pub fn new(behavior: SignBehavior, probe: HardwareProbe) -> Self {
        Self {
            behavior,
            recovery_supported: true,
            probe,
        }
    }

    pub fn unsupported(behavior: SignBehavior, probe: HardwareProbe) -> Self {
        Self {
            behavior,
            recovery_supported: false,
            probe,
        }
    }
}

impl HardwareKeyPort for RecoverablePort {
    fn bind_or_verify_role(
        &mut self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        self.probe.bind_role(claim)
    }

    fn claim_operation(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        self.probe.claim(operation)
    }

    fn attest(
        &mut self,
        key_id: &str,
        key_version: &str,
        challenge: &AttestationChallenge,
    ) -> Result<HardwareAttestation, KeyError> {
        TestPort::ready().attest(key_id, key_version, challenge)
    }

    fn sign_digest(&mut self, operation: &HardwareSigningOperation) -> Result<Vec<u8>, KeyError> {
        self.probe.sign(operation, self.behavior)
    }

    fn recover_signature(
        &mut self,
        operation: &HardwareSigningOperation,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        self.probe.recover(operation, self.recovery_supported)
    }
}
