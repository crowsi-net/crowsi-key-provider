use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crowsi_key_provider::{
    HardwareOperationClaim, HardwareOperationDisposition, HardwareRoleBinding, HardwareRoleClaim,
    HardwareSigningOperation, KeyError,
};

use crate::support::role_binding;

use super::SignBehavior;

#[derive(Default)]
struct HardwareState {
    operations: BTreeMap<String, HardwareOperation>,
    role_claim: Option<HardwareRoleClaim>,
    hardware_fence: u64,
    sign_calls: usize,
    recover_calls: usize,
}

#[derive(Default)]
struct HardwareOperation {
    operation: Option<HardwareSigningOperation>,
    signature: Option<Vec<u8>>,
    sign_invoked: bool,
}

#[derive(Clone, Default)]
pub struct HardwareProbe(Arc<Mutex<HardwareState>>);

impl HardwareProbe {
    pub fn counts(&self) -> (usize, usize) {
        let state = self.0.lock().unwrap();
        (state.sign_calls, state.recover_calls)
    }

    pub fn force_fence(&self, value: u64) {
        self.0.lock().unwrap().hardware_fence = value;
    }

    pub fn substitute_signature(&self, operation_id: &str, signature: Vec<u8>) {
        if let Some(value) = self.0.lock().unwrap().operations.get_mut(operation_id) {
            value.signature = Some(signature);
        }
    }

    pub fn operation_id(&self) -> Option<String> {
        self.0.lock().unwrap().operations.keys().next().cloned()
    }

    pub(super) fn bind_role(
        &self,
        claim: &HardwareRoleClaim,
    ) -> Result<HardwareRoleBinding, KeyError> {
        let mut state = self.0.lock().unwrap();
        match &state.role_claim {
            Some(value) if value != claim => return Err(KeyError::RoleBindingRejected),
            None => state.role_claim = Some(claim.clone()),
            Some(_) => {}
        }
        let mut binding = role_binding(claim);
        binding.current_fence = state.hardware_fence;
        Ok(binding)
    }

    pub(super) fn claim(
        &self,
        operation: &HardwareSigningOperation,
    ) -> Result<HardwareOperationClaim, KeyError> {
        let mut state = self.0.lock().unwrap();
        if let Some(existing) = state.operations.get(&operation.operation_id) {
            if existing.operation.as_ref() != Some(operation) {
                return Err(KeyError::OperationClaimRejected);
            }
            return Ok(operation_claim(
                operation,
                HardwareOperationDisposition::Existing,
            ));
        }
        if state
            .role_claim
            .as_ref()
            .map(|value| &value.claim_digest_sha256)
            != Some(&operation.role_claim_digest_sha256)
            || state.hardware_fence != operation.previous_hardware_fence
            || operation.hardware_fence != state.hardware_fence + 1
        {
            return Err(KeyError::HardwareFenceRejected);
        }
        state.hardware_fence = operation.hardware_fence;
        state.operations.insert(
            operation.operation_id.clone(),
            HardwareOperation {
                operation: Some(operation.clone()),
                ..HardwareOperation::default()
            },
        );
        Ok(operation_claim(
            operation,
            HardwareOperationDisposition::Claimed,
        ))
    }

    pub(super) fn sign(
        &self,
        operation: &HardwareSigningOperation,
        behavior: SignBehavior,
    ) -> Result<Vec<u8>, KeyError> {
        let mut state = self.0.lock().unwrap();
        state.sign_calls += 1;
        let Some(record) = state.operations.get_mut(&operation.operation_id) else {
            return Err(KeyError::OperationClaimRejected);
        };
        if record.operation.as_ref() != Some(operation) || record.sign_invoked {
            return Err(KeyError::OperationClaimRejected);
        }
        record.sign_invoked = true;
        if matches!(behavior, SignBehavior::RemainUnknown) {
            return Err(KeyError::HardwareResultUnknown);
        }
        record.signature = Some(vec![7; 64]);
        match behavior {
            SignBehavior::Return => Ok(vec![7; 64]),
            SignBehavior::LoseResponse => Err(KeyError::HardwareResultUnknown),
            SignBehavior::RemainUnknown => unreachable!(),
        }
    }

    pub(super) fn recover(
        &self,
        operation: &HardwareSigningOperation,
        supported: bool,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        let mut state = self.0.lock().unwrap();
        state.recover_calls += 1;
        if !supported {
            return Err(KeyError::RecoveryUnsupported);
        }
        Ok(state
            .operations
            .get(&operation.operation_id)
            .filter(|value| value.operation.as_ref() == Some(operation))
            .and_then(|value| value.signature.clone()))
    }
}

fn operation_claim(
    operation: &HardwareSigningOperation,
    disposition: HardwareOperationDisposition,
) -> HardwareOperationClaim {
    HardwareOperationClaim {
        operation_id: operation.operation_id.clone(),
        request_binding_sha256: operation.request_binding_sha256.clone(),
        ledger_instance_id: operation.ledger_instance_id.clone(),
        role_claim_digest_sha256: operation.role_claim_digest_sha256.clone(),
        previous_hardware_fence: operation.previous_hardware_fence,
        hardware_fence: operation.hardware_fence,
        disposition,
    }
}
