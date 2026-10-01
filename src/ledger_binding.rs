use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::{KeyError, KeyPolicy, ProviderLedgerBinding};

pub(crate) fn bind(
    connection: &mut Connection,
    policy: &KeyPolicy,
    initialize: bool,
) -> Result<ProviderLedgerBinding, KeyError> {
    let expected = policy_digest(policy);
    let ledger_instance_id = initialize.then(random_ledger_instance_id).transpose()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| KeyError::LedgerUnavailable)?;
    if initialize {
        transaction
            .execute(
                "INSERT INTO ledger_binding VALUES (1, ?1, ?2, ?3, 0)",
                rusqlite::params![
                    expected.as_slice(),
                    ledger_instance_id,
                    policy.role_manifest_digest_sha256,
                ],
            )
            .map_err(|_| KeyError::LedgerUnavailable)?;
    }
    let actual = transaction
        .query_row(
            "SELECT policy_digest,ledger_instance_id,
             role_manifest_digest_sha256,hardware_fence
             FROM ledger_binding WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    ProviderLedgerBinding {
                        ledger_instance_id: row.get(1)?,
                        role_manifest_digest_sha256: row.get(2)?,
                        hardware_fence: row.get(3)?,
                    },
                ))
            },
        )
        .optional()
        .map_err(|_| KeyError::LedgerUnavailable)?;
    let Some((actual_digest, binding)) = actual else {
        return Err(KeyError::LedgerUnavailable);
    };
    if actual_digest != expected
        || binding.role_manifest_digest_sha256 != policy.role_manifest_digest_sha256
    {
        return Err(KeyError::LedgerUnavailable);
    }
    transaction
        .commit()
        .map_err(|_| KeyError::LedgerUnavailable)?;
    Ok(binding)
}

fn policy_digest(policy: &KeyPolicy) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in [
        "crowsi-key-ledger-binding-v1",
        &policy.security_domain,
        &policy.deployment_id,
        &policy.workload_id,
        &policy.key_id,
        &policy.key_version,
        &policy.public_key_spki_sha256,
        policy.purpose.as_str(),
        policy.source.as_str(),
        policy.algorithm.as_str(),
        &policy.attestation_verifier_key_id,
        &policy.role_manifest_digest_sha256,
    ] {
        hash.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(policy.attestation_trust_revision.to_be_bytes());
    hash.update(policy.max_ttl_seconds.to_be_bytes());
    hash.update(policy.max_attestation_ttl_seconds.to_be_bytes());
    hash.update(policy.max_recovery_ttl_seconds.to_be_bytes());
    hash.finalize().into()
}

fn random_ledger_instance_id() -> Result<String, KeyError> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| KeyError::LedgerUnavailable)?;
    Ok(format!("ledger-instance:{}", hex(&random)))
}

fn hex(value: &[u8]) -> String {
    value
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
            output
        })
}
