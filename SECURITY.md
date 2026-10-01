# Security policy

- Private key bytes are absent from every public type.
- A provider signs only a fixed 32-byte digest for one pinned purpose and key.
- The only accepted algorithm is P-256/SHA-256 with canonical 64-byte IEEE
  P1363 low-S signatures verified by the independent verifier.
- Workload certificate issuance uses a dedicated purpose and key material.
- Certificate-authority receipts use a second purpose and key material; the
  certificate-signing key cannot sign protocol receipts.
- Manager durable-commit receipts use a third certificate-specific purpose and
  key; an authority receipt cannot assert a manager database commit.
- Manager-to-PA handoff receipts use a fourth certificate-specific purpose and
  key; commit and handoff evidence cannot substitute for each other.
- Provider construction requires a durable role claim sealed to security
  domain, deployment, workload, key ID/version, SPKI, purpose, algorithm,
  ledger instance, and role-manifest digest.
- The raw role binding and its hardware seal, signature, public-key binding,
  durable counter, and claim are verified by an independent verifier.
- A physical key already bound to another ledger or purpose fails closed.
- Key version and canonical SPKI SHA-256 are policy-pinned and independently
  verified; the signing port cannot attest and self-verify a substituted key.
- Every attestation is a bounded, signed vendor envelope tied to a short-lived
  challenge covering request, purpose, digest, key version, SPKI, and trust revision.
- An independent verifier must derive and verify evidence fields, signature,
  vendor chain, challenge, and public-key binding.
- Raw vendor envelopes and their signatures are redacted from `Debug` and are
  not returned in the public signing response; callers receive only verified metadata.
- Request ID, nonce, provider-generated 256-bit challenge, exact request/policy
  binding, and a deterministic ledger-scoped hardware operation ID are atomically
  journaled before signing.
- SQLite schema v5 has a CSPRNG 256-bit ledger instance ID and the last committed
  hardware fence; v4 and older databases are never migrated implicitly.
- Hardware performs an exact request-binding operation CAS. Only a newly claimed
  operation may sign; an existing exact operation permits readback only.
- A cloned database cannot authorize another request. Concurrent clones for the
  same request converge on one signature and an exact readback.
- Hardware one fence ahead of SQLite enters recovery-only mode. More than one
  ahead, rollback, skipped counters, or changed claims fail closed.
- Every error after invoking hardware is normalized to an unknown result and
  cannot be retried under the same request.
- Recovery reads a completed journal result or the same hardware operation ID;
  unsupported readback fails closed and never invokes signing again.
- Original event time and a bounded recovery deadline are durable. Expired
  requests cannot start signing, while exact attempts can resolve only within
  that separately bounded window.
- Hardware-backed, non-exportable, role-scoped, vendor-chain-verified attestation is mandatory.
- Test doubles are defined only by tests and are not a production fallback.
- No production TPM, PKCS#11, or Cloud HSM adapter is shipped yet. Deployment
  must remain unavailable until an adapter and separate verifier implement the
  sealed role claim, durable CAS/counter, and exact readback contracts.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
