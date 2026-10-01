use rusqlite::Connection;

pub(crate) const REPLAY_DDL: &str = "CREATE TABLE IF NOT EXISTS signing_replay(
  request_hash BLOB PRIMARY KEY CHECK(length(request_hash)=32),
  nonce_hash BLOB NOT NULL UNIQUE CHECK(length(nonce_hash)=32),
  challenge_hash BLOB NOT NULL UNIQUE CHECK(length(challenge_hash)=32)
) STRICT;";

pub(crate) const CLOCK_DDL: &str = "CREATE TABLE IF NOT EXISTS trusted_clock_watermark(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  epoch_s INTEGER NOT NULL CHECK(epoch_s>=0)
) STRICT;";

pub(crate) const BINDING_DDL: &str = "CREATE TABLE IF NOT EXISTS ledger_binding(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  policy_digest BLOB NOT NULL CHECK(length(policy_digest)=32),
  ledger_instance_id TEXT NOT NULL UNIQUE
    CHECK(length(ledger_instance_id)=80 AND ledger_instance_id GLOB 'ledger-instance:[0-9a-f]*'),
  role_manifest_digest_sha256 TEXT NOT NULL
    CHECK(length(role_manifest_digest_sha256)=64),
  hardware_fence INTEGER NOT NULL CHECK(hardware_fence>=0)
) STRICT;";

pub(crate) const ATTEMPT_DDL: &str = "CREATE TABLE IF NOT EXISTS signing_attempt(
  request_hash BLOB PRIMARY KEY REFERENCES signing_replay(request_hash)
    CHECK(length(request_hash)=32),
  request_binding_sha256 TEXT NOT NULL UNIQUE CHECK(length(request_binding_sha256)=64),
  operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id)=83),
  ledger_instance_id TEXT NOT NULL CHECK(length(ledger_instance_id)=80),
  role_claim_digest_sha256 TEXT NOT NULL CHECK(length(role_claim_digest_sha256)=64),
  key_id TEXT NOT NULL,
  key_version TEXT NOT NULL,
  public_key_spki_sha256 TEXT NOT NULL CHECK(length(public_key_spki_sha256)=64),
  purpose TEXT NOT NULL,
  algorithm TEXT NOT NULL CHECK(algorithm='ecdsa-p256-sha256-p1363-low-s'),
  signing_digest_sha256 TEXT NOT NULL CHECK(length(signing_digest_sha256)=64),
  request_issued_at_epoch_s INTEGER NOT NULL CHECK(request_issued_at_epoch_s>=0),
  request_expires_at_epoch_s INTEGER NOT NULL CHECK(request_expires_at_epoch_s>request_issued_at_epoch_s),
  recovery_deadline_epoch_s INTEGER NOT NULL CHECK(recovery_deadline_epoch_s>request_expires_at_epoch_s),
  previous_hardware_fence INTEGER NOT NULL CHECK(previous_hardware_fence>=0),
  hardware_fence INTEGER NOT NULL CHECK(hardware_fence=previous_hardware_fence+1),
  state TEXT NOT NULL CHECK(state IN ('invocation-pending','result-unknown','completed')),
  signature BLOB,
  CHECK((state='completed' AND length(signature)=64)
    OR (state!='completed' AND signature IS NULL))
) STRICT;";

pub(crate) fn version_matches(connection: &Connection) -> bool {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap_or_default();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or_default();
    application == 1_129_466_704 && version == 5
}

pub(crate) fn schema_matches(connection: &Connection) -> bool {
    let replay = table_sql(connection, "signing_replay");
    let clock = table_sql(connection, "trusted_clock_watermark");
    let binding = table_sql(connection, "ledger_binding");
    let attempt = table_sql(connection, "signing_attempt");
    let unexpected: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_autoindex_signing_replay_%'
               AND name NOT LIKE 'sqlite_autoindex_signing_attempt_%'
               AND name NOT LIKE 'sqlite_autoindex_ledger_binding_%'
               AND NOT(type='table' AND name IN (
                 'signing_replay', 'trusted_clock_watermark', 'ledger_binding',
                 'signing_attempt'
               ))",
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);
    normalized(&replay) == normalized(&REPLAY_DDL.replace(" IF NOT EXISTS", ""))
        && normalized(&clock) == normalized(&CLOCK_DDL.replace(" IF NOT EXISTS", ""))
        && normalized(&binding) == normalized(&BINDING_DDL.replace(" IF NOT EXISTS", ""))
        && normalized(&attempt) == normalized(&ATTEMPT_DDL.replace(" IF NOT EXISTS", ""))
        && unexpected == 0
}

fn table_sql(connection: &Connection, name: &str) -> String {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .unwrap_or_default()
}

fn normalized(value: &str) -> String {
    value
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
