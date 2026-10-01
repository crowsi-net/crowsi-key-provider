//! Durable state and recovery scenarios share one SQLite-linked executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../durable_role_binding.rs"]
mod durable_role_binding;
#[path = "../fence_recovery.rs"]
mod fence_recovery;
#[path = "../post_invocation_failure.rs"]
mod post_invocation_failure;
#[path = "../signing_recovery.rs"]
mod signing_recovery;
#[path = "../signing_recovery_rejection.rs"]
mod signing_recovery_rejection;
#[path = "../sqlite_integrity.rs"]
mod sqlite_integrity;
#[path = "../sqlite_replay.rs"]
mod sqlite_replay;
