use std::time::{SystemTime, UNIX_EPOCH};

use crate::KeyError;

/// Supplies time from the signing service's trusted boundary, not its caller.
pub trait TrustedClock {
    /// Returns the current Unix epoch seconds.
    ///
    /// # Errors
    ///
    /// Fails when trusted time is unavailable.
    fn now_epoch_s(&mut self) -> Result<u64, KeyError>;
}

/// Production default backed by the host system clock.
pub struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now_epoch_s(&mut self) -> Result<u64, KeyError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .map_err(|_| KeyError::TrustedTimeUnavailable)
    }
}
