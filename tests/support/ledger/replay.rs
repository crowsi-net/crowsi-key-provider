use crowsi_key_provider::{KeyError, ReplayLedger};

use super::MemoryLedger;

impl ReplayLedger for MemoryLedger {
    fn observe_time(&mut self, now_epoch_s: u64) -> Result<(), KeyError> {
        if self
            .clock_watermark
            .is_some_and(|previous| now_epoch_s < previous)
        {
            return Err(KeyError::TrustedTimeUnavailable);
        }
        self.clock_watermark = Some(now_epoch_s);
        Ok(())
    }

    fn reserve(
        &mut self,
        request_id: &str,
        nonce: &str,
        challenge_digest: &str,
    ) -> Result<(), KeyError> {
        if self.requests.contains(request_id)
            || self.nonces.contains(nonce)
            || self.challenges.contains(challenge_digest)
        {
            return Err(KeyError::ReplayRejected);
        }
        self.requests.insert(request_id.into());
        self.nonces.insert(nonce.into());
        self.challenges.insert(challenge_digest.into());
        Ok(())
    }
}
