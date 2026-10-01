mod port;
mod state;

pub use port::RecoverablePort;
pub use state::HardwareProbe;

#[derive(Clone, Copy)]
pub enum SignBehavior {
    Return,
    LoseResponse,
    RemainUnknown,
}
