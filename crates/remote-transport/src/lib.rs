mod binding;
mod candidates;
mod channel;
mod observe;
mod p2p;
mod quic;
mod racing;
mod reconnect;
mod scheduler;
mod tls_fallback;

#[cfg(test)]
pub mod test_tls;

#[cfg(all(feature = "test-support", not(test)))]
pub mod test_tls;

pub use binding::*;
pub use candidates::*;
pub use channel::*;
pub use observe::*;
pub use p2p::*;
pub use quic::*;
pub use racing::*;
pub use reconnect::*;
pub use scheduler::*;
pub use tls_fallback::*;

use remote_protocol::{MessageHeader, TransportPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    LanDirect,
    UdpP2p,
    QuicRelay,
    Tls443Relay,
}

impl TransportKind {
    pub const fn priority(self) -> u8 {
        match self {
            Self::LanDirect => 0,
            Self::UdpP2p => 1,
            Self::QuicRelay => 2,
            Self::Tls443Relay => 3,
        }
    }
}

impl From<TransportKind> for TransportPath {
    fn from(value: TransportKind) -> Self {
        match value {
            TransportKind::LanDirect => Self::LanDirect,
            TransportKind::UdpP2p => Self::UdpP2p,
            TransportKind::QuicRelay => Self::QuicRelay,
            TransportKind::Tls443Relay => Self::Tls443Relay,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCandidate {
    pub kind: TransportKind,
    pub endpoint: String,
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkMetrics {
    pub rtt_ms: u32,
    pub loss_ppm: u32,
    pub jitter_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket<'a> {
    pub header: MessageHeader,
    pub payload: &'a [u8],
}

pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    NotConnected,
    Backpressure,
    Closed,
    InvalidState,
    InvalidBinding(BindingError),
    Io(String),
}

pub trait Transport {
    fn kind(&self) -> TransportKind;
    fn send(&mut self, packet: OutboundPacket<'_>) -> TransportResult<()>;
    fn poll(&mut self) -> TransportResult<Option<Vec<u8>>>;
}

pub fn choose_best_candidate(candidates: &[ConnectionCandidate]) -> Option<&ConnectionCandidate> {
    candidates.iter().min_by_key(|candidate| {
        let rtt = candidate.rtt_ms.unwrap_or(u32::MAX / 2);
        (candidate.kind.priority(), rtt)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_path_priority_over_relay_rtt() {
        let candidates = [
            ConnectionCandidate {
                kind: TransportKind::QuicRelay,
                endpoint: "relay.example:443".to_owned(),
                rtt_ms: Some(5),
            },
            ConnectionCandidate {
                kind: TransportKind::UdpP2p,
                endpoint: "203.0.113.10:50000".to_owned(),
                rtt_ms: Some(20),
            },
        ];

        assert_eq!(
            choose_best_candidate(&candidates).map(|candidate| candidate.kind),
            Some(TransportKind::UdpP2p)
        );
    }
}
