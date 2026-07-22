use std::cmp::Ordering;

use crate::{ConnectionCandidate, LinkMetrics, TransportError, TransportKind, TransportResult};

pub const DEFAULT_TLS_443_START_DELAY_MILLIS: u64 = 500;
pub const DEFAULT_RTT_CLOSE_THRESHOLD_MILLIS: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaceConfig {
    pub tls_443_start_delay_millis: u64,
    pub rtt_close_threshold_millis: u32,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            tls_443_start_delay_millis: DEFAULT_TLS_443_START_DELAY_MILLIS,
            rtt_close_threshold_millis: DEFAULT_RTT_CLOSE_THRESHOLD_MILLIS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceAttemptState {
    Pending,
    Started,
    Succeeded(LinkMetrics),
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceAttempt {
    pub attempt_id: usize,
    pub candidate: ConnectionCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceWinner {
    pub attempt_id: usize,
    pub candidate: ConnectionCandidate,
    pub metrics: LinkMetrics,
}

#[derive(Debug, Clone)]
struct AttemptEntry {
    candidate: ConnectionCandidate,
    state: RaceAttemptState,
}

#[derive(Debug, Clone)]
pub struct PathRace {
    config: RaceConfig,
    started_at_epoch_millis: u64,
    attempts: Vec<AttemptEntry>,
}

impl PathRace {
    pub fn new(
        candidates: impl IntoIterator<Item = ConnectionCandidate>,
        started_at_epoch_millis: u64,
        config: RaceConfig,
    ) -> Self {
        Self {
            config,
            started_at_epoch_millis,
            attempts: candidates
                .into_iter()
                .map(|candidate| AttemptEntry {
                    candidate,
                    state: RaceAttemptState::Pending,
                })
                .collect(),
        }
    }

    /// Returns all probes that must be started now. LAN, UDP P2P and QUIC
    /// Relay are released together; TLS 443 Relay observes its configured delay.
    pub fn take_due_attempts(&mut self, now_epoch_millis: u64) -> Vec<RaceAttempt> {
        let tls_due = now_epoch_millis.saturating_sub(self.started_at_epoch_millis)
            >= self.config.tls_443_start_delay_millis;
        self.attempts
            .iter_mut()
            .enumerate()
            .filter_map(|(attempt_id, entry)| {
                if entry.state != RaceAttemptState::Pending
                    || (entry.candidate.kind == TransportKind::Tls443Relay && !tls_due)
                {
                    return None;
                }
                entry.state = RaceAttemptState::Started;
                Some(RaceAttempt {
                    attempt_id,
                    candidate: entry.candidate.clone(),
                })
            })
            .collect()
    }

    pub fn record_success(
        &mut self,
        attempt_id: usize,
        metrics: LinkMetrics,
    ) -> TransportResult<()> {
        let entry = self
            .attempts
            .get_mut(attempt_id)
            .ok_or(TransportError::InvalidState)?;
        if entry.state != RaceAttemptState::Started {
            return Err(TransportError::InvalidState);
        }
        entry.state = RaceAttemptState::Succeeded(metrics);
        Ok(())
    }

    pub fn record_failure(&mut self, attempt_id: usize) -> TransportResult<()> {
        let entry = self
            .attempts
            .get_mut(attempt_id)
            .ok_or(TransportError::InvalidState)?;
        if entry.state != RaceAttemptState::Started {
            return Err(TransportError::InvalidState);
        }
        entry.state = RaceAttemptState::Failed;
        Ok(())
    }

    pub fn attempt_state(&self, attempt_id: usize) -> Option<RaceAttemptState> {
        self.attempts.get(attempt_id).map(|entry| entry.state)
    }

    pub fn best_success(&self) -> Option<RaceWinner> {
        self.attempts
            .iter()
            .enumerate()
            .filter_map(|(attempt_id, entry)| match entry.state {
                RaceAttemptState::Succeeded(metrics) => Some(RaceWinner {
                    attempt_id,
                    candidate: entry.candidate.clone(),
                    metrics,
                }),
                _ => None,
            })
            .min_by(|left, right| compare_winners(left, right, self.config))
    }

    pub fn is_complete(&self) -> bool {
        self.attempts.iter().all(|entry| {
            matches!(
                entry.state,
                RaceAttemptState::Succeeded(_) | RaceAttemptState::Failed
            )
        })
    }
}

fn compare_winners(left: &RaceWinner, right: &RaceWinner, config: RaceConfig) -> Ordering {
    left.candidate
        .kind
        .priority()
        .cmp(&right.candidate.kind.priority())
        .then_with(|| compare_same_path_metrics(left.metrics, right.metrics, config))
        .then_with(|| left.attempt_id.cmp(&right.attempt_id))
}

fn compare_same_path_metrics(
    left: LinkMetrics,
    right: LinkMetrics,
    config: RaceConfig,
) -> Ordering {
    if left.rtt_ms.abs_diff(right.rtt_ms) <= config.rtt_close_threshold_millis {
        left.loss_ppm
            .cmp(&right.loss_ppm)
            .then_with(|| left.jitter_ms.cmp(&right.jitter_ms))
            .then_with(|| left.rtt_ms.cmp(&right.rtt_ms))
    } else {
        left.rtt_ms.cmp(&right.rtt_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(kind: TransportKind, endpoint: &str) -> ConnectionCandidate {
        ConnectionCandidate {
            kind,
            endpoint: endpoint.to_owned(),
            rtt_ms: None,
        }
    }

    #[test]
    fn starts_three_primary_paths_together_and_delays_tls_443() {
        let mut race = PathRace::new(
            [
                candidate(TransportKind::LanDirect, "192.168.1.2:4000"),
                candidate(TransportKind::UdpP2p, "198.51.100.2:4000"),
                candidate(TransportKind::QuicRelay, "relay.example:443"),
                candidate(TransportKind::Tls443Relay, "relay.example:443"),
            ],
            1_000,
            RaceConfig::default(),
        );

        let initial = race.take_due_attempts(1_000);
        assert_eq!(initial.len(), 3);
        assert_eq!(
            initial
                .iter()
                .map(|attempt| attempt.candidate.kind)
                .collect::<Vec<_>>(),
            vec![
                TransportKind::LanDirect,
                TransportKind::UdpP2p,
                TransportKind::QuicRelay
            ]
        );
        assert!(race.take_due_attempts(1_499).is_empty());
        assert_eq!(
            race.take_due_attempts(1_500)[0].candidate.kind,
            TransportKind::Tls443Relay
        );
    }

    #[test]
    fn path_priority_wins_before_latency() {
        let mut race = PathRace::new(
            [
                candidate(TransportKind::UdpP2p, "p2p"),
                candidate(TransportKind::QuicRelay, "relay"),
            ],
            0,
            RaceConfig::default(),
        );
        race.take_due_attempts(0);
        race.record_success(
            0,
            LinkMetrics {
                rtt_ms: 50,
                loss_ppm: 100,
                jitter_ms: 5,
            },
        )
        .expect("p2p result");
        race.record_success(
            1,
            LinkMetrics {
                rtt_ms: 5,
                loss_ppm: 0,
                jitter_ms: 0,
            },
        )
        .expect("relay result");

        assert_eq!(
            race.best_success().map(|winner| winner.candidate.kind),
            Some(TransportKind::UdpP2p)
        );
    }

    #[test]
    fn close_rtt_uses_loss_then_jitter() {
        let mut race = PathRace::new(
            [
                candidate(TransportKind::UdpP2p, "lossy"),
                candidate(TransportKind::UdpP2p, "stable"),
            ],
            0,
            RaceConfig::default(),
        );
        race.take_due_attempts(0);
        race.record_success(
            0,
            LinkMetrics {
                rtt_ms: 20,
                loss_ppm: 2_000,
                jitter_ms: 1,
            },
        )
        .expect("lossy result");
        race.record_success(
            1,
            LinkMetrics {
                rtt_ms: 25,
                loss_ppm: 100,
                jitter_ms: 3,
            },
        )
        .expect("stable result");

        assert_eq!(
            race.best_success().map(|winner| winner.candidate.endpoint),
            Some("stable".to_owned())
        );
    }
}
