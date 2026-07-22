use std::collections::VecDeque;

use remote_protocol::{ChannelId, MessageHeader};

pub const DEFAULT_MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
const PRIORITY_LEVELS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    InvalidChannel,
    PayloadLengthMismatch,
    Backpressure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledPacket {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

impl ScheduledPacket {
    fn wire_len(&self) -> usize {
        remote_protocol::HEADER_LEN.saturating_add(self.payload.len())
    }
}

#[derive(Debug, Clone)]
pub struct PriorityScheduler {
    queues: [VecDeque<ScheduledPacket>; PRIORITY_LEVELS],
    latest_realtime_input: Option<ScheduledPacket>,
    max_queued_bytes: usize,
    queued_bytes: usize,
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_QUEUED_BYTES)
    }
}

impl PriorityScheduler {
    pub fn new(max_queued_bytes: usize) -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            latest_realtime_input: None,
            max_queued_bytes,
            queued_bytes: 0,
        }
    }

    pub fn enqueue(&mut self, packet: ScheduledPacket) -> Result<(), SchedulerError> {
        packet
            .header
            .validate_kind_channel()
            .map_err(|_| SchedulerError::InvalidChannel)?;
        if usize::try_from(packet.header.payload_len).ok() != Some(packet.payload.len()) {
            return Err(SchedulerError::PayloadLengthMismatch);
        }

        if packet.header.channel_id == ChannelId::InputRealtime {
            let replaced_len = self
                .latest_realtime_input
                .as_ref()
                .map_or(0, ScheduledPacket::wire_len);
            let projected = self
                .queued_bytes
                .saturating_sub(replaced_len)
                .saturating_add(packet.wire_len());
            if projected > self.max_queued_bytes {
                return Err(SchedulerError::Backpressure);
            }
            self.latest_realtime_input = Some(packet);
            self.queued_bytes = projected;
            return Ok(());
        }

        let projected = self.queued_bytes.saturating_add(packet.wire_len());
        if projected > self.max_queued_bytes {
            return Err(SchedulerError::Backpressure);
        }
        self.queued_bytes = projected;
        self.queues[channel_priority(packet.header.channel_id)].push_back(packet);
        Ok(())
    }

    pub fn pop_next(&mut self) -> Option<ScheduledPacket> {
        // Realtime input has the same top-class treatment as channels 0/1/7,
        // while replacement prevents stale mouse movement from accumulating.
        let packet = self
            .latest_realtime_input
            .take()
            .or_else(|| self.queues.iter_mut().find_map(|queue| queue.pop_front()))?;
        self.queued_bytes = self.queued_bytes.saturating_sub(packet.wire_len());
        Some(packet)
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.latest_realtime_input.is_none() && self.queues.iter().all(VecDeque::is_empty)
    }
}

const fn channel_priority(channel: ChannelId) -> usize {
    match channel {
        ChannelId::SecureControl | ChannelId::InputReliable | ChannelId::DeviceControl => 0,
        ChannelId::MediaControl => 1,
        ChannelId::Video => 2,
        ChannelId::Clipboard => 3,
        ChannelId::FileTransfer => 4,
        ChannelId::Telemetry => 5,
        ChannelId::InputRealtime => 0,
    }
}

#[cfg(test)]
mod tests {
    use remote_protocol::{MessageKind, PROTOCOL_VERSION};

    use super::*;

    fn packet(kind: MessageKind, channel: ChannelId, sequence: u64, byte: u8) -> ScheduledPacket {
        ScheduledPacket {
            header: MessageHeader {
                version: PROTOCOL_VERSION,
                kind,
                flags: 0,
                channel_id: channel,
                session_id: 1,
                sequence,
                payload_len: 1,
            },
            payload: vec![byte],
        }
    }

    #[test]
    fn fixed_channel_classes_preempt_file_and_telemetry() {
        let mut scheduler = PriorityScheduler::default();
        scheduler
            .enqueue(packet(MessageKind::Stats, ChannelId::Telemetry, 0, 8))
            .expect("telemetry");
        scheduler
            .enqueue(packet(
                MessageKind::FileChunk,
                ChannelId::FileTransfer,
                0,
                6,
            ))
            .expect("file");
        scheduler
            .enqueue(packet(MessageKind::VideoFrameData, ChannelId::Video, 0, 4))
            .expect("video");
        scheduler
            .enqueue(packet(
                MessageKind::MediaConfigState,
                ChannelId::MediaControl,
                0,
                3,
            ))
            .expect("media control");
        scheduler
            .enqueue(packet(
                MessageKind::InputEvent,
                ChannelId::InputReliable,
                0,
                1,
            ))
            .expect("input");

        let order = std::iter::from_fn(|| scheduler.pop_next())
            .map(|packet| packet.header.channel_id)
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                ChannelId::InputReliable,
                ChannelId::MediaControl,
                ChannelId::Video,
                ChannelId::FileTransfer,
                ChannelId::Telemetry
            ]
        );
    }

    #[test]
    fn realtime_input_keeps_only_latest_movement() {
        let mut scheduler = PriorityScheduler::default();
        scheduler
            .enqueue(packet(
                MessageKind::InputEvent,
                ChannelId::InputRealtime,
                1,
                1,
            ))
            .expect("first movement");
        scheduler
            .enqueue(packet(
                MessageKind::InputEvent,
                ChannelId::InputRealtime,
                2,
                2,
            ))
            .expect("latest movement");

        let packet = scheduler.pop_next().expect("latest packet");
        assert_eq!(packet.header.sequence, 2);
        assert_eq!(packet.payload, [2]);
        assert!(scheduler.is_empty());
    }

    #[test]
    fn rejects_wrong_kind_channel() {
        let mut scheduler = PriorityScheduler::default();
        assert_eq!(
            scheduler.enqueue(packet(
                MessageKind::VideoFrameData,
                ChannelId::FileTransfer,
                0,
                1
            )),
            Err(SchedulerError::InvalidChannel)
        );
    }
}
