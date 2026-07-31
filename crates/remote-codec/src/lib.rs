#![forbid(unsafe_code)]

//! Ubuntu software H.264 encoding for the Mobile MVP.
//!
//! Frames are normalized to packed BGRA before being sent to a persistent
//! GStreamer pipeline. `multipartmux` preserves one H.264 access unit per
//! output part, so no transport framing is inferred from H.264 start codes.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use remote_capture::{CapturedFrame, PixelFormat};

const MULTIPART_BOUNDARY: &str = "rctl";
const MAX_MULTIPART_HEADERS: usize = 16 * 1024;
const MAX_BUFFER_OVERHEAD: usize = 64 * 1024;
const MAX_ACCESS_UNIT_BYTES: usize = 32 * 1024 * 1024;

/// Parameters fixed for one GStreamer encoder process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoEncoderConfig {
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub keyframe_interval: u32,
    pub max_access_unit_bytes: usize,
    pub output_timeout: Duration,
}

impl Default for VideoEncoderConfig {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            frame_rate: 30,
            keyframe_interval: 60,
            max_access_unit_bytes: 4 * 1024 * 1024,
            output_timeout: Duration::from_secs(3),
        }
    }
}

impl VideoEncoderConfig {
    pub fn validate(&self) -> Result<(), VideoEncoderError> {
        if self.width == 0
            || self.height == 0
            || self.frame_rate == 0
            || self.keyframe_interval == 0
        {
            return Err(VideoEncoderError::InvalidConfiguration(
                "width, height, frame rate, and keyframe interval must be non-zero",
            ));
        }
        if !self.width.is_multiple_of(2) || !self.height.is_multiple_of(2) {
            return Err(VideoEncoderError::InvalidConfiguration(
                "H.264 yuv420 dimensions must be even",
            ));
        }
        if self.max_access_unit_bytes == 0 || self.max_access_unit_bytes > MAX_ACCESS_UNIT_BYTES {
            return Err(VideoEncoderError::InvalidConfiguration(
                "maximum access unit size is outside the supported range",
            ));
        }
        if self.output_timeout.is_zero() {
            return Err(VideoEncoderError::InvalidConfiguration(
                "output timeout must be non-zero",
            ));
        }
        Ok(())
    }
}

/// A complete Annex-B H.264 access unit emitted for one captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAccessUnit {
    pub data: Box<[u8]>,
    pub frame_id: u64,
    pub pts: u64,
    pub is_keyframe: bool,
}

impl EncodedAccessUnit {
    pub fn contains_nal_type(&self, nal_type: u8) -> bool {
        annex_b_nal_types(&self.data).any(|candidate| candidate == nal_type)
    }
}

/// GStreamer/x264 process-backed H.264 encoder.
pub struct VideoEncoder {
    config: VideoEncoderConfig,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    output: Receiver<Result<Vec<u8>, VideoEncoderError>>,
    reader: Option<JoinHandle<()>>,
    next_frame_id: u64,
}

impl VideoEncoder {
    pub fn new(config: VideoEncoderConfig) -> Result<Self, VideoEncoderError> {
        config.validate()?;
        let (child, stdin, output, reader) = spawn_encoder_process(&config)?;

        Ok(Self {
            config,
            child: Some(child),
            stdin: Some(stdin),
            output,
            reader: Some(reader),
            next_frame_id: 0,
        })
    }

    pub fn config(&self) -> &VideoEncoderConfig {
        &self.config
    }

    pub fn encode(
        &mut self,
        frame: &CapturedFrame,
    ) -> Result<EncodedAccessUnit, VideoEncoderError> {
        self.encode_with_options(frame, false)
    }

    pub fn encode_with_options(
        &mut self,
        frame: &CapturedFrame,
        force_keyframe: bool,
    ) -> Result<EncodedAccessUnit, VideoEncoderError> {
        if force_keyframe && self.next_frame_id > 0 {
            self.restart_process()?;
        }
        let packed = pack_bgra_frame(frame, &self.config)?;
        let timestamp_micros = frame.timestamp_micros();
        let stdin = self.stdin.as_mut().ok_or(VideoEncoderError::Stopped)?;
        stdin.write_all(&packed).map_err(VideoEncoderError::Write)?;
        stdin.flush().map_err(VideoEncoderError::Write)?;

        match self.output.recv_timeout(self.config.output_timeout) {
            Ok(Ok(data)) => {
                let is_keyframe = annex_b_nal_types(&data).any(|nal_type| nal_type == 5);
                let frame_id = self.next_frame_id;
                self.next_frame_id = self
                    .next_frame_id
                    .checked_add(1)
                    .ok_or(VideoEncoderError::FrameIdExhausted)?;
                Ok(EncodedAccessUnit {
                    data: data.into_boxed_slice(),
                    frame_id,
                    pts: timestamp_micros,
                    is_keyframe,
                })
            }
            Ok(Err(error)) => {
                let _ = self.stop();
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.stop();
                Err(VideoEncoderError::OutputTimeout(self.config.output_timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = self.stop();
                Err(VideoEncoderError::OutputClosed)
            }
        }
    }

    pub fn stop(&mut self) -> Result<(), VideoEncoderError> {
        self.stdin.take();
        let Some(child) = self.child.as_mut() else {
            self.join_reader();
            return Ok(());
        };

        let deadline = Instant::now() + self.config.output_timeout;
        loop {
            match child.try_wait().map_err(VideoEncoderError::Wait)? {
                Some(_) => break,
                None if Instant::now() >= deadline => {
                    child.kill().map_err(VideoEncoderError::Stop)?;
                    child.wait().map_err(VideoEncoderError::Wait)?;
                    break;
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        }
        self.child.take();
        self.join_reader();
        Ok(())
    }

    fn join_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }

    fn restart_process(&mut self) -> Result<(), VideoEncoderError> {
        self.stop()?;
        let (child, stdin, output, reader) = spawn_encoder_process(&self.config)?;
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.output = output;
        self.reader = Some(reader);
        Ok(())
    }
}

impl Drop for VideoEncoder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

type EncoderProcess = (
    Child,
    ChildStdin,
    Receiver<Result<Vec<u8>, VideoEncoderError>>,
    JoinHandle<()>,
);

fn spawn_encoder_process(config: &VideoEncoderConfig) -> Result<EncoderProcess, VideoEncoderError> {
    let mut command = Command::new("gst-launch-1.0");
    command
        .arg("-q")
        .arg("fdsrc")
        .arg("fd=0")
        .arg("!")
        .arg("rawvideoparse")
        .arg("format=bgra")
        .arg(format!("width={}", config.width))
        .arg(format!("height={}", config.height))
        .arg(format!("framerate={}/1", config.frame_rate))
        .arg("!")
        .arg("videoconvert")
        .arg("!")
        .arg("x264enc")
        .arg("tune=zerolatency")
        .arg("speed-preset=ultrafast")
        .arg("byte-stream=true")
        .arg("aud=true")
        .arg("bframes=0")
        .arg(format!("key-int-max={}", config.keyframe_interval))
        .arg("!")
        .arg("video/x-h264,profile=baseline,stream-format=byte-stream,alignment=au")
        .arg("!")
        .arg("multipartmux")
        .arg(format!("boundary={MULTIPART_BOUNDARY}"))
        .arg("!")
        .arg("fdsink")
        .arg("fd=1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = command.spawn().map_err(VideoEncoderError::Start)?;
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(VideoEncoderError::MissingPipe("stdin"));
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(VideoEncoderError::MissingPipe("stdout"));
    };
    let (sender, output) = mpsc::channel();
    let max_access_unit_bytes = config.max_access_unit_bytes;
    let reader = thread::spawn(move || {
        read_multipart_output(stdout, max_access_unit_bytes, sender);
    });
    Ok((child, stdin, output, reader))
}

#[derive(Debug)]
pub enum VideoEncoderError {
    InvalidConfiguration(&'static str),
    UnsupportedPixelFormat(PixelFormat),
    FrameDimensions {
        expected_width: u32,
        expected_height: u32,
        actual_width: u32,
        actual_height: u32,
    },
    FrameLayout(&'static str),
    Start(io::Error),
    MissingPipe(&'static str),
    Write(io::Error),
    Wait(io::Error),
    Stop(io::Error),
    OutputTimeout(Duration),
    OutputClosed,
    Multipart(MultipartError),
    FrameIdExhausted,
    Stopped,
}

impl fmt::Display for VideoEncoderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => write!(formatter, "invalid video encoder configuration: {reason}"),
            Self::UnsupportedPixelFormat(format) => write!(formatter, "unsupported capture pixel format for H.264 encoding: {format:?}"),
            Self::FrameDimensions { expected_width, expected_height, actual_width, actual_height } => write!(formatter, "frame dimensions {actual_width}x{actual_height} do not match encoder dimensions {expected_width}x{expected_height}"),
            Self::FrameLayout(reason) => write!(formatter, "invalid packed capture frame: {reason}"),
            Self::Start(error) => write!(formatter, "could not start GStreamer H.264 encoder: {error}"),
            Self::MissingPipe(pipe) => write!(formatter, "GStreamer H.264 encoder did not expose {pipe}"),
            Self::Write(error) => write!(formatter, "could not write a frame to GStreamer H.264 encoder: {error}"),
            Self::Wait(error) => write!(formatter, "could not wait for GStreamer H.264 encoder: {error}"),
            Self::Stop(error) => write!(formatter, "could not stop GStreamer H.264 encoder: {error}"),
            Self::OutputTimeout(timeout) => write!(formatter, "timed out waiting {timeout:?} for GStreamer H.264 output"),
            Self::OutputClosed => formatter.write_str("GStreamer H.264 output closed before an access unit arrived"),
            Self::Multipart(error) => write!(formatter, "invalid GStreamer multipart output: {error}"),
            Self::FrameIdExhausted => formatter.write_str("H.264 frame identifier space is exhausted"),
            Self::Stopped => formatter.write_str("GStreamer H.264 encoder is stopped"),
        }
    }
}

impl std::error::Error for VideoEncoderError {}

/// Incremental parser for `multipartmux boundary=rctl` output.
#[derive(Debug)]
pub struct MultipartAccessUnitParser {
    buffer: Vec<u8>,
    boundary: Vec<u8>,
    max_access_unit_bytes: usize,
}

impl MultipartAccessUnitParser {
    pub fn new(boundary: &str, max_access_unit_bytes: usize) -> Result<Self, MultipartError> {
        if boundary.is_empty() || boundary.bytes().any(|byte| !byte.is_ascii_alphanumeric()) {
            return Err(MultipartError::InvalidBoundary);
        }
        if max_access_unit_bytes == 0 || max_access_unit_bytes > MAX_ACCESS_UNIT_BYTES {
            return Err(MultipartError::InvalidMaximum);
        }
        let mut delimiter = b"--".to_vec();
        delimiter.extend_from_slice(boundary.as_bytes());
        Ok(Self {
            buffer: Vec::new(),
            boundary: delimiter,
            max_access_unit_bytes,
        })
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, MultipartError> {
        let max_buffer = self
            .max_access_unit_bytes
            .checked_add(MAX_BUFFER_OVERHEAD)
            .ok_or(MultipartError::BufferTooLarge)?;
        if input.len() > max_buffer.saturating_sub(self.buffer.len()) {
            return Err(MultipartError::BufferTooLarge);
        }
        self.buffer.extend_from_slice(input);
        let mut access_units = Vec::new();

        loop {
            let Some(boundary_index) = find_bytes(&self.buffer, &self.boundary) else {
                self.retain_boundary_suffix();
                break;
            };
            if boundary_index > 0 {
                self.buffer.drain(..boundary_index);
            }
            let boundary_end = self.boundary.len();
            if self.buffer.len() < boundary_end + 2 {
                break;
            }
            if self.buffer[boundary_end..].starts_with(b"--") {
                self.buffer.clear();
                break;
            }
            if !self.buffer[boundary_end..].starts_with(b"\r\n") {
                return Err(MultipartError::MalformedBoundary);
            }
            let headers_start = boundary_end + 2;
            let Some(headers_end_relative) = find_bytes(&self.buffer[headers_start..], b"\r\n\r\n")
            else {
                if self.buffer.len() > MAX_MULTIPART_HEADERS {
                    return Err(MultipartError::HeadersTooLarge);
                }
                break;
            };
            let headers_end = headers_start + headers_end_relative;
            let content_length = parse_content_length(&self.buffer[headers_start..headers_end])?;
            if content_length == 0 {
                return Err(MultipartError::EmptyAccessUnit);
            }
            if content_length > self.max_access_unit_bytes {
                return Err(MultipartError::AccessUnitTooLarge {
                    length: content_length,
                    maximum: self.max_access_unit_bytes,
                });
            }
            let body_start = headers_end + 4;
            let body_end = body_start.checked_add(content_length).ok_or(
                MultipartError::AccessUnitTooLarge {
                    length: content_length,
                    maximum: self.max_access_unit_bytes,
                },
            )?;
            if self.buffer.len() < body_end {
                break;
            }
            access_units.push(self.buffer[body_start..body_end].to_vec());
            self.buffer.drain(..body_end);
            if self.buffer.starts_with(b"\r\n") {
                self.buffer.drain(..2);
            }
        }
        Ok(access_units)
    }

    fn retain_boundary_suffix(&mut self) {
        let keep = self.boundary.len().saturating_sub(1);
        if self.buffer.len() > keep {
            let discard = self.buffer.len() - keep;
            self.buffer.drain(..discard);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    InvalidBoundary,
    InvalidMaximum,
    BufferTooLarge,
    HeadersTooLarge,
    MalformedBoundary,
    MissingContentLength,
    DuplicateContentLength,
    InvalidContentLength,
    EmptyAccessUnit,
    AccessUnitTooLarge { length: usize, maximum: usize },
}

impl fmt::Display for MultipartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBoundary => formatter.write_str("multipart boundary is invalid"),
            Self::InvalidMaximum => {
                formatter.write_str("multipart maximum access unit size is invalid")
            }
            Self::BufferTooLarge => formatter.write_str("multipart buffer exceeds its size limit"),
            Self::HeadersTooLarge => {
                formatter.write_str("multipart headers exceed their size limit")
            }
            Self::MalformedBoundary => formatter.write_str("multipart boundary is malformed"),
            Self::MissingContentLength => {
                formatter.write_str("multipart part has no Content-Length")
            }
            Self::DuplicateContentLength => {
                formatter.write_str("multipart part has multiple Content-Length headers")
            }
            Self::InvalidContentLength => {
                formatter.write_str("multipart Content-Length is invalid")
            }
            Self::EmptyAccessUnit => formatter.write_str("multipart access unit is empty"),
            Self::AccessUnitTooLarge { length, maximum } => write!(
                formatter,
                "multipart access unit {length} bytes exceeds {maximum} bytes"
            ),
        }
    }
}

impl std::error::Error for MultipartError {}

fn read_multipart_output<R: Read>(
    mut stdout: R,
    max_access_unit_bytes: usize,
    sender: mpsc::Sender<Result<Vec<u8>, VideoEncoderError>>,
) {
    let mut parser = match MultipartAccessUnitParser::new(MULTIPART_BOUNDARY, max_access_unit_bytes)
    {
        Ok(parser) => parser,
        Err(error) => {
            let _ = sender.send(Err(VideoEncoderError::Multipart(error)));
            return;
        }
    };
    let mut chunk = [0_u8; 8192];
    loop {
        match stdout.read(&mut chunk) {
            Ok(0) => return,
            Ok(length) => match parser.push(&chunk[..length]) {
                Ok(access_units) => {
                    for access_unit in access_units {
                        if sender.send(Ok(access_unit)).is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(VideoEncoderError::Multipart(error)));
                    return;
                }
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = sender.send(Err(VideoEncoderError::Write(error)));
                return;
            }
        }
    }
}

fn pack_bgra_frame(
    frame: &CapturedFrame,
    config: &VideoEncoderConfig,
) -> Result<Vec<u8>, VideoEncoderError> {
    if frame.width() != config.width || frame.height() != config.height {
        return Err(VideoEncoderError::FrameDimensions {
            expected_width: config.width,
            expected_height: config.height,
            actual_width: frame.width(),
            actual_height: frame.height(),
        });
    }
    if !matches!(
        frame.pixel_format(),
        PixelFormat::Bgra8 | PixelFormat::Rgba8
    ) {
        return Err(VideoEncoderError::UnsupportedPixelFormat(
            frame.pixel_format(),
        ));
    }
    let row_bytes = usize::try_from(config.width)
        .ok()
        .and_then(|width| width.checked_mul(4))
        .ok_or(VideoEncoderError::FrameLayout("row byte count overflowed"))?;
    let stride = usize::try_from(frame.stride())
        .map_err(|_| VideoEncoderError::FrameLayout("stride overflowed"))?;
    let height = usize::try_from(config.height)
        .map_err(|_| VideoEncoderError::FrameLayout("height overflowed"))?;
    if stride < row_bytes
        || frame.bytes().len()
            != stride
                .checked_mul(height)
                .ok_or(VideoEncoderError::FrameLayout("frame size overflowed"))?
    {
        return Err(VideoEncoderError::FrameLayout(
            "stride and byte length are inconsistent",
        ));
    }
    let capacity = row_bytes
        .checked_mul(height)
        .ok_or(VideoEncoderError::FrameLayout(
            "packed frame size overflowed",
        ))?;
    let mut packed = Vec::with_capacity(capacity);
    for row in frame.bytes().chunks_exact(stride).take(height) {
        let pixels = &row[..row_bytes];
        match frame.pixel_format() {
            PixelFormat::Bgra8 => packed.extend_from_slice(pixels),
            PixelFormat::Rgba8 => {
                for pixel in pixels.chunks_exact(4) {
                    packed.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
                }
            }
            PixelFormat::Nv12 => {
                return Err(VideoEncoderError::UnsupportedPixelFormat(PixelFormat::Nv12))
            }
        }
    }
    Ok(packed)
}

fn parse_content_length(headers: &[u8]) -> Result<usize, MultipartError> {
    let headers = std::str::from_utf8(headers).map_err(|_| MultipartError::InvalidContentLength)?;
    let mut content_length = None;
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            return Err(MultipartError::InvalidContentLength);
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(MultipartError::DuplicateContentLength);
            }
            if value.trim().is_empty() || !value.trim().bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(MultipartError::InvalidContentLength);
            }
            content_length = Some(
                value
                    .trim()
                    .parse()
                    .map_err(|_| MultipartError::InvalidContentLength)?,
            );
        }
    }
    content_length.ok_or(MultipartError::MissingContentLength)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn annex_b_nal_types(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut offsets = VecDeque::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        let start_code_length = if bytes[index..].starts_with(&[0, 0, 0, 1]) {
            Some(4)
        } else if bytes[index..].starts_with(&[0, 0, 1]) {
            Some(3)
        } else {
            None
        };
        if let Some(start_code_length) = start_code_length {
            if let Some(header) = bytes.get(index + start_code_length) {
                offsets.push_back(header & 0x1f);
            }
            index += start_code_length;
        } else {
            index += 1;
        }
    }
    offsets.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_capture::{CaptureLimits, FrameMetadata};

    fn frame(width: u32, height: u32, stride: u32, pixel_format: PixelFormat) -> CapturedFrame {
        let row_count = match pixel_format {
            PixelFormat::Bgra8 | PixelFormat::Rgba8 => height,
            PixelFormat::Nv12 => height + height / 2,
        };
        let bytes = usize::try_from(stride).unwrap() * usize::try_from(row_count).unwrap();
        CapturedFrame::try_new(
            FrameMetadata {
                monitor_id: 1,
                width,
                height,
                stride,
                pixel_format,
                timestamp_micros: 1234,
            },
            (0..bytes).map(|index| (index % 251) as u8).collect(),
            CaptureLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn multipart_parser_preserves_content_length_access_unit_boundaries() {
        let mut parser = MultipartAccessUnitParser::new("rctl", 128).unwrap();
        assert!(parser
            .push(b"--rctl\r\nContent-Type: video/x-h264\r\nContent-Length: 5\r\n\r\n")
            .unwrap()
            .is_empty());
        assert_eq!(
            parser
                .push(b"abcde\r\n--rctl\r\nContent-Length: 3\r\n\r\nxyz")
                .unwrap(),
            vec![b"abcde".to_vec(), b"xyz".to_vec()]
        );
    }

    #[test]
    fn multipart_parser_rejects_invalid_lengths() {
        let mut parser = MultipartAccessUnitParser::new("rctl", 8).unwrap();
        assert_eq!(
            parser
                .push(b"--rctl\r\nContent-Length: eight\r\n\r\n")
                .unwrap_err(),
            MultipartError::InvalidContentLength
        );
        let mut parser = MultipartAccessUnitParser::new("rctl", 8).unwrap();
        assert_eq!(
            parser
                .push(b"--rctl\r\nContent-Length: 0\r\n\r\n")
                .unwrap_err(),
            MultipartError::EmptyAccessUnit
        );
        let mut parser = MultipartAccessUnitParser::new("rctl", 8).unwrap();
        assert_eq!(
            parser
                .push(b"--rctl\r\nContent-Length: 9\r\n\r\n")
                .unwrap_err(),
            MultipartError::AccessUnitTooLarge {
                length: 9,
                maximum: 8
            }
        );
    }

    #[test]
    fn invalid_frame_is_rejected_before_writing_to_gstreamer() {
        let config = VideoEncoderConfig {
            width: 4,
            height: 4,
            ..VideoEncoderConfig::default()
        };
        let result = pack_bgra_frame(&frame(4, 4, 4, PixelFormat::Nv12), &config);
        assert!(matches!(
            result,
            Err(VideoEncoderError::UnsupportedPixelFormat(PixelFormat::Nv12))
        ));
    }

    #[test]
    fn encodes_a_real_annex_b_h264_access_unit_when_gstreamer_x264_is_available() {
        if Command::new("gst-launch-1.0")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
            || Command::new("gst-inspect-1.0")
                .arg("x264enc")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_or(true, |status| !status.success())
        {
            return;
        }
        let mut encoder = VideoEncoder::new(VideoEncoderConfig {
            width: 4,
            height: 4,
            output_timeout: Duration::from_secs(5),
            ..VideoEncoderConfig::default()
        })
        .unwrap();
        let access_unit = encoder
            .encode(&frame(4, 4, 20, PixelFormat::Rgba8))
            .unwrap();
        assert!(
            access_unit.data.starts_with(&[0, 0, 0, 1]) || access_unit.data.starts_with(&[0, 0, 1])
        );
        assert!(access_unit.contains_nal_type(7), "missing SPS");
        assert!(access_unit.contains_nal_type(8), "missing PPS");
        assert!(access_unit.contains_nal_type(5), "missing IDR");
        assert!(access_unit.is_keyframe);
        let forced = encoder
            .encode_with_options(&frame(4, 4, 20, PixelFormat::Rgba8), true)
            .unwrap();
        assert_eq!(forced.frame_id, access_unit.frame_id + 1);
        assert!(forced.is_keyframe);
        assert!(forced.contains_nal_type(7));
        assert!(forced.contains_nal_type(8));
        encoder.stop().unwrap();
    }
}
