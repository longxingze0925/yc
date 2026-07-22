use std::time::Instant;

use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xproto::{
    ConnectionExt as _, ImageFormat, ImageOrder, VisualClass, Visualtype, Window,
};
use x11rb::rust_connection::RustConnection;

use crate::{
    CaptureAuthorizationState, CaptureBackend, CaptureError, CaptureLimits, CaptureResult,
    CaptureState, CapturedFrame, FrameMetadata, MonitorInfo, PixelFormat, ScreenCapturer,
};

#[derive(Debug, Clone)]
struct X11Monitor {
    public: MonitorInfo,
    x: i16,
    y: i16,
    width: u16,
    height: u16,
}

struct X11Session {
    connection: RustConnection,
    root: Window,
    root_depth: u8,
    image_byte_order: ImageOrder,
    bits_per_pixel: u8,
    scanline_pad: u8,
    visual: Visualtype,
    monitors: Vec<X11Monitor>,
}

pub struct UbuntuX11Capturer {
    state: CaptureState,
    session: Option<X11Session>,
    started_at: Option<Instant>,
    last_timestamp_micros: u64,
    limits: CaptureLimits,
}

impl std::fmt::Debug for UbuntuX11Capturer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UbuntuX11Capturer")
            .field("state", &self.state)
            .field("connected", &self.session.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl Default for UbuntuX11Capturer {
    fn default() -> Self {
        Self::new(CaptureLimits::default())
    }
}

impl UbuntuX11Capturer {
    pub fn new(limits: CaptureLimits) -> Self {
        Self {
            state: CaptureState::Idle,
            session: None,
            started_at: None,
            last_timestamp_micros: 0,
            limits,
        }
    }

    fn open_session(&self) -> CaptureResult<X11Session> {
        let (connection, screen_number) =
            x11rb::connect(None).map_err(|error| x11_failure("connect", error))?;
        let (root, root_depth, image_byte_order, bits_per_pixel, scanline_pad, visual) = {
            let setup = connection.setup();
            let screen =
                setup
                    .roots
                    .get(screen_number)
                    .ok_or_else(|| CaptureError::BackendFailure {
                        backend: CaptureBackend::UbuntuX11GetImage,
                        operation: "select screen",
                        reason: format!("X11 screen index {screen_number} is missing"),
                    })?;
            let format = setup
                .pixmap_formats
                .iter()
                .find(|format| format.depth == screen.root_depth)
                .ok_or_else(|| CaptureError::BackendFailure {
                    backend: CaptureBackend::UbuntuX11GetImage,
                    operation: "select pixel format",
                    reason: format!("no pixmap format for root depth {}", screen.root_depth),
                })?;
            let visual = screen
                .allowed_depths
                .iter()
                .flat_map(|depth| depth.visuals.iter())
                .find(|visual| visual.visual_id == screen.root_visual)
                .cloned()
                .ok_or_else(|| CaptureError::BackendFailure {
                    backend: CaptureBackend::UbuntuX11GetImage,
                    operation: "select root visual",
                    reason: format!("root visual {} was not advertised", screen.root_visual),
                })?;
            (
                screen.root,
                screen.root_depth,
                setup.image_byte_order,
                format.bits_per_pixel,
                format.scanline_pad,
                visual,
            )
        };
        if visual.class != VisualClass::TRUE_COLOR {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuX11GetImage,
                reason: format!(
                    "root visual class {:?} is not TrueColor; indexed and DirectColor visuals require colormap conversion",
                    visual.class
                ),
            });
        }
        if !valid_color_masks(&visual) {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuX11GetImage,
                reason:
                    "the X11 TrueColor visual has zero, overlapping, or non-contiguous RGB masks"
                        .into(),
            });
        }

        let monitors = query_monitors(&connection, screen_number, self.limits)?;
        Ok(X11Session {
            connection,
            root,
            root_depth,
            image_byte_order,
            bits_per_pixel,
            scanline_pad,
            visual,
            monitors,
        })
    }

    fn next_timestamp_micros(&mut self) -> u64 {
        let elapsed = self
            .started_at
            .map(|started_at| started_at.elapsed().as_micros())
            .unwrap_or_default();
        let elapsed = u64::try_from(elapsed).unwrap_or(u64::MAX);
        let timestamp = elapsed.max(self.last_timestamp_micros.saturating_add(1));
        self.last_timestamp_micros = timestamp;
        timestamp
    }
}

impl ScreenCapturer for UbuntuX11Capturer {
    fn backend(&self) -> CaptureBackend {
        CaptureBackend::UbuntuX11GetImage
    }

    fn state(&self) -> CaptureState {
        self.state
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        CaptureAuthorizationState::NotRequired
    }

    fn start(&mut self) -> CaptureResult<()> {
        if self.state == CaptureState::Running {
            return Ok(());
        }
        let session = self.open_session()?;
        self.session = Some(session);
        self.started_at = Some(Instant::now());
        self.last_timestamp_micros = 0;
        self.state = CaptureState::Running;
        Ok(())
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        let session = self.session.as_ref().ok_or(CaptureError::InvalidState)?;
        Ok(session
            .monitors
            .iter()
            .map(|monitor| monitor.public.clone())
            .collect())
    }

    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        let (width, height, bgra) = {
            let session = self.session.as_ref().ok_or(CaptureError::InvalidState)?;
            let monitor = session
                .monitors
                .iter()
                .find(|monitor| monitor.public.monitor_id == monitor_id)
                .ok_or(CaptureError::MonitorNotFound)?;
            let capture_width = u32::from(monitor.width);
            let capture_height = u32::from(monitor.height);
            let capture_stride = capture_width
                .checked_mul(4)
                .ok_or(CaptureError::InvalidFrame("pixel stride overflow"))?;
            self.limits.validate_layout(
                capture_width,
                capture_height,
                capture_stride,
                PixelFormat::Bgra8,
            )?;

            let reply = session
                .connection
                .get_image(
                    ImageFormat::Z_PIXMAP,
                    session.root,
                    monitor.x,
                    monitor.y,
                    monitor.width,
                    monitor.height,
                    u32::MAX,
                )
                .map_err(|error| x11_failure("request frame", error))?
                .reply()
                .map_err(|error| x11_failure("receive frame", error))?;
            if reply.depth != session.root_depth {
                return Err(CaptureError::InvalidFrame(
                    "X11 image depth changed during capture",
                ));
            }
            let bgra = convert_to_bgra(
                &reply.data,
                monitor.width,
                monitor.height,
                session.bits_per_pixel,
                session.scanline_pad,
                session.image_byte_order,
                &session.visual,
                self.limits,
            )?;
            (u32::from(monitor.width), u32::from(monitor.height), bgra)
        };
        let stride = width
            .checked_mul(4)
            .ok_or(CaptureError::InvalidFrame("pixel stride overflow"))?;
        CapturedFrame::try_new(
            FrameMetadata {
                monitor_id,
                width,
                height,
                stride,
                pixel_format: PixelFormat::Bgra8,
                timestamp_micros: self.next_timestamp_micros(),
            },
            bgra,
            self.limits,
        )
    }

    fn stop(&mut self) -> CaptureResult<()> {
        self.session = None;
        self.started_at = None;
        self.state = CaptureState::Stopped;
        Ok(())
    }
}

impl Drop for UbuntuX11Capturer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn query_monitors(
    connection: &RustConnection,
    screen_number: usize,
    limits: CaptureLimits,
) -> CaptureResult<Vec<X11Monitor>> {
    let screen = connection
        .setup()
        .roots
        .get(screen_number)
        .ok_or(CaptureError::BackendUnavailable)?;
    if let Ok(cookie) = connection.randr_get_monitors(screen.root, true) {
        if let Ok(reply) = cookie.reply() {
            let mut monitors = Vec::with_capacity(reply.monitors.len());
            for (index, monitor) in reply.monitors.into_iter().enumerate() {
                limits.validate_dimensions(u32::from(monitor.width), u32::from(monitor.height))?;
                let name = connection
                    .get_atom_name(monitor.name)
                    .ok()
                    .and_then(|cookie| cookie.reply().ok())
                    .map(|reply| String::from_utf8_lossy(&reply.name).into_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| format!("X11 monitor {}", index + 1));
                let monitor_id = if monitor.name == 0 {
                    u32::try_from(index + 1).unwrap_or(u32::MAX)
                } else {
                    monitor.name
                };
                monitors.push(X11Monitor {
                    public: MonitorInfo {
                        monitor_id,
                        name,
                        x: i32::from(monitor.x),
                        y: i32::from(monitor.y),
                        width: u32::from(monitor.width),
                        height: u32::from(monitor.height),
                        scale_factor_milli: 1_000,
                        is_primary: monitor.primary,
                    },
                    x: monitor.x,
                    y: monitor.y,
                    width: monitor.width,
                    height: monitor.height,
                });
            }
            if !monitors.is_empty() {
                return Ok(monitors);
            }
        }
    }

    limits.validate_dimensions(
        u32::from(screen.width_in_pixels),
        u32::from(screen.height_in_pixels),
    )?;
    Ok(vec![X11Monitor {
        public: MonitorInfo {
            monitor_id: 1,
            name: format!("X11 screen {screen_number}"),
            x: 0,
            y: 0,
            width: u32::from(screen.width_in_pixels),
            height: u32::from(screen.height_in_pixels),
            scale_factor_milli: 1_000,
            is_primary: true,
        },
        x: 0,
        y: 0,
        width: screen.width_in_pixels,
        height: screen.height_in_pixels,
    }])
}

#[allow(clippy::too_many_arguments)]
fn convert_to_bgra(
    source: &[u8],
    width: u16,
    height: u16,
    bits_per_pixel: u8,
    scanline_pad: u8,
    byte_order: ImageOrder,
    visual: &Visualtype,
    limits: CaptureLimits,
) -> CaptureResult<Vec<u8>> {
    let bytes_per_pixel = match bits_per_pixel {
        16 => 2_usize,
        24 => 3,
        32 => 4,
        _ => {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuX11GetImage,
                reason: format!("{bits_per_pixel}-bit X11 pixels are not supported"),
            });
        }
    };
    if scanline_pad == 0 || !scanline_pad.is_power_of_two() || !scanline_pad.is_multiple_of(8) {
        return Err(CaptureError::InvalidFrame(
            "X11 scanline padding is invalid",
        ));
    }
    let width = usize::from(width);
    let height = usize::from(height);
    let row_bits = width
        .checked_mul(usize::from(bits_per_pixel))
        .ok_or(CaptureError::InvalidFrame("X11 row size overflow"))?;
    let pad_bits = usize::from(scanline_pad);
    let padded_row_bits = row_bits
        .checked_add(pad_bits - 1)
        .ok_or(CaptureError::InvalidFrame("X11 padded row size overflow"))?
        / pad_bits
        * pad_bits;
    let source_stride = padded_row_bits / 8;
    let required_source = source_stride
        .checked_mul(height)
        .ok_or(CaptureError::InvalidFrame("X11 frame size overflow"))?;
    if source.len() < required_source {
        return Err(CaptureError::InvalidFrame(
            "X11 returned fewer bytes than its pixel format requires",
        ));
    }

    let destination_stride = width
        .checked_mul(4)
        .ok_or(CaptureError::InvalidFrame("BGRA row size overflow"))?;
    let destination_len = destination_stride
        .checked_mul(height)
        .ok_or(CaptureError::InvalidFrame("BGRA frame size overflow"))?;
    if destination_len > limits.max_frame_bytes() {
        return Err(CaptureError::FrameTooLarge {
            width: u32::try_from(width).unwrap_or(u32::MAX),
            height: u32::try_from(height).unwrap_or(u32::MAX),
            bytes: destination_len,
            max_bytes: limits.max_frame_bytes(),
        });
    }

    let mut destination = vec![0_u8; destination_len];
    for y in 0..height {
        let source_row = &source[y * source_stride..(y + 1) * source_stride];
        let destination_row =
            &mut destination[y * destination_stride..(y + 1) * destination_stride];
        for x in 0..width {
            let offset = x * bytes_per_pixel;
            let pixel = read_pixel(&source_row[offset..offset + bytes_per_pixel], byte_order);
            let destination_pixel = &mut destination_row[x * 4..x * 4 + 4];
            destination_pixel.copy_from_slice(&[
                component_to_u8(pixel, visual.blue_mask),
                component_to_u8(pixel, visual.green_mask),
                component_to_u8(pixel, visual.red_mask),
                u8::MAX,
            ]);
        }
    }
    Ok(destination)
}

fn read_pixel(bytes: &[u8], byte_order: ImageOrder) -> u32 {
    if byte_order == ImageOrder::LSB_FIRST {
        bytes
            .iter()
            .enumerate()
            .fold(0_u32, |value, (index, byte)| {
                value | (u32::from(*byte) << (index * 8))
            })
    } else {
        bytes
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte))
    }
}

fn component_to_u8(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let maximum = mask >> shift;
    let value = (pixel & mask) >> shift;
    u8::try_from((u64::from(value) * 255 + u64::from(maximum) / 2) / u64::from(maximum))
        .unwrap_or(u8::MAX)
}

fn valid_color_masks(visual: &Visualtype) -> bool {
    let masks = [visual.red_mask, visual.green_mask, visual.blue_mask];
    masks.iter().all(|mask| {
        if *mask == 0 {
            return false;
        }
        let shifted = mask >> mask.trailing_zeros();
        shifted & shifted.saturating_add(1) == 0
    }) && visual.red_mask & visual.green_mask == 0
        && visual.red_mask & visual.blue_mask == 0
        && visual.green_mask & visual.blue_mask == 0
}

fn x11_failure(operation: &'static str, error: impl std::fmt::Display) -> CaptureError {
    CaptureError::BackendFailure {
        backend: CaptureBackend::UbuntuX11GetImage,
        operation,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb888_visual() -> Visualtype {
        Visualtype {
            visual_id: 1,
            class: VisualClass::TRUE_COLOR,
            bits_per_rgb_value: 8,
            colormap_entries: 256,
            red_mask: 0x00ff_0000,
            green_mask: 0x0000_ff00,
            blue_mask: 0x0000_00ff,
        }
    }

    #[test]
    fn little_endian_xrgb_is_normalized_to_bgra() {
        let pixels = convert_to_bgra(
            &[0x33, 0x22, 0x11, 0x00],
            1,
            1,
            32,
            32,
            ImageOrder::LSB_FIRST,
            &rgb888_visual(),
            CaptureLimits::default(),
        )
        .expect("convert XRGB");
        assert_eq!(pixels, [0x33, 0x22, 0x11, 0xff]);
    }

    #[test]
    fn source_rows_may_have_x11_padding() {
        let pixels = convert_to_bgra(
            &[0x33, 0x22, 0x11, 0x00],
            1,
            1,
            24,
            32,
            ImageOrder::LSB_FIRST,
            &rgb888_visual(),
            CaptureLimits::default(),
        )
        .expect("convert padded BGR");
        assert_eq!(pixels, [0x33, 0x22, 0x11, 0xff]);
    }

    #[test]
    fn unsupported_pixel_depth_is_explicit() {
        let error = convert_to_bgra(
            &[0; 8],
            1,
            1,
            8,
            8,
            ImageOrder::LSB_FIRST,
            &rgb888_visual(),
            CaptureLimits::default(),
        )
        .expect_err("8-bit indexed visual must not be guessed");
        assert!(matches!(error, CaptureError::Unsupported { .. }));
    }

    #[test]
    fn overlapping_color_masks_are_rejected() {
        let mut visual = rgb888_visual();
        visual.green_mask = visual.red_mask;
        assert!(!valid_color_masks(&visual));
    }

    #[test]
    #[ignore = "requires a live Ubuntu X11 desktop"]
    fn live_x11_capture_is_non_empty() {
        let mut capturer = UbuntuX11Capturer::default();
        capturer.start().expect("connect to X11");
        let monitor = capturer
            .monitors()
            .expect("enumerate X11 monitors")
            .into_iter()
            .next()
            .expect("at least one monitor");
        let frame = capturer
            .capture_frame(monitor.monitor_id)
            .expect("capture X11 frame");
        assert!(!frame.bytes().is_empty());
        assert!(frame.bytes().iter().any(|byte| *byte != 0));
        capturer.stop().expect("release X11 connection");
    }
}
