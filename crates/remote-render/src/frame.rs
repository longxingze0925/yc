use std::fmt;

use crate::{RenderError, RenderResult, RenderSurface};

pub const MAX_RENDER_WIDTH: u32 = 16_384;
pub const MAX_RENDER_HEIGHT: u32 = 16_384;
pub const MAX_RENDER_FRAME_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_RENDER_SCALE_FACTOR_MILLI: u32 = 16_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PixelFormat {
    Bgra8 = 1,
    Rgba8 = 2,
    Nv12 = 3,
    I420 = 4,
}

impl fmt::Display for PixelFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Bgra8 => "BGRA8",
            Self::Rgba8 => "RGBA8",
            Self::Nv12 => "NV12",
            Self::I420 => "I420",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlaneKind {
    Packed = 1,
    Luma = 2,
    ChromaUv = 3,
    ChromaU = 4,
    ChromaV = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePlane<'a> {
    stride: u32,
    bytes: &'a [u8],
}

impl<'a> FramePlane<'a> {
    pub const fn new(stride: u32, bytes: &'a [u8]) -> Self {
        Self { stride, bytes }
    }

    pub const fn stride(self) -> u32 {
        self.stride
    }

    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramePlanes<'a> {
    Packed(FramePlane<'a>),
    Nv12 {
        y: FramePlane<'a>,
        uv: FramePlane<'a>,
    },
    I420 {
        y: FramePlane<'a>,
        u: FramePlane<'a>,
        v: FramePlane<'a>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    planes: FramePlanes<'a>,
}

impl<'a> DecodedFrame<'a> {
    pub const fn new(
        width: u32,
        height: u32,
        pixel_format: PixelFormat,
        planes: FramePlanes<'a>,
    ) -> Self {
        Self {
            width,
            height,
            pixel_format,
            planes,
        }
    }

    pub const fn packed(
        width: u32,
        height: u32,
        pixel_format: PixelFormat,
        stride: u32,
        bytes: &'a [u8],
    ) -> Self {
        Self::new(
            width,
            height,
            pixel_format,
            FramePlanes::Packed(FramePlane::new(stride, bytes)),
        )
    }

    pub const fn nv12(
        width: u32,
        height: u32,
        y_stride: u32,
        y: &'a [u8],
        uv_stride: u32,
        uv: &'a [u8],
    ) -> Self {
        Self::new(
            width,
            height,
            PixelFormat::Nv12,
            FramePlanes::Nv12 {
                y: FramePlane::new(y_stride, y),
                uv: FramePlane::new(uv_stride, uv),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn i420(
        width: u32,
        height: u32,
        y_stride: u32,
        y: &'a [u8],
        u_stride: u32,
        u: &'a [u8],
        v_stride: u32,
        v: &'a [u8],
    ) -> Self {
        Self::new(
            width,
            height,
            PixelFormat::I420,
            FramePlanes::I420 {
                y: FramePlane::new(y_stride, y),
                u: FramePlane::new(u_stride, u),
                v: FramePlane::new(v_stride, v),
            },
        )
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }

    pub const fn pixel_format(self) -> PixelFormat {
        self.pixel_format
    }

    pub const fn planes(self) -> FramePlanes<'a> {
        self.planes
    }

    pub fn validate(self, limits: RenderLimits) -> RenderResult<ValidatedFrame<'a>> {
        limits.validate_frame(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPlane<'a> {
    kind: PlaneKind,
    width: u32,
    height: u32,
    stride: u32,
    bytes: &'a [u8],
}

impl<'a> ValidatedPlane<'a> {
    pub const fn kind(self) -> PlaneKind {
        self.kind
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }

    pub const fn stride(self) -> u32 {
        self.stride
    }

    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedFrame<'a> {
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    planes: [Option<ValidatedPlane<'a>>; 3],
    plane_count: usize,
    total_bytes: usize,
}

impl<'a> ValidatedFrame<'a> {
    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn height(&self) -> u32 {
        self.height
    }

    pub const fn pixel_format(&self) -> PixelFormat {
        self.pixel_format
    }

    pub const fn plane_count(&self) -> usize {
        self.plane_count
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn plane(&self, index: usize) -> Option<ValidatedPlane<'a>> {
        self.planes.get(index).copied().flatten()
    }

    pub fn planes(&self) -> impl Iterator<Item = ValidatedPlane<'a>> + '_ {
        self.planes[..self.plane_count]
            .iter()
            .filter_map(|plane| *plane)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameObservation {
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub plane_count: usize,
    pub total_bytes: usize,
    /// Deterministic FNV-1a fingerprint for tests and diagnostics, not for security decisions.
    pub fingerprint: u64,
}

impl FrameObservation {
    pub fn from_frame(frame: &ValidatedFrame<'_>) -> Self {
        let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;
        hash_bytes(&mut fingerprint, &frame.width.to_le_bytes());
        hash_bytes(&mut fingerprint, &frame.height.to_le_bytes());
        hash_bytes(&mut fingerprint, &[frame.pixel_format as u8]);

        for plane in frame.planes() {
            hash_bytes(&mut fingerprint, &[plane.kind as u8]);
            hash_bytes(&mut fingerprint, &plane.width.to_le_bytes());
            hash_bytes(&mut fingerprint, &plane.height.to_le_bytes());
            hash_bytes(&mut fingerprint, &plane.stride.to_le_bytes());
            hash_bytes(&mut fingerprint, plane.bytes);
        }

        Self {
            width: frame.width,
            height: frame.height,
            pixel_format: frame.pixel_format,
            plane_count: frame.plane_count,
            total_bytes: frame.total_bytes,
            fingerprint,
        }
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderLimits {
    max_width: u32,
    max_height: u32,
    max_frame_bytes: usize,
}

impl RenderLimits {
    pub const DEFAULT: Self = Self {
        max_width: MAX_RENDER_WIDTH,
        max_height: MAX_RENDER_HEIGHT,
        max_frame_bytes: MAX_RENDER_FRAME_BYTES,
    };

    pub fn try_new(max_width: u32, max_height: u32, max_frame_bytes: usize) -> RenderResult<Self> {
        if max_width == 0
            || max_height == 0
            || max_frame_bytes == 0
            || max_width > MAX_RENDER_WIDTH
            || max_height > MAX_RENDER_HEIGHT
            || max_frame_bytes > MAX_RENDER_FRAME_BYTES
        {
            return Err(RenderError::InvalidLimits);
        }
        Ok(Self {
            max_width,
            max_height,
            max_frame_bytes,
        })
    }

    pub const fn max_width(self) -> u32 {
        self.max_width
    }

    pub const fn max_height(self) -> u32 {
        self.max_height
    }

    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    pub(crate) fn validate_surface(self, surface: RenderSurface) -> RenderResult<()> {
        if surface.width == 0 || surface.height == 0 {
            return Err(RenderError::InvalidSurface(
                "surface width and height must be non-zero",
            ));
        }
        if surface.width > self.max_width || surface.height > self.max_height {
            return Err(RenderError::InvalidSurface(
                "surface dimensions exceed the configured limits",
            ));
        }
        if surface.scale_factor_milli == 0
            || surface.scale_factor_milli > MAX_RENDER_SCALE_FACTOR_MILLI
        {
            return Err(RenderError::InvalidSurface(
                "surface scale factor is outside the supported range",
            ));
        }
        Ok(())
    }

    fn validate_frame<'a>(self, frame: DecodedFrame<'a>) -> RenderResult<ValidatedFrame<'a>> {
        self.validate_dimensions(frame.width, frame.height)?;

        let mut planes = [None; 3];
        let plane_count;
        match (frame.pixel_format, frame.planes) {
            (PixelFormat::Bgra8 | PixelFormat::Rgba8, FramePlanes::Packed(packed)) => {
                let row_bytes =
                    frame
                        .width
                        .checked_mul(4)
                        .ok_or(RenderError::InvalidFrameLayout(
                            "packed row size overflowed",
                        ))?;
                planes[0] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    packed,
                    PlaneSpec {
                        kind: PlaneKind::Packed,
                        width: frame.width,
                        height: frame.height,
                        minimum_stride: row_bytes,
                        stride_alignment: 4,
                    },
                )?);
                plane_count = 1;
            }
            (PixelFormat::Nv12, FramePlanes::Nv12 { y, uv }) => {
                validate_even_dimensions(frame.width, frame.height, PixelFormat::Nv12)?;
                planes[0] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    y,
                    PlaneSpec {
                        kind: PlaneKind::Luma,
                        width: frame.width,
                        height: frame.height,
                        minimum_stride: frame.width,
                        stride_alignment: 1,
                    },
                )?);
                planes[1] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    uv,
                    PlaneSpec {
                        kind: PlaneKind::ChromaUv,
                        width: frame.width / 2,
                        height: frame.height / 2,
                        minimum_stride: frame.width,
                        stride_alignment: 2,
                    },
                )?);
                plane_count = 2;
            }
            (PixelFormat::I420, FramePlanes::I420 { y, u, v }) => {
                validate_even_dimensions(frame.width, frame.height, PixelFormat::I420)?;
                let chroma_width = frame.width / 2;
                let chroma_height = frame.height / 2;
                planes[0] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    y,
                    PlaneSpec {
                        kind: PlaneKind::Luma,
                        width: frame.width,
                        height: frame.height,
                        minimum_stride: frame.width,
                        stride_alignment: 1,
                    },
                )?);
                planes[1] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    u,
                    PlaneSpec {
                        kind: PlaneKind::ChromaU,
                        width: chroma_width,
                        height: chroma_height,
                        minimum_stride: chroma_width,
                        stride_alignment: 1,
                    },
                )?);
                planes[2] = Some(self.validate_plane(
                    frame.width,
                    frame.height,
                    v,
                    PlaneSpec {
                        kind: PlaneKind::ChromaV,
                        width: chroma_width,
                        height: chroma_height,
                        minimum_stride: chroma_width,
                        stride_alignment: 1,
                    },
                )?);
                plane_count = 3;
            }
            _ => {
                return Err(RenderError::InvalidFrameLayout(
                    "pixel format does not match the supplied plane layout",
                ));
            }
        }

        let total_bytes = planes[..plane_count]
            .iter()
            .flatten()
            .try_fold(0_usize, |total, plane| total.checked_add(plane.bytes.len()))
            .ok_or(RenderError::InvalidFrameLayout(
                "total pixel layout size overflowed",
            ))?;
        if total_bytes > self.max_frame_bytes {
            return Err(RenderError::FrameTooLarge {
                width: frame.width,
                height: frame.height,
                bytes: total_bytes,
                max_bytes: self.max_frame_bytes,
            });
        }

        Ok(ValidatedFrame {
            width: frame.width,
            height: frame.height,
            pixel_format: frame.pixel_format,
            planes,
            plane_count,
            total_bytes,
        })
    }

    fn validate_dimensions(self, width: u32, height: u32) -> RenderResult<()> {
        if width == 0 || height == 0 {
            return Err(RenderError::InvalidFrameLayout(
                "frame width and height must be non-zero",
            ));
        }
        if width > self.max_width || height > self.max_height {
            return Err(RenderError::FrameTooLarge {
                width,
                height,
                bytes: 0,
                max_bytes: self.max_frame_bytes,
            });
        }
        Ok(())
    }

    fn validate_plane<'a>(
        self,
        frame_width: u32,
        frame_height: u32,
        plane: FramePlane<'a>,
        spec: PlaneSpec,
    ) -> RenderResult<ValidatedPlane<'a>> {
        if plane.stride < spec.minimum_stride {
            return Err(RenderError::InvalidFrameLayout(
                "plane stride is smaller than its pixel row",
            ));
        }
        if !plane.stride.is_multiple_of(spec.stride_alignment) {
            return Err(RenderError::InvalidFrameLayout(
                "plane stride is not aligned for its pixel format",
            ));
        }

        let expected_bytes = usize::try_from(plane.stride)
            .ok()
            .and_then(|stride| {
                usize::try_from(spec.height)
                    .ok()
                    .and_then(|height| stride.checked_mul(height))
            })
            .ok_or(RenderError::InvalidFrameLayout(
                "plane layout size overflowed",
            ))?;
        if expected_bytes > self.max_frame_bytes {
            return Err(RenderError::FrameTooLarge {
                width: frame_width,
                height: frame_height,
                bytes: expected_bytes,
                max_bytes: self.max_frame_bytes,
            });
        }
        if plane.bytes.len() != expected_bytes {
            return Err(RenderError::InvalidFrameLayout(
                "plane byte length must exactly match stride and plane height",
            ));
        }

        Ok(ValidatedPlane {
            kind: spec.kind,
            width: spec.width,
            height: spec.height,
            stride: plane.stride,
            bytes: plane.bytes,
        })
    }
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy)]
struct PlaneSpec {
    kind: PlaneKind,
    width: u32,
    height: u32,
    minimum_stride: u32,
    stride_alignment: u32,
}

fn validate_even_dimensions(width: u32, height: u32, format: PixelFormat) -> RenderResult<()> {
    if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(RenderError::InvalidFrameLayout(match format {
            PixelFormat::Nv12 => "NV12 frame width and height must be even",
            _ => "I420 frame width and height must be even",
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_frame_accepts_aligned_padding_and_observes_pixels() {
        let bytes = [1_u8; 24];
        let frame = DecodedFrame::packed(2, 2, PixelFormat::Bgra8, 12, &bytes)
            .validate(RenderLimits::default())
            .expect("valid padded BGRA frame");

        assert_eq!(frame.total_bytes(), 24);
        assert_eq!(frame.plane_count(), 1);
        assert_eq!(frame.plane(0).expect("packed plane").stride(), 12);
        let observation = FrameObservation::from_frame(&frame);
        assert_ne!(observation.fingerprint, 0);
    }

    #[test]
    fn packed_frame_rejects_bad_stride_and_length() {
        let short_stride = [0_u8; 14];
        assert!(matches!(
            DecodedFrame::packed(2, 2, PixelFormat::Rgba8, 7, &short_stride)
                .validate(RenderLimits::default()),
            Err(RenderError::InvalidFrameLayout(_))
        ));

        let wrong_length = [0_u8; 15];
        assert!(matches!(
            DecodedFrame::packed(2, 2, PixelFormat::Rgba8, 8, &wrong_length)
                .validate(RenderLimits::default()),
            Err(RenderError::InvalidFrameLayout(_))
        ));
    }

    #[test]
    fn format_must_match_plane_layout() {
        let bytes = [0_u8; 16];
        let frame = DecodedFrame::new(
            2,
            2,
            PixelFormat::Nv12,
            FramePlanes::Packed(FramePlane::new(8, &bytes)),
        );
        assert!(matches!(
            frame.validate(RenderLimits::default()),
            Err(RenderError::InvalidFrameLayout(_))
        ));
    }

    #[test]
    fn nv12_and_i420_validate_each_plane() {
        let y = [16_u8; 8];
        let uv = [128_u8; 4];
        let nv12 = DecodedFrame::nv12(4, 2, 4, &y, 4, &uv)
            .validate(RenderLimits::default())
            .expect("valid NV12");
        assert_eq!(nv12.plane_count(), 2);
        assert_eq!(nv12.plane(1).expect("UV plane").kind(), PlaneKind::ChromaUv);

        let u = [128_u8; 2];
        let v = [128_u8; 2];
        let i420 = DecodedFrame::i420(4, 2, 4, &y, 2, &u, 2, &v)
            .validate(RenderLimits::default())
            .expect("valid I420");
        assert_eq!(i420.plane_count(), 3);
        assert_eq!(i420.total_bytes(), 12);
    }

    #[test]
    fn subsampled_formats_require_even_dimensions() {
        let y = [0_u8; 6];
        let uv = [0_u8; 3];
        assert!(matches!(
            DecodedFrame::nv12(3, 2, 3, &y, 3, &uv).validate(RenderLimits::default()),
            Err(RenderError::InvalidFrameLayout(_))
        ));
    }

    #[test]
    fn configured_frame_byte_limit_is_enforced() {
        let limits = RenderLimits::try_new(16, 16, 15).expect("small test limits");
        let bytes = [0_u8; 16];
        assert!(matches!(
            DecodedFrame::packed(2, 2, PixelFormat::Bgra8, 8, &bytes).validate(limits),
            Err(RenderError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn limits_cannot_exceed_hard_ceiling() {
        assert_eq!(
            RenderLimits::try_new(
                MAX_RENDER_WIDTH + 1,
                MAX_RENDER_HEIGHT,
                MAX_RENDER_FRAME_BYTES
            ),
            Err(RenderError::InvalidLimits)
        );
    }
}
