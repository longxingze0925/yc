use std::error::Error;
use std::fmt;

mod frame;
mod mock;
mod surface;

pub mod desktop;

pub use frame::{
    DecodedFrame, FrameObservation, FramePlane, FramePlanes, PixelFormat, PlaneKind, RenderLimits,
    ValidatedFrame, ValidatedPlane, MAX_RENDER_FRAME_BYTES, MAX_RENDER_HEIGHT,
    MAX_RENDER_SCALE_FACTOR_MILLI, MAX_RENDER_WIDTH,
};
pub use mock::SafeMockRenderer;
pub use surface::{NativeSurfaceAdapter, SurfaceRenderer};

#[cfg(target_os = "windows")]
pub use desktop::{D3d11SurfaceAdapter, WindowsD3d11Renderer};
#[cfg(target_os = "linux")]
pub use desktop::{UbuntuWgpuRenderer, WgpuSurfaceAdapter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderBackend {
    WindowsD3d11,
    UbuntuOpenGl,
    UbuntuVulkan,
    IosMetal,
    SafeMock,
    UnsupportedPlatform,
}

impl fmt::Display for RenderBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::WindowsD3d11 => "Windows D3D11 / DirectComposition",
            Self::UbuntuOpenGl => "Ubuntu OpenGL via wgpu",
            Self::UbuntuVulkan => "Ubuntu Vulkan via wgpu",
            Self::IosMetal => "iOS Metal",
            Self::SafeMock => "safe mock renderer",
            Self::UnsupportedPlatform => "unsupported platform renderer",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderState {
    Idle,
    Ready,
    SurfaceLost,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderSurface {
    pub width: u32,
    pub height: u32,
    pub scale_factor_milli: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    BackendUnavailable,
    SurfaceLost,
    SurfaceOutdated,
    SurfaceTimeout,
    OutOfMemory,
    InvalidFrame,
    InvalidFrameLayout(&'static str),
    InvalidSurface(&'static str),
    InvalidLimits,
    InvalidState,
    FrameTooLarge {
        width: u32,
        height: u32,
        bytes: usize,
        max_bytes: usize,
    },
    UnsupportedPixelFormat {
        backend: RenderBackend,
        format: PixelFormat,
    },
    BackendFailure {
        backend: RenderBackend,
        operation: &'static str,
        reason: String,
    },
    Unsupported {
        backend: RenderBackend,
        reason: &'static str,
    },
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable => formatter.write_str("render backend unavailable"),
            Self::SurfaceLost => formatter.write_str("render surface lost"),
            Self::SurfaceOutdated => formatter.write_str("render surface is outdated"),
            Self::SurfaceTimeout => formatter.write_str("render surface presentation timed out"),
            Self::OutOfMemory => formatter.write_str("render backend is out of memory"),
            Self::InvalidFrame => formatter.write_str("decoded frame is invalid"),
            Self::InvalidFrameLayout(reason) => {
                write!(formatter, "decoded frame layout is invalid: {reason}")
            }
            Self::InvalidSurface(reason) => write!(formatter, "render surface is invalid: {reason}"),
            Self::InvalidLimits => formatter.write_str("render limits are invalid"),
            Self::InvalidState => formatter.write_str("renderer is in an invalid state"),
            Self::FrameTooLarge {
                width,
                height,
                bytes,
                max_bytes,
            } => write!(
                formatter,
                "decoded frame {width}x{height} ({bytes} bytes) exceeds the configured {max_bytes}-byte limit"
            ),
            Self::UnsupportedPixelFormat { backend, format } => {
                write!(formatter, "{backend} does not support {format} frames")
            }
            Self::BackendFailure {
                backend,
                operation,
                reason,
            } => write!(formatter, "{backend} failed during {operation}: {reason}"),
            Self::Unsupported { backend, reason } => {
                write!(formatter, "{backend} is unsupported: {reason}")
            }
        }
    }
}

impl Error for RenderError {}

pub type RenderResult<T> = Result<T, RenderError>;

pub trait FrameRenderer {
    fn backend(&self) -> RenderBackend;
    fn state(&self) -> RenderState;
    fn initialize(&mut self, surface: RenderSurface) -> RenderResult<()>;
    fn resize(&mut self, surface: RenderSurface) -> RenderResult<()>;
    fn render(&mut self, frame: DecodedFrame<'_>) -> RenderResult<()>;
    fn shutdown(&mut self) -> RenderResult<()>;
}

pub struct RenderLease<R: FrameRenderer> {
    renderer: Option<R>,
}

impl<R: FrameRenderer> RenderLease<R> {
    pub fn initialize(mut renderer: R, surface: RenderSurface) -> RenderResult<Self> {
        renderer.initialize(surface)?;
        Ok(Self {
            renderer: Some(renderer),
        })
    }

    pub fn renderer(&self) -> &R {
        self.renderer.as_ref().expect("render lease is active")
    }

    pub fn renderer_mut(&mut self) -> &mut R {
        self.renderer.as_mut().expect("render lease is active")
    }

    pub fn shutdown(mut self) -> RenderResult<R> {
        let mut renderer = self.renderer.take().expect("render lease is active");
        renderer.shutdown()?;
        Ok(renderer)
    }
}

impl<R: FrameRenderer> Drop for RenderLease<R> {
    fn drop(&mut self) {
        if let Some(renderer) = self.renderer.as_mut() {
            let _ = renderer.shutdown();
        }
    }
}

#[derive(Debug)]
pub struct UnsupportedRenderer {
    backend: RenderBackend,
    reason: &'static str,
}

impl UnsupportedRenderer {
    pub const fn new(backend: RenderBackend, reason: &'static str) -> Self {
        Self { backend, reason }
    }

    fn error(&self) -> RenderError {
        RenderError::Unsupported {
            backend: self.backend,
            reason: self.reason,
        }
    }
}

impl FrameRenderer for UnsupportedRenderer {
    fn backend(&self) -> RenderBackend {
        self.backend
    }

    fn state(&self) -> RenderState {
        RenderState::Shutdown
    }

    fn initialize(&mut self, _surface: RenderSurface) -> RenderResult<()> {
        Err(self.error())
    }

    fn resize(&mut self, _surface: RenderSurface) -> RenderResult<()> {
        Err(self.error())
    }

    fn render(&mut self, _frame: DecodedFrame<'_>) -> RenderResult<()> {
        Err(self.error())
    }

    fn shutdown(&mut self) -> RenderResult<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn platform_renderer() -> Box<dyn FrameRenderer> {
    Box::new(UnsupportedRenderer::new(
        RenderBackend::WindowsD3d11,
        "a D3D11 surface adapter must be created from the desktop native window",
    ))
}

#[cfg(target_os = "linux")]
pub fn platform_renderer() -> Box<dyn FrameRenderer> {
    Box::new(UnsupportedRenderer::new(
        RenderBackend::UbuntuVulkan,
        "a wgpu surface adapter must be created from the desktop native window",
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn platform_renderer() -> Box<dyn FrameRenderer> {
    Box::new(UnsupportedRenderer::new(
        RenderBackend::UnsupportedPlatform,
        "desktop rendering is only planned for Windows and Ubuntu",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface() -> RenderSurface {
        RenderSurface {
            width: 1280,
            height: 720,
            scale_factor_milli: 1_000,
        }
    }

    #[test]
    fn render_lease_shuts_down_the_backend() {
        let renderer = SafeMockRenderer::default();
        let lease = RenderLease::initialize(renderer, surface()).expect("initialize lease");
        let renderer = lease.shutdown().expect("shutdown lease");
        assert_eq!(renderer.state(), RenderState::Shutdown);
        assert!(renderer.released());
    }

    #[test]
    fn unsupported_backend_never_reports_success() {
        let mut renderer = UnsupportedRenderer::new(RenderBackend::UbuntuOpenGl, "test boundary");
        assert!(matches!(
            renderer.initialize(surface()),
            Err(RenderError::Unsupported { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unbound_linux_platform_renderer_never_claims_native_success() {
        let mut renderer = platform_renderer();
        assert_eq!(renderer.backend(), RenderBackend::UbuntuVulkan);
        assert!(matches!(
            renderer.initialize(surface()),
            Err(RenderError::Unsupported { .. })
        ));
    }
}
