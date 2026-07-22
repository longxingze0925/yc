use crate::{
    DecodedFrame, FrameRenderer, NativeSurfaceAdapter, RenderBackend, RenderError, RenderLimits,
    RenderResult, RenderState, RenderSurface, SurfaceRenderer,
};

/// Implemented by the desktop window layer with `wgpu`.
///
/// The adapter owns the native `wgpu::Surface`, device, queue, upload textures,
/// YUV pipeline, and surface-error mapping. Pixels never pass through Slint controls.
pub trait WgpuSurfaceAdapter: NativeSurfaceAdapter {}

pub struct UbuntuWgpuRenderer<A: WgpuSurfaceAdapter> {
    inner: SurfaceRenderer<A>,
}

impl<A: WgpuSurfaceAdapter> UbuntuWgpuRenderer<A> {
    pub fn try_new(adapter: A) -> RenderResult<Self> {
        Self::with_limits(adapter, RenderLimits::default())
    }

    pub fn with_limits(adapter: A, limits: RenderLimits) -> RenderResult<Self> {
        let backend = adapter.backend();
        if !matches!(
            backend,
            RenderBackend::UbuntuVulkan | RenderBackend::UbuntuOpenGl
        ) {
            return Err(RenderError::Unsupported {
                backend,
                reason: "Ubuntu wgpu must select the Vulkan or OpenGL backend",
            });
        }
        Ok(Self {
            inner: SurfaceRenderer::with_limits(adapter, limits),
        })
    }

    pub const fn surface(&self) -> Option<RenderSurface> {
        self.inner.surface()
    }

    pub const fn frames_rendered(&self) -> u64 {
        self.inner.frames_rendered()
    }

    pub const fn adapter(&self) -> &A {
        self.inner.adapter()
    }

    pub fn notify_surface_lost(&mut self) {
        self.inner.notify_surface_lost();
    }
}

impl<A: WgpuSurfaceAdapter> FrameRenderer for UbuntuWgpuRenderer<A> {
    fn backend(&self) -> RenderBackend {
        self.inner.backend()
    }

    fn state(&self) -> RenderState {
        self.inner.state()
    }

    fn initialize(&mut self, surface: RenderSurface) -> RenderResult<()> {
        self.inner.initialize(surface)
    }

    fn resize(&mut self, surface: RenderSurface) -> RenderResult<()> {
        self.inner.resize(surface)
    }

    fn render(&mut self, frame: DecodedFrame<'_>) -> RenderResult<()> {
        self.inner.render(frame)
    }

    fn shutdown(&mut self) -> RenderResult<()> {
        self.inner.shutdown()
    }
}
