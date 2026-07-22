use crate::{
    DecodedFrame, FrameRenderer, NativeSurfaceAdapter, RenderBackend, RenderError, RenderLimits,
    RenderResult, RenderState, RenderSurface, SurfaceRenderer,
};

/// Windows-only adapter contract for D3D11 and DirectComposition resources.
pub trait D3d11SurfaceAdapter: NativeSurfaceAdapter {}

pub struct WindowsD3d11Renderer<A: D3d11SurfaceAdapter> {
    inner: SurfaceRenderer<A>,
}

impl<A: D3d11SurfaceAdapter> WindowsD3d11Renderer<A> {
    pub fn try_new(adapter: A) -> RenderResult<Self> {
        Self::with_limits(adapter, RenderLimits::default())
    }

    pub fn with_limits(adapter: A, limits: RenderLimits) -> RenderResult<Self> {
        let backend = adapter.backend();
        if backend != RenderBackend::WindowsD3d11 {
            return Err(RenderError::Unsupported {
                backend,
                reason: "Windows native rendering requires the D3D11 backend",
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

impl<A: D3d11SurfaceAdapter> FrameRenderer for WindowsD3d11Renderer<A> {
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
