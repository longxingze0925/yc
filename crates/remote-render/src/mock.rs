use crate::{
    DecodedFrame, FrameObservation, FrameRenderer, NativeSurfaceAdapter, PixelFormat,
    RenderBackend, RenderLimits, RenderResult, RenderState, RenderSurface, SurfaceRenderer,
    ValidatedFrame,
};

#[derive(Debug, Default)]
struct SafeMockSurface {
    last_frame: Option<FrameObservation>,
    released: bool,
}

impl NativeSurfaceAdapter for SafeMockSurface {
    fn backend(&self) -> RenderBackend {
        RenderBackend::SafeMock
    }

    fn supports_format(&self, _format: PixelFormat) -> bool {
        true
    }

    fn configure(&mut self, _surface: RenderSurface) -> RenderResult<()> {
        self.released = false;
        Ok(())
    }

    fn present(&mut self, frame: &ValidatedFrame<'_>) -> RenderResult<()> {
        self.last_frame = Some(FrameObservation::from_frame(frame));
        Ok(())
    }

    fn release(&mut self) -> RenderResult<()> {
        self.released = true;
        Ok(())
    }
}

pub struct SafeMockRenderer {
    inner: SurfaceRenderer<SafeMockSurface>,
}

impl Default for SafeMockRenderer {
    fn default() -> Self {
        Self::with_limits(RenderLimits::default())
    }
}

impl SafeMockRenderer {
    pub fn with_limits(limits: RenderLimits) -> Self {
        Self {
            inner: SurfaceRenderer::with_limits(SafeMockSurface::default(), limits),
        }
    }

    pub const fn frames_rendered(&self) -> u64 {
        self.inner.frames_rendered()
    }

    pub const fn surface(&self) -> Option<RenderSurface> {
        self.inner.surface()
    }

    pub const fn last_frame(&self) -> Option<FrameObservation> {
        self.inner.adapter().last_frame
    }

    pub const fn released(&self) -> bool {
        self.inner.adapter().released
    }

    pub fn notify_surface_lost(&mut self) {
        self.inner.notify_surface_lost();
    }
}

impl FrameRenderer for SafeMockRenderer {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RenderError;

    fn surface(width: u32, height: u32) -> RenderSurface {
        RenderSurface {
            width,
            height,
            scale_factor_milli: 1_000,
        }
    }

    #[test]
    fn safe_mock_observes_pixel_changes() {
        let mut renderer = SafeMockRenderer::default();
        renderer
            .initialize(surface(1280, 720))
            .expect("initialize mock");
        let first = [0_u8; 16];
        renderer
            .render(DecodedFrame::packed(2, 2, PixelFormat::Rgba8, 8, &first))
            .expect("render first frame");
        let first_fingerprint = renderer.last_frame().expect("first frame").fingerprint;
        let second = [1_u8; 16];
        renderer
            .render(DecodedFrame::packed(2, 2, PixelFormat::Rgba8, 8, &second))
            .expect("render second frame");

        assert_eq!(renderer.frames_rendered(), 2);
        assert_ne!(
            first_fingerprint,
            renderer.last_frame().expect("second frame").fingerprint
        );
    }

    #[test]
    fn safe_mock_recovers_surface_loss_via_resize() {
        let mut renderer = SafeMockRenderer::default();
        renderer
            .initialize(surface(1280, 720))
            .expect("initialize mock");
        renderer.notify_surface_lost();
        let bytes = [0_u8; 16];
        assert_eq!(
            renderer.render(DecodedFrame::packed(2, 2, PixelFormat::Bgra8, 8, &bytes)),
            Err(RenderError::SurfaceLost)
        );
        renderer
            .resize(surface(1920, 1080))
            .expect("recover surface");
        assert_eq!(renderer.state(), RenderState::Ready);
    }
}
