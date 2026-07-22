use crate::{
    DecodedFrame, FrameRenderer, PixelFormat, RenderBackend, RenderError, RenderLimits,
    RenderResult, RenderState, RenderSurface, ValidatedFrame,
};

/// Owns a native graphics surface and all backend resources used to present frames.
///
/// Implementations keep the native window/surface, device, queue, textures,
/// conversion pipeline, and staging buffers outside Slint image controls.
pub trait NativeSurfaceAdapter {
    fn backend(&self) -> RenderBackend;
    fn supports_format(&self, format: PixelFormat) -> bool;
    fn configure(&mut self, surface: RenderSurface) -> RenderResult<()>;
    fn present(&mut self, frame: &ValidatedFrame<'_>) -> RenderResult<()>;
    fn release(&mut self) -> RenderResult<()>;
}

pub struct SurfaceRenderer<A: NativeSurfaceAdapter> {
    adapter: A,
    backend: RenderBackend,
    state: RenderState,
    surface: Option<RenderSurface>,
    limits: RenderLimits,
    frames_rendered: u64,
}

impl<A: NativeSurfaceAdapter> SurfaceRenderer<A> {
    pub fn new(adapter: A) -> Self {
        Self::with_limits(adapter, RenderLimits::default())
    }

    pub fn with_limits(adapter: A, limits: RenderLimits) -> Self {
        let backend = adapter.backend();
        Self {
            adapter,
            backend,
            state: RenderState::Idle,
            surface: None,
            limits,
            frames_rendered: 0,
        }
    }

    pub const fn surface(&self) -> Option<RenderSurface> {
        self.surface
    }

    pub const fn frames_rendered(&self) -> u64 {
        self.frames_rendered
    }

    pub const fn limits(&self) -> RenderLimits {
        self.limits
    }

    pub const fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn notify_surface_lost(&mut self) {
        if self.state == RenderState::Ready {
            self.state = RenderState::SurfaceLost;
        }
    }

    fn configure_surface(&mut self, surface: RenderSurface) -> RenderResult<()> {
        self.limits.validate_surface(surface)?;
        match self.adapter.configure(surface) {
            Ok(()) => {
                self.surface = Some(surface);
                self.state = RenderState::Ready;
                Ok(())
            }
            Err(error) => {
                self.state = RenderState::SurfaceLost;
                Err(error)
            }
        }
    }

    fn mark_present_error(&mut self, error: &RenderError) {
        if matches!(
            error,
            RenderError::SurfaceLost
                | RenderError::SurfaceOutdated
                | RenderError::BackendUnavailable
        ) {
            self.state = RenderState::SurfaceLost;
        }
    }
}

impl<A: NativeSurfaceAdapter> FrameRenderer for SurfaceRenderer<A> {
    fn backend(&self) -> RenderBackend {
        self.backend
    }

    fn state(&self) -> RenderState {
        self.state
    }

    fn initialize(&mut self, surface: RenderSurface) -> RenderResult<()> {
        if self.state != RenderState::Idle {
            return Err(RenderError::InvalidState);
        }
        self.configure_surface(surface)
    }

    fn resize(&mut self, surface: RenderSurface) -> RenderResult<()> {
        if !matches!(self.state, RenderState::Ready | RenderState::SurfaceLost) {
            return Err(RenderError::InvalidState);
        }
        self.configure_surface(surface)
    }

    fn render(&mut self, frame: DecodedFrame<'_>) -> RenderResult<()> {
        match self.state {
            RenderState::Ready => {}
            RenderState::SurfaceLost => return Err(RenderError::SurfaceLost),
            RenderState::Idle | RenderState::Shutdown => return Err(RenderError::InvalidState),
        }

        let frame = frame.validate(self.limits)?;
        if !self.adapter.supports_format(frame.pixel_format()) {
            return Err(RenderError::UnsupportedPixelFormat {
                backend: self.backend,
                format: frame.pixel_format(),
            });
        }

        match self.adapter.present(&frame) {
            Ok(()) => {
                self.frames_rendered = self.frames_rendered.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                self.mark_present_error(&error);
                Err(error)
            }
        }
    }

    fn shutdown(&mut self) -> RenderResult<()> {
        if self.state == RenderState::Shutdown {
            return Ok(());
        }
        let result = self.adapter.release();
        self.surface = None;
        self.state = RenderState::Shutdown;
        result
    }
}

impl<A: NativeSurfaceAdapter> Drop for SurfaceRenderer<A> {
    fn drop(&mut self) {
        if self.state != RenderState::Shutdown {
            let _ = self.adapter.release();
            self.surface = None;
            self.state = RenderState::Shutdown;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Debug, Default)]
    struct Calls {
        configurations: Vec<RenderSurface>,
        presentations: usize,
        releases: usize,
        fail_next_present: Option<RenderError>,
    }

    struct RecordingAdapter {
        calls: Rc<RefCell<Calls>>,
        supported_format: PixelFormat,
    }

    impl NativeSurfaceAdapter for RecordingAdapter {
        fn backend(&self) -> RenderBackend {
            RenderBackend::UbuntuVulkan
        }

        fn supports_format(&self, format: PixelFormat) -> bool {
            format == self.supported_format
        }

        fn configure(&mut self, surface: RenderSurface) -> RenderResult<()> {
            self.calls.borrow_mut().configurations.push(surface);
            Ok(())
        }

        fn present(&mut self, _frame: &ValidatedFrame<'_>) -> RenderResult<()> {
            let mut calls = self.calls.borrow_mut();
            if let Some(error) = calls.fail_next_present.take() {
                return Err(error);
            }
            calls.presentations += 1;
            Ok(())
        }

        fn release(&mut self) -> RenderResult<()> {
            self.calls.borrow_mut().releases += 1;
            Ok(())
        }
    }

    fn surface(width: u32, height: u32) -> RenderSurface {
        RenderSurface {
            width,
            height,
            scale_factor_milli: 1_000,
        }
    }

    fn bgra_frame<'a>(bytes: &'a [u8]) -> DecodedFrame<'a> {
        DecodedFrame::packed(2, 2, PixelFormat::Bgra8, 8, bytes)
    }

    fn renderer(calls: Rc<RefCell<Calls>>) -> SurfaceRenderer<RecordingAdapter> {
        SurfaceRenderer::new(RecordingAdapter {
            calls,
            supported_format: PixelFormat::Bgra8,
        })
    }

    #[test]
    fn resize_reconfigures_the_native_surface() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut renderer = renderer(Rc::clone(&calls));
        renderer.initialize(surface(1280, 720)).expect("initialize");
        renderer.resize(surface(1920, 1080)).expect("resize");

        assert_eq!(renderer.surface(), Some(surface(1920, 1080)));
        assert_eq!(calls.borrow().configurations.len(), 2);
    }

    #[test]
    fn surface_loss_requires_reconfigure_before_presenting_again() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut renderer = renderer(Rc::clone(&calls));
        renderer.initialize(surface(1280, 720)).expect("initialize");
        calls.borrow_mut().fail_next_present = Some(RenderError::SurfaceLost);
        let bytes = [1_u8; 16];

        assert_eq!(
            renderer.render(bgra_frame(&bytes)),
            Err(RenderError::SurfaceLost)
        );
        assert_eq!(renderer.state(), RenderState::SurfaceLost);
        assert_eq!(
            renderer.render(bgra_frame(&bytes)),
            Err(RenderError::SurfaceLost)
        );

        renderer
            .resize(surface(1280, 720))
            .expect("recover surface");
        renderer
            .render(bgra_frame(&bytes))
            .expect("render after recovery");
        assert_eq!(renderer.frames_rendered(), 1);
    }

    #[test]
    fn unsupported_format_is_rejected_before_adapter_upload() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut renderer = renderer(Rc::clone(&calls));
        renderer.initialize(surface(1280, 720)).expect("initialize");
        let bytes = [0_u8; 16];

        assert!(matches!(
            renderer.render(DecodedFrame::packed(2, 2, PixelFormat::Rgba8, 8, &bytes)),
            Err(RenderError::UnsupportedPixelFormat { .. })
        ));
        assert_eq!(calls.borrow().presentations, 0);
    }

    #[test]
    fn shutdown_and_drop_release_exactly_once() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        {
            let mut renderer = renderer(Rc::clone(&calls));
            renderer.initialize(surface(1280, 720)).expect("initialize");
            renderer.shutdown().expect("shutdown");
            renderer.shutdown().expect("idempotent shutdown");
        }
        assert_eq!(calls.borrow().releases, 1);
    }

    #[test]
    fn drop_releases_an_active_native_surface() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        {
            let mut renderer = renderer(Rc::clone(&calls));
            renderer.initialize(surface(1280, 720)).expect("initialize");
        }
        assert_eq!(calls.borrow().releases, 1);
    }

    #[test]
    fn invalid_resize_does_not_reach_the_adapter() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut renderer = renderer(Rc::clone(&calls));
        renderer.initialize(surface(1280, 720)).expect("initialize");

        assert!(matches!(
            renderer.resize(surface(0, 720)),
            Err(RenderError::InvalidSurface(_))
        ));
        assert_eq!(calls.borrow().configurations.len(), 1);
        assert_eq!(renderer.state(), RenderState::Ready);
    }
}
