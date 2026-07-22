use crate::input::{InputBackend, InputManager};
use remote_capture::ScreenCapturer;
use remote_render::{FrameRenderer, RenderSurface};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStartReport {
    pub capture: String,
    pub render: String,
    pub input: String,
    pub ready: bool,
}

pub struct SessionResources<B: InputBackend> {
    capture: Box<dyn ScreenCapturer>,
    render: Box<dyn FrameRenderer>,
    input: InputManager<B>,
    disconnected: bool,
}

impl<B: InputBackend> SessionResources<B> {
    pub fn new(
        capture: Box<dyn ScreenCapturer>,
        render: Box<dyn FrameRenderer>,
        input: InputManager<B>,
    ) -> Self {
        Self {
            capture,
            render,
            input,
            disconnected: false,
        }
    }

    pub fn start(&mut self, surface: RenderSurface) -> ResourceStartReport {
        let capture_backend = self.capture.backend();
        let capture_result = self.capture.start();
        let render_backend = self.render.backend();
        let render_result = self.render.initialize(surface);
        let ready = capture_result.is_ok() && render_result.is_ok();
        ResourceStartReport {
            capture: capture_result
                .map(|()| format!("{capture_backend}: ready"))
                .unwrap_or_else(|error| format!("{capture_backend}: {error}")),
            render: render_result
                .map(|()| format!("{render_backend}: ready"))
                .unwrap_or_else(|error| format!("{render_backend}: {error}")),
            input: self.input.backend_name().into(),
            ready,
        }
    }

    pub fn input_mut(&mut self) -> &mut InputManager<B> {
        &mut self.input
    }

    pub fn disconnect(&mut self) {
        if self.disconnected {
            return;
        }
        let _ = self.input.release_all();
        let _ = self.capture.stop();
        let _ = self.render.shutdown();
        self.disconnected = true;
    }

    pub fn release_input_for_focus_loss(&mut self) {
        let _ = self.input.release_all();
    }

    pub fn is_disconnected(&self) -> bool {
        self.disconnected
    }
}

impl<B: InputBackend> Drop for SessionResources<B> {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputEvent, PhysicalKey, SafeMockInputBackend};
    use remote_capture::SafeMockCapturer;
    use remote_render::SafeMockRenderer;

    fn surface() -> RenderSurface {
        RenderSurface {
            width: 1280,
            height: 720,
            scale_factor_milli: 1_000,
        }
    }

    #[test]
    fn disconnect_releases_all_input_before_resources_are_dropped() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let mut resources = SessionResources::new(
            Box::new(SafeMockCapturer::default()),
            Box::new(SafeMockRenderer::default()),
            InputManager::new(backend),
        );
        assert!(resources.start(surface()).ready);
        resources
            .input_mut()
            .key_down(PhysicalKey(0xE0))
            .expect("control down");

        resources.disconnect();
        assert!(resources.is_disconnected());
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }

    #[test]
    fn dropping_resources_also_releases_all_input() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        {
            let mut resources = SessionResources::new(
                Box::new(SafeMockCapturer::default()),
                Box::new(SafeMockRenderer::default()),
                InputManager::new(backend),
            );
            resources.start(surface());
            resources
                .input_mut()
                .key_down(PhysicalKey(0x04))
                .expect("key down");
        }
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }

    #[test]
    fn focus_loss_releases_all_without_closing_the_session() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let mut resources = SessionResources::new(
            Box::new(SafeMockCapturer::default()),
            Box::new(SafeMockRenderer::default()),
            InputManager::new(backend),
        );
        resources.start(surface());
        resources
            .input_mut()
            .key_down(PhysicalKey(0xE2))
            .expect("alt down");

        resources.release_input_for_focus_loss();
        assert!(!resources.input_mut().has_pressed_inputs());
        assert!(!resources.is_disconnected());
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }
}
