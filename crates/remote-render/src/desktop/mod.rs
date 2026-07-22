#[cfg(target_os = "windows")]
mod d3d11;
#[cfg(target_os = "linux")]
mod wgpu;

#[cfg(target_os = "windows")]
pub use d3d11::{D3d11SurfaceAdapter, WindowsD3d11Renderer};
#[cfg(target_os = "linux")]
pub use wgpu::{UbuntuWgpuRenderer, WgpuSurfaceAdapter};
