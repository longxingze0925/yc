import MetalKit
import SwiftUI

public struct MetalRemoteView: UIViewRepresentable {
    private let renderer: MetalRemoteRenderer
    private let zoomScale: CGFloat

    public init(renderer: MetalRemoteRenderer, zoomScale: CGFloat = 1) {
        self.renderer = renderer
        self.zoomScale = zoomScale
    }

    public func makeUIView(context: Context) -> MTKView {
        let view = MTKView(frame: .zero, device: renderer.device)
        renderer.setZoomScale(zoomScale)
        renderer.attach(to: view)
        return view
    }

    public func updateUIView(_ uiView: MTKView, context: Context) {
        renderer.setZoomScale(zoomScale)
    }

    public static func dismantleUIView(_ uiView: MTKView, coordinator: ()) {
        guard let renderer = uiView.delegate as? MetalRemoteRenderer else { return }
        renderer.detach(from: uiView)
    }
}
