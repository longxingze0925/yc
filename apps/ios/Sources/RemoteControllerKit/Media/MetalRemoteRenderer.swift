import CoreVideo
import Foundation
import Metal
import MetalKit
import simd

public enum MetalRemoteRendererError: LocalizedError {
    case metalUnavailable
    case commandQueueUnavailable
    case shaderLibraryUnavailable
    case shaderFunctionUnavailable
    case pipelineCreationFailed(String)
    case textureCacheCreationFailed(CVReturn)

    public var errorDescription: String? {
        switch self {
        case .metalUnavailable:
            return "当前设备不支持 Metal"
        case .commandQueueUnavailable:
            return "Metal 命令队列创建失败"
        case .shaderLibraryUnavailable:
            return "远控渲染着色器未包含在 App 资源中"
        case .shaderFunctionUnavailable:
            return "远控渲染着色器函数不完整"
        case let .pipelineCreationFailed(message):
            return "Metal 渲染管线创建失败：\(message)"
        case let .textureCacheCreationFailed(status):
            return "Metal 视频纹理缓存创建失败（\(status)）"
        }
    }
}

public final class MetalRemoteRenderer: NSObject, MTKViewDelegate, @unchecked Sendable {
    private struct Vertex {
        var position: SIMD2<Float>
        var textureCoordinate: SIMD2<Float>
    }

    public let device: MTLDevice

    private let commandQueue: MTLCommandQueue
    private let pipeline: MTLRenderPipelineState
    private let textureCache: CVMetalTextureCache
    private let frameLock = NSLock()
    private var latestFrame: CVPixelBuffer?
    private var viewportZoomScale: CGFloat = 1
    private weak var view: MTKView?

    public init(resourceBundle: Bundle? = nil) throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw MetalRemoteRendererError.metalUnavailable
        }
        guard let commandQueue = device.makeCommandQueue() else {
            throw MetalRemoteRendererError.commandQueueUnavailable
        }
        guard let library = try? device.makeDefaultLibrary(bundle: resourceBundle ?? .module) else {
            throw MetalRemoteRendererError.shaderLibraryUnavailable
        }
        guard let vertex = library.makeFunction(name: "remoteVertex"),
              let fragment = library.makeFunction(name: "remoteNV12Fragment") else {
            throw MetalRemoteRendererError.shaderFunctionUnavailable
        }

        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.label = "Remote NV12 Pipeline"
        descriptor.vertexFunction = vertex
        descriptor.fragmentFunction = fragment
        descriptor.colorAttachments[0].pixelFormat = .bgra8Unorm

        do {
            pipeline = try device.makeRenderPipelineState(descriptor: descriptor)
        } catch {
            throw MetalRemoteRendererError.pipelineCreationFailed(error.localizedDescription)
        }

        var cache: CVMetalTextureCache?
        let cacheStatus = CVMetalTextureCacheCreate(
            kCFAllocatorDefault,
            nil,
            device,
            nil,
            &cache
        )
        guard cacheStatus == kCVReturnSuccess, let cache else {
            throw MetalRemoteRendererError.textureCacheCreationFailed(cacheStatus)
        }

        self.device = device
        self.commandQueue = commandQueue
        textureCache = cache
        super.init()
    }

    public func attach(to view: MTKView) {
        self.view = view
        view.device = device
        view.delegate = self
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColorMake(0.035, 0.043, 0.055, 1)
        view.framebufferOnly = true
        view.enableSetNeedsDisplay = false
        view.isPaused = false
        view.preferredFramesPerSecond = 60
        view.autoResizeDrawable = true
    }

    public func detach(from view: MTKView) {
        if self.view === view {
            view.delegate = nil
            view.isPaused = true
            self.view = nil
        }
    }

    public func display(_ pixelBuffer: CVPixelBuffer) {
        guard CVPixelBufferGetPlaneCount(pixelBuffer) == 2,
              CVPixelBufferGetPixelFormatType(pixelBuffer) == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
                CVPixelBufferGetPixelFormatType(pixelBuffer) == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange else {
            return
        }
        frameLock.lock()
        latestFrame = pixelBuffer
        frameLock.unlock()
    }

    public func setZoomScale(_ scale: CGFloat) {
        frameLock.lock()
        viewportZoomScale = min(4, max(1, scale))
        frameLock.unlock()
    }

    public func clear() {
        frameLock.lock()
        latestFrame = nil
        frameLock.unlock()
        CVMetalTextureCacheFlush(textureCache, 0)
    }

    public func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}

    public func draw(in view: MTKView) {
        guard let drawable = view.currentDrawable,
              let renderPass = view.currentRenderPassDescriptor,
              let commandBuffer = commandQueue.makeCommandBuffer() else {
            return
        }
        commandBuffer.label = "Remote Frame"

        frameLock.lock()
        let frame = latestFrame
        let zoomScale = viewportZoomScale
        frameLock.unlock()

        guard let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: renderPass) else {
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }

        guard let frame, let textures = makeTextures(from: frame) else {
            encoder.endEncoding()
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }

        let vertices = aspectFitVertices(
            frameWidth: CVPixelBufferGetWidth(frame),
            frameHeight: CVPixelBufferGetHeight(frame),
            drawableSize: view.drawableSize,
            zoomScale: zoomScale
        )
        guard !vertices.isEmpty else {
            encoder.endEncoding()
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }
        encoder.label = "Remote NV12 Encoder"
        encoder.setRenderPipelineState(pipeline)
        vertices.withUnsafeBytes { bytes in
            if let baseAddress = bytes.baseAddress {
                encoder.setVertexBytes(baseAddress, length: bytes.count, index: 0)
            }
        }
        encoder.setFragmentTexture(textures.luma, index: 0)
        encoder.setFragmentTexture(textures.chroma, index: 1)
        encoder.drawPrimitives(type: .triangleStrip, vertexStart: 0, vertexCount: vertices.count)
        encoder.endEncoding()

        commandBuffer.present(drawable)
        commandBuffer.commit()
    }

    private func makeTextures(from pixelBuffer: CVPixelBuffer) -> (luma: MTLTexture, chroma: MTLTexture)? {
        var lumaReference: CVMetalTexture?
        var chromaReference: CVMetalTexture?
        let lumaStatus = CVMetalTextureCacheCreateTextureFromImage(
            kCFAllocatorDefault,
            textureCache,
            pixelBuffer,
            nil,
            .r8Unorm,
            CVPixelBufferGetWidthOfPlane(pixelBuffer, 0),
            CVPixelBufferGetHeightOfPlane(pixelBuffer, 0),
            0,
            &lumaReference
        )
        let chromaStatus = CVMetalTextureCacheCreateTextureFromImage(
            kCFAllocatorDefault,
            textureCache,
            pixelBuffer,
            nil,
            .rg8Unorm,
            CVPixelBufferGetWidthOfPlane(pixelBuffer, 1),
            CVPixelBufferGetHeightOfPlane(pixelBuffer, 1),
            1,
            &chromaReference
        )
        guard lumaStatus == kCVReturnSuccess,
              chromaStatus == kCVReturnSuccess,
              let lumaReference,
              let chromaReference,
              let luma = CVMetalTextureGetTexture(lumaReference),
              let chroma = CVMetalTextureGetTexture(chromaReference) else {
            return nil
        }
        return (luma, chroma)
    }

    private func aspectFitVertices(
        frameWidth: Int,
        frameHeight: Int,
        drawableSize: CGSize,
        zoomScale: CGFloat
    ) -> [Vertex] {
        guard frameWidth > 0, frameHeight > 0, drawableSize.width > 0, drawableSize.height > 0 else {
            return []
        }
        let frameAspect = Float(frameWidth) / Float(frameHeight)
        let drawableAspect = Float(drawableSize.width / drawableSize.height)
        let xScale: Float
        let yScale: Float
        if frameAspect > drawableAspect {
            xScale = 1
            yScale = drawableAspect / frameAspect
        } else {
            xScale = frameAspect / drawableAspect
            yScale = 1
        }
        return [
            Vertex(position: [-xScale * Float(zoomScale), -yScale * Float(zoomScale)], textureCoordinate: [0, 1]),
            Vertex(position: [xScale * Float(zoomScale), -yScale * Float(zoomScale)], textureCoordinate: [1, 1]),
            Vertex(position: [-xScale * Float(zoomScale), yScale * Float(zoomScale)], textureCoordinate: [0, 0]),
            Vertex(position: [xScale * Float(zoomScale), yScale * Float(zoomScale)], textureCoordinate: [1, 0])
        ]
    }
}

public protocol RemoteFrameRendering: AnyObject, Sendable {
    func display(_ pixelBuffer: CVPixelBuffer)
    func clear()
}

extension MetalRemoteRenderer: RemoteFrameRendering {}
