import Foundation

public struct H264AccessUnit: Sendable {
    public let data: Data
    public let presentationTimeMillis: Int64
    public let isKeyframe: Bool
    public let frameID: UInt64

    public init(data: Data, presentationTimeMillis: Int64, isKeyframe: Bool, frameID: UInt64) {
        self.data = data
        self.presentationTimeMillis = presentationTimeMillis
        self.isKeyframe = isKeyframe
        self.frameID = frameID
    }
}

public enum SessionIncomingEvent: Sendable {
    case lifecycle(SessionLifecycleState)
    case h264(H264AccessUnit)
    case stats(RemoteSessionStats)
    case displays([DisplayDescriptor])
    case permissions(SessionPermissions)
    case privacyMode(mode: String, state: String, errorCode: String?)
    case remoteError(code: String, message: String)
}

public protocol SessionTransport: Sendable {
    var incomingEvents: AsyncThrowingStream<SessionIncomingEvent, Error> { get }
    func establish() async throws
    func sendInput(_ event: InputEvent) async throws
    func requestMediaQuality(_ profile: MediaQualityProfile, displayID: String) async throws
    func requestKeyframe(displayID: String, lastFrameID: UInt64?) async throws
    func selectDisplay(_ displayID: String) async throws
    func requestClipboard(enabled: Bool) async throws
    func requestPrivacyMode(_ mode: String, enabled: Bool) async throws
    func requestFileTransfer(fileURL: URL) async throws
    func close(reason: String) async
}

public protocol SessionTransportFactory: Sendable {
    func makeTransport(for descriptor: SessionDescriptor) async throws -> any SessionTransport
}

public protocol RustCoreSessionBridging: Sendable {
    func makeAuthenticatedTransport(for descriptor: SessionDescriptor) async throws -> any SessionTransport
}

public struct RustCoreSessionTransportFactory: SessionTransportFactory {
    private let bridge: (any RustCoreSessionBridging)?

    public init(bridge: (any RustCoreSessionBridging)? = nil) {
        self.bridge = bridge
    }

    public func makeTransport(for descriptor: SessionDescriptor) async throws -> any SessionTransport {
        guard let bridge else { throw SessionTransportError.rustCoreUnavailable }
        return try await bridge.makeAuthenticatedTransport(for: descriptor)
    }
}

public enum SessionTransportError: LocalizedError, Equatable {
    case rustCoreUnavailable
    case secureSessionNotEstablished
    case permissionDenied(String)
    case invalidState

    public var errorDescription: String? {
        switch self {
        case .rustCoreUnavailable:
            return "Rust Core 的 QUIC、OPAQUE 与端到端加密 FFI 尚未接入"
        case .secureSessionNotEstablished:
            return "端到端加密会话尚未建立"
        case let .permissionDenied(capability):
            return "当前会话未授权\(capability)"
        case .invalidState:
            return "当前会话状态不允许此操作"
        }
    }
}
