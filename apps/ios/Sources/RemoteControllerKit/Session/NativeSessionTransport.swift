#if REMOTE_CORE_FFI
import Foundation
import Security

public struct NativeTransportSelection: Sendable, Equatable {
    public let protocolVersion: UInt16
    public let path: TransportPath
    public let candidatePairID: String
    public let relayNodeID: String?

    public init(
        protocolVersion: UInt16,
        path: TransportPath,
        candidatePairID: String,
        relayNodeID: String? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.path = path
        self.candidatePairID = candidatePairID
        self.relayNodeID = relayNodeID
    }
}

public enum NativeSecureTransportEvent: Sendable {
    case transportSelected(NativeTransportSelection)
    case peerKeyExchange(message: Data, authoritativeDevicePublicKey: Data)
    case peerKeyConfirm(Data)
    case secureVideoFrame(infoPacket: Data, dataPacket: Data)
    case stats(RemoteSessionStats)
    case disconnected(recoverable: Bool, reason: String)
    case closed
}

public protocol NativeSecureTransportDriver: Sendable {
    var events: AsyncThrowingStream<NativeSecureTransportEvent, Error> { get }
    func start(descriptor: SessionDescriptor, connectionEpoch: UInt64) async throws
    func sendKeyExchange(_ message: Data) async throws
    func sendKeyConfirm(_ message: Data) async throws
    func sendSecurePacket(_ packet: Data, realtime: Bool) async throws
    func secureSessionDidBecomeReady(session: NativeControllerSession) async throws
    func close(reason: String) async
}

public protocol NativeSecureTransportDriverFactory: Sendable {
    func makeDriver(for descriptor: SessionDescriptor) async throws -> any NativeSecureTransportDriver
}

public final class NativeRustCoreSessionBridge: RustCoreSessionBridging, @unchecked Sendable {
    public static let shared = NativeRustCoreSessionBridge()

    private let lock = NSLock()
    private var driverFactory: (any NativeSecureTransportDriverFactory)?

    public init(driverFactory: (any NativeSecureTransportDriverFactory)? = nil) {
        self.driverFactory = driverFactory
    }

    public func install(driverFactory: any NativeSecureTransportDriverFactory) {
        lock.withLock { self.driverFactory = driverFactory }
    }

    public func uninstallDriverFactory() {
        lock.withLock { driverFactory = nil }
    }

    public func makeAuthenticatedTransport(
        for descriptor: SessionDescriptor
    ) async throws -> any SessionTransport {
        guard let driverFactory = lock.withLock({ driverFactory }) else {
            throw SessionTransportError.transportDriverUnavailable
        }
        let driver = try await driverFactory.makeDriver(for: descriptor)
        return try NativeRustSessionTransport(
            descriptor: descriptor,
            identityStore: DeviceIdentityStore(store: KeychainStore()),
            driver: driver
        )
    }
}

private actor NativeRustSessionTransport: SessionTransport {
    nonisolated let incomingEvents: AsyncThrowingStream<SessionIncomingEvent, Error>

    private let descriptor: SessionDescriptor
    private let identityStore: DeviceIdentityStore
    private let driver: any NativeSecureTransportDriver
    private let core: NativeControllerSession
    private let continuation: AsyncThrowingStream<SessionIncomingEvent, Error>.Continuation
    private var commandTask: Task<Void, Never>?
    private var coreEventTask: Task<Void, Never>?
    private var driverEventTask: Task<Void, Never>?
    private var connectionEpoch: UInt64 = 0
    private var started = false
    private var closed = false

    init(
        descriptor: SessionDescriptor,
        identityStore: DeviceIdentityStore,
        driver: any NativeSecureTransportDriver
    ) throws {
        self.descriptor = descriptor
        self.identityStore = identityStore
        self.driver = driver
        core = try NativeControllerSession(sessionID: descriptor.sessionID)
        var captured: AsyncThrowingStream<SessionIncomingEvent, Error>.Continuation!
        incomingEvents = AsyncThrowingStream { captured = $0 }
        continuation = captured
    }

    func establish() async throws {
        guard !started, !closed else { throw SessionTransportError.invalidState }
        started = true
        continuation.yield(.permissions(descriptor.permissions))
        startConsumers()
        do {
            try core.connect()
        } catch {
            fail(error)
            throw error
        }
    }

    func sendInput(_ event: InputEvent) async throws {
        guard started, !closed else { throw SessionTransportError.invalidState }
        try core.sendInput(event)
    }

    func requestKeyframe(displayID: String, lastFrameID: UInt64?) async throws {
        guard started, !closed else { throw SessionTransportError.invalidState }
        try core.requestKeyframe(
            sessionID: descriptor.sessionID,
            displayID: displayID,
            lastFrameID: lastFrameID
        )
    }

    func requestMediaQuality(_ profile: MediaQualityProfile, displayID: String) async throws {
        throw SessionTransportError.commandUnavailable("媒体质量切换")
    }

    func selectDisplay(_ displayID: String) async throws {
        guard !displayID.isEmpty else { throw SessionTransportError.invalidState }
    }

    func requestClipboard(enabled: Bool) async throws {
        throw SessionTransportError.commandUnavailable("剪贴板")
    }

    func requestPrivacyMode(_ mode: String, enabled: Bool) async throws {
        throw SessionTransportError.commandUnavailable("隐私屏")
    }

    func requestFileTransfer(fileURL: URL) async throws {
        throw SessionTransportError.commandUnavailable("文件传输")
    }

    func close(reason: String) async {
        guard !closed else { return }
        closed = true
        try? core.close()
        await driver.close(reason: reason)
        commandTask?.cancel()
        coreEventTask?.cancel()
        driverEventTask?.cancel()
        commandTask = nil
        coreEventTask = nil
        driverEventTask = nil
        continuation.finish()
    }

    private func startConsumers() {
        let commands = core.commands
        commandTask = Task { [weak self] in
            for await command in commands {
                guard !Task.isCancelled else { return }
                await self?.handle(command)
            }
        }

        let coreEvents = core.events
        coreEventTask = Task { [weak self] in
            for await event in coreEvents {
                guard !Task.isCancelled else { return }
                await self?.handle(event)
            }
        }

        let driverEvents = driver.events
        driverEventTask = Task { [weak self] in
            do {
                for try await event in driverEvents {
                    guard !Task.isCancelled else { return }
                    await self?.handle(event)
                }
            } catch {
                await self?.fail(error)
            }
        }
    }

    private func handle(_ command: NativeControllerCommand) async {
        guard !closed else { return }
        do {
            switch command {
            case let .start(epoch):
                connectionEpoch = epoch
                try await driver.start(descriptor: descriptor, connectionEpoch: epoch)
            case let .signKeyExchange(digest):
                try core.submitKeyExchangeSignature(identityStore.sign(digest: digest))
            case let .sendKeyExchange(message):
                try await driver.sendKeyExchange(message)
            case let .sendKeyConfirm(message):
                try await driver.sendKeyConfirm(message)
            case let .sendSecurePacket(packet, realtime):
                try await driver.sendSecurePacket(packet, realtime: realtime)
            case .close:
                await driver.close(reason: "rust_core_closed")
            }
        } catch {
            fail(error)
        }
    }

    private func handle(_ event: NativeControllerEvent) {
        guard !closed else { return }
        switch event {
        case let .lifecycle(state):
            continuation.yield(.lifecycle(state))
        case let .videoFormat(displayID, width, height):
            continuation.yield(.displays([DisplayDescriptor(
                displayID: displayID,
                name: "远程屏幕",
                width: width,
                height: height,
                scaleFactor: 1,
                isPrimary: true
            )]))
        case let .h264(accessUnit):
            continuation.yield(.h264(accessUnit))
        case let .recoverableError(message):
            continuation.yield(.lifecycle(.degraded(message)))
        case let .fatalError(message):
            continuation.yield(.remoteError(code: "rust_transport", message: message))
        }
    }

    private func handle(_ event: NativeSecureTransportEvent) async {
        guard !closed else { return }
        do {
            switch event {
            case let .transportSelected(selection):
                let identity = try identityStore.loadOrCreate()
                let now = try nowEpochMillis()
                try core.configureHandshake(NativeHandshakeConfiguration(
                    descriptor: descriptor,
                    identity: identity,
                    protocolVersion: selection.protocolVersion,
                    selectedTransportPath: selection.path,
                    selectedCandidatePairID: selection.candidatePairID,
                    relayNodeID: selection.relayNodeID,
                    keyExchangeNonce: try randomBytes(count: 32),
                    timestampEpochMillis: now
                ))
                continuation.yield(.lifecycle(.establishingSecureSession))
            case let .peerKeyExchange(message, publicKey):
                let now = try nowEpochMillis()
                try core.receivePeerKeyExchange(
                    message,
                    authoritativeDevicePublicKey: publicKey,
                    nowEpochMillis: now,
                    keyConfirmTimestampEpochMillis: now
                )
            case let .peerKeyConfirm(message):
                try core.receivePeerKeyConfirm(message, nowEpochMillis: try nowEpochMillis())
                try await driver.secureSessionDidBecomeReady(session: core)
            case let .secureVideoFrame(infoPacket, dataPacket):
                try core.receiveSecureVideoFrame(infoPacket: infoPacket, dataPacket: dataPacket)
            case let .stats(stats):
                continuation.yield(.stats(stats))
            case let .disconnected(recoverable, reason):
                try core.receiveDisconnected(
                    connectionEpoch: connectionEpoch,
                    recoverable: recoverable,
                    reason: reason
                )
            case .closed:
                await close(reason: "transport_closed")
            }
        } catch {
            fail(error)
        }
    }

    private func fail(_ error: Error) {
        guard !closed else { return }
        continuation.yield(.remoteError(code: "native_secure_transport", message: error.localizedDescription))
    }

    private func nowEpochMillis() throws -> UInt64 {
        guard let value = UInt64(exactly: Date.now.epochMillis) else {
            throw SessionTransportError.invalidState
        }
        return value
    }

    private func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SessionTransportError.invalidState
        }
        return Data(bytes)
    }
}
#endif
