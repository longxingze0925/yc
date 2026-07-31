#if REMOTE_CORE_FFI
import Foundation
import RemoteIOSFFI

public enum NativeControllerCoreError: LocalizedError, Equatable {
    case creationFailed
    case invalidHandle
    case invalidState
    case invalidInput
    case transport
    case security
    case internalFailure(Int32)

    public var errorDescription: String? {
        switch self {
        case .creationFailed:
            return "Rust 会话句柄创建失败"
        case .invalidHandle:
            return "Rust 会话句柄已失效"
        case .invalidState:
            return "Rust 会话状态不允许此操作"
        case .invalidInput:
            return "Rust 拒绝了输入或媒体数据"
        case .transport:
            return "Rust 会话传输失败"
        case .security:
            return "Rust 会话安全握手或密文校验失败"
        case let .internalFailure(code):
            return "Rust 会话内部错误（\(code)）"
        }
    }
}

public enum NativeControllerCommand: Sendable {
    case start(connectionEpoch: UInt64)
    case signKeyExchange(digest: Data)
    case sendKeyExchange(Data)
    case sendKeyConfirm(Data)
    case sendSecurePacket(data: Data, realtime: Bool)
    case close
}

public enum NativeControllerEvent: Sendable {
    case lifecycle(SessionLifecycleState)
    case videoFormat(displayID: String, width: UInt32, height: UInt32)
    case h264(H264AccessUnit)
    case recoverableError(String)
    case fatalError(String)
}

public struct NativeHandshakeConfiguration: Encodable, Sendable {
    public let sessionID: UUID
    public let accountID: String
    public let controllerDeviceID: String
    public let controlledDeviceID: String
    public let permissions: SessionPermissions
    public let permissionsDigest: [UInt8]
    public let protocolVersion: UInt16
    public let sessionExpiresAtEpochMillis: UInt64
    public let selectedTransportPath: TransportPath
    public let selectedCandidatePairID: String
    public let relayNodeID: String?
    public let localDevicePublicKey: [UInt8]
    public let keyExchangeNonce: [UInt8]
    public let timestampEpochMillis: UInt64

    public init(
        descriptor: SessionDescriptor,
        identity: DeviceIdentity,
        protocolVersion: UInt16,
        selectedTransportPath: TransportPath,
        selectedCandidatePairID: String,
        relayNodeID: String?,
        keyExchangeNonce: Data,
        timestampEpochMillis: UInt64
    ) throws {
        guard identity.deviceID == descriptor.controllerDeviceID,
              identity.publicKey.count == 32,
              descriptor.permissionsDigest.count == 32,
              keyExchangeNonce.count == 32,
              descriptor.expiresAtEpochMillis > 0,
              UInt64(descriptor.expiresAtEpochMillis) > timestampEpochMillis,
              ProtocolConstants.supportedVersions.contains(protocolVersion),
              selectedCandidatePairID.count == 32,
              selectedCandidatePairID != String(repeating: "0", count: 32),
              selectedCandidatePairID.unicodeScalars.allSatisfy({
                  CharacterSet(charactersIn: "0123456789abcdef").contains($0)
              }),
              selectedTransportPath.isRelay == (relayNodeID != nil) else {
            throw NativeControllerCoreError.invalidInput
        }
        sessionID = descriptor.sessionID
        accountID = descriptor.accountID
        controllerDeviceID = descriptor.controllerDeviceID
        controlledDeviceID = descriptor.controlledDeviceID
        permissions = descriptor.permissions
        permissionsDigest = Array(descriptor.permissionsDigest)
        self.protocolVersion = protocolVersion
        sessionExpiresAtEpochMillis = UInt64(descriptor.expiresAtEpochMillis)
        self.selectedTransportPath = selectedTransportPath
        self.selectedCandidatePairID = selectedCandidatePairID
        self.relayNodeID = relayNodeID
        localDevicePublicKey = Array(identity.publicKey)
        self.keyExchangeNonce = Array(keyExchangeNonce)
        self.timestampEpochMillis = timestampEpochMillis
    }

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case accountID = "account_id"
        case controllerDeviceID = "controller_device_id"
        case controlledDeviceID = "controlled_device_id"
        case permissions
        case permissionsDigest = "permissions_digest"
        case protocolVersion = "protocol_version"
        case sessionExpiresAtEpochMillis = "session_expires_at_epoch_millis"
        case selectedTransportPath = "selected_transport_path"
        case selectedCandidatePairID = "selected_candidate_pair_id"
        case relayNodeID = "relay_node_id"
        case localDevicePublicKey = "local_device_public_key"
        case keyExchangeNonce = "key_exchange_nonce"
        case timestampEpochMillis = "timestamp_epoch_millis"
    }
}

private struct NativeKeyframeRequest: Encodable {
    let sessionID: UUID
    let displayID: String
    let reason = "keyframe_loss"
    let lastReceivedFrameID: UInt64
    let timestampEpochMillis: UInt64

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case displayID = "display_id"
        case reason
        case lastReceivedFrameID = "last_received_frame_id"
        case timestampEpochMillis = "timestamp_epoch_millis"
    }
}

private final class NativeCallbackContext: @unchecked Sendable {
    let commandContinuation: AsyncStream<NativeControllerCommand>.Continuation
    let eventContinuation: AsyncStream<NativeControllerEvent>.Continuation

    init(
        commandContinuation: AsyncStream<NativeControllerCommand>.Continuation,
        eventContinuation: AsyncStream<NativeControllerEvent>.Continuation
    ) {
        self.commandContinuation = commandContinuation
        self.eventContinuation = eventContinuation
    }
}

private struct NativeVideoFormat: Decodable {
    let displayID: String
    let width: UInt32
    let height: UInt32

    private enum CodingKeys: String, CodingKey {
        case displayID = "display_id"
        case width
        case height
    }
}

private let nativeCommandCallback: RemoteControllerCommandCallback = {
    context, commandKind, connectionEpoch, delivery, payload, payloadLength in
    guard let context = NativeControllerSession.context(from: context) else { return }
    switch commandKind {
    case REMOTE_CONTROLLER_COMMAND_START.rawValue:
        context.commandContinuation.yield(.start(connectionEpoch: connectionEpoch))
    case REMOTE_CONTROLLER_COMMAND_SIGN_KEY_EXCHANGE.rawValue:
        guard let payload else { return }
        context.commandContinuation.yield(.signKeyExchange(
            digest: Data(bytes: payload, count: payloadLength)
        ))
    case REMOTE_CONTROLLER_COMMAND_SEND_KEY_EXCHANGE.rawValue:
        guard let payload else { return }
        context.commandContinuation.yield(.sendKeyExchange(Data(bytes: payload, count: payloadLength)))
    case REMOTE_CONTROLLER_COMMAND_SEND_KEY_CONFIRM.rawValue:
        guard let payload else { return }
        context.commandContinuation.yield(.sendKeyConfirm(Data(bytes: payload, count: payloadLength)))
    case REMOTE_CONTROLLER_COMMAND_SEND_SECURE_PACKET.rawValue:
        guard let payload else { return }
        context.commandContinuation.yield(.sendSecurePacket(
            data: Data(bytes: payload, count: payloadLength),
            realtime: delivery == 1
        ))
    case REMOTE_CONTROLLER_COMMAND_CLOSE.rawValue:
        context.commandContinuation.yield(.close)
    default:
        break
    }
}

private let nativeEventCallback: RemoteControllerEventCallback = {
    context, eventKind, stateOrError, payload, payloadLength,
    presentationTimeMillis, isKeyframe, frameID in
    guard let context = NativeControllerSession.context(from: context) else { return }
    switch eventKind {
    case REMOTE_CONTROLLER_EVENT_STATE.rawValue:
        let lifecycle: SessionLifecycleState
        switch stateOrError {
        case REMOTE_CONTROLLER_STATE_CONNECTING.rawValue: lifecycle = .connecting
        case REMOTE_CONTROLLER_STATE_STREAMING.rawValue: lifecycle = .connected
        case REMOTE_CONTROLLER_STATE_RECONNECTING.rawValue: lifecycle = .reconnecting
        case REMOTE_CONTROLLER_STATE_CLOSED.rawValue: lifecycle = .closed
        default: lifecycle = .idle
        }
        context.eventContinuation.yield(.lifecycle(lifecycle))
    case REMOTE_CONTROLLER_EVENT_H264.rawValue:
        guard let payload else { return }
        context.eventContinuation.yield(.h264(H264AccessUnit(
            data: Data(bytes: payload, count: payloadLength),
            presentationTimeMillis: presentationTimeMillis,
            isKeyframe: isKeyframe,
            frameID: frameID
        )))
    case REMOTE_CONTROLLER_EVENT_VIDEO_FORMAT.rawValue:
        guard let payload,
              let format = try? JSONDecoder().decode(
                  NativeVideoFormat.self,
                  from: Data(bytes: payload, count: payloadLength)
              ) else { return }
        context.eventContinuation.yield(.videoFormat(
            displayID: format.displayID,
            width: format.width,
            height: format.height
        ))
    case REMOTE_CONTROLLER_EVENT_RECOVERABLE_ERROR.rawValue:
        context.eventContinuation.yield(.recoverableError(
            NativeControllerSession.string(from: payload, count: payloadLength)
        ))
    case REMOTE_CONTROLLER_EVENT_FATAL_ERROR.rawValue:
        context.eventContinuation.yield(.fatalError(
            NativeControllerSession.string(from: payload, count: payloadLength)
        ))
    default:
        break
    }
}

public final class NativeControllerSession: @unchecked Sendable {
    public let commands: AsyncStream<NativeControllerCommand>
    public let events: AsyncStream<NativeControllerEvent>

    private let callbackContext: Unmanaged<NativeCallbackContext>
    private let lock = NSLock()
    private var handle: UInt64

    public init(sessionID: UUID) throws {
        var commandContinuation: AsyncStream<NativeControllerCommand>.Continuation!
        commands = AsyncStream { commandContinuation = $0 }
        var eventContinuation: AsyncStream<NativeControllerEvent>.Continuation!
        events = AsyncStream { eventContinuation = $0 }
        callbackContext = Unmanaged.passRetained(NativeCallbackContext(
            commandContinuation: commandContinuation,
            eventContinuation: eventContinuation
        ))

        let pair = sessionID.uint64Pair
        handle = remote_controller_session_create(
            pair.high,
            pair.low,
            RemoteControllerCallbacks(
                context: UInt64(UInt(bitPattern: callbackContext.toOpaque())),
                on_command: nativeCommandCallback,
                on_event: nativeEventCallback
            )
        )
        guard handle != 0 else {
            callbackContext.release()
            throw NativeControllerCoreError.creationFailed
        }
    }

    deinit {
        let ownedHandle = lock.withLock { () -> UInt64 in
            defer { handle = 0 }
            return handle
        }
        if ownedHandle != 0 {
            remote_controller_session_destroy(ownedHandle)
        }
        callbackContext.takeUnretainedValue().commandContinuation.finish()
        callbackContext.takeUnretainedValue().eventContinuation.finish()
        callbackContext.release()
    }

    public func connect() throws {
        try check(remote_controller_session_connect(requireHandle()))
    }

    public func configureHandshake(_ configuration: NativeHandshakeConfiguration) throws {
        try withEncoded(configuration) { bytes in
            remote_controller_session_configure_handshake_json(
                requireHandle(),
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count
            )
        }
    }

    public func submitKeyExchangeSignature(_ signature: Data) throws {
        let result = signature.withUnsafeBytes { bytes in
            remote_controller_session_submit_key_exchange_signature(
                requireHandle(),
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count
            )
        }
        try check(result)
    }

    public func receivePeerKeyExchange(
        _ message: Data,
        authoritativeDevicePublicKey: Data,
        nowEpochMillis: UInt64,
        keyConfirmTimestampEpochMillis: UInt64
    ) throws {
        let result = message.withUnsafeBytes { messageBytes in
            authoritativeDevicePublicKey.withUnsafeBytes { keyBytes in
                remote_controller_session_receive_peer_key_exchange_json(
                    requireHandle(),
                    messageBytes.bindMemory(to: UInt8.self).baseAddress,
                    messageBytes.count,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    keyBytes.count,
                    nowEpochMillis,
                    keyConfirmTimestampEpochMillis
                )
            }
        }
        try check(result)
    }

    public func receivePeerKeyConfirm(_ message: Data, nowEpochMillis: UInt64) throws {
        let result = message.withUnsafeBytes { bytes in
            remote_controller_session_receive_peer_key_confirm_json(
                requireHandle(),
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                nowEpochMillis
            )
        }
        try check(result)
    }

    public func sendInput(_ event: InputEvent) throws {
        try withEncoded(event) { bytes in
            remote_controller_session_send_input_json(
                requireHandle(),
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count
            )
        }
    }

    public func requestKeyframe(
        sessionID: UUID,
        displayID: String,
        lastFrameID: UInt64?
    ) throws {
        guard let timestampEpochMillis = UInt64(exactly: Date.now.epochMillis) else {
            throw NativeControllerCoreError.invalidInput
        }
        let request = NativeKeyframeRequest(
            sessionID: sessionID,
            displayID: displayID,
            lastReceivedFrameID: lastFrameID ?? 0,
            timestampEpochMillis: timestampEpochMillis
        )
        try withEncoded(request) { bytes in
            remote_controller_session_send_keyframe_request_json(
                requireHandle(),
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count
            )
        }
    }

    public func receiveDisconnected(
        connectionEpoch: UInt64,
        recoverable: Bool,
        reason: String
    ) throws {
        try sendTransportEvent(
            connectionEpoch: connectionEpoch,
            eventKind: recoverable ? 2 : 3,
            reason: reason
        )
    }

    public func receiveSecureVideoFrame(infoPacket: Data, dataPacket: Data) throws {
        let result = infoPacket.withUnsafeBytes { infoBytes in
            dataPacket.withUnsafeBytes { dataBytes in
                remote_controller_session_receive_secure_video_frame(
                    requireHandle(),
                    infoBytes.bindMemory(to: UInt8.self).baseAddress,
                    infoBytes.count,
                    dataBytes.bindMemory(to: UInt8.self).baseAddress,
                    dataBytes.count
                )
            }
        }
        try check(result)
    }

    public func close() throws {
        try check(remote_controller_session_close(requireHandle()))
    }

    func rawHandleForQuicTransport() throws -> UInt64 {
        let handle = requireHandle()
        guard handle != 0 else { throw NativeControllerCoreError.invalidHandle }
        return handle
    }

    fileprivate static func context(from rawValue: UInt64) -> NativeCallbackContext? {
        guard rawValue != 0,
              let pointer = UnsafeRawPointer(bitPattern: UInt(rawValue)) else { return nil }
        return Unmanaged<NativeCallbackContext>.fromOpaque(pointer).takeUnretainedValue()
    }

    fileprivate static func string(from bytes: UnsafePointer<UInt8>?, count: Int) -> String {
        guard let bytes, count > 0 else { return "" }
        return String(decoding: UnsafeBufferPointer(start: bytes, count: count), as: UTF8.self)
    }

    private func sendTransportEvent(
        connectionEpoch: UInt64,
        eventKind: Int32,
        reason: String
    ) throws {
        let data = Data(reason.utf8)
        let result = data.withUnsafeBytes { bytes in
            remote_controller_session_transport_event(
                requireHandle(),
                connectionEpoch,
                eventKind,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count
            )
        }
        try check(result)
    }

    private func requireHandle() -> UInt64 {
        lock.withLock { handle }
    }

    private func check(_ result: Int32) throws {
        switch result {
        case REMOTE_CONTROLLER_OK.rawValue: return
        case REMOTE_CONTROLLER_INVALID_HANDLE.rawValue: throw NativeControllerCoreError.invalidHandle
        case REMOTE_CONTROLLER_INVALID_STATE.rawValue: throw NativeControllerCoreError.invalidState
        case REMOTE_CONTROLLER_INVALID_INPUT.rawValue: throw NativeControllerCoreError.invalidInput
        case REMOTE_CONTROLLER_TRANSPORT_ERROR.rawValue: throw NativeControllerCoreError.transport
        case REMOTE_CONTROLLER_SECURITY_ERROR.rawValue: throw NativeControllerCoreError.security
        default: throw NativeControllerCoreError.internalFailure(result)
        }
    }

    private func withEncoded<T: Encodable>(
        _ value: T,
        operation: (UnsafeRawBufferPointer) -> Int32
    ) throws {
        let data = try JSONEncoder().encode(value)
        try check(data.withUnsafeBytes(operation))
    }
}

private extension UUID {
    var uint64Pair: (high: UInt64, low: UInt64) {
        var value = uuid
        return withUnsafeBytes(of: &value) { bytes in
            let high = bytes.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let low = bytes.suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            return (high, low)
        }
    }
}

private extension TransportPath {
    var isRelay: Bool {
        self == .quicRelay || self == .tls443Relay
    }
}
#endif
