#if REMOTE_CORE_FFI
import Foundation
import RemoteIOSFFI

enum NativeQuicDataPlaneEvent: Sendable {
    case state(Int32, String)
    case secureVideoFrame(infoPacket: Data, dataPacket: Data)
    case disconnected(recoverable: Bool, reason: String)
    case closed
}

private final class NativeQuicCallbackContext: @unchecked Sendable {
    let continuation: AsyncStream<NativeQuicDataPlaneEvent>.Continuation
    private let lock = NSLock()
    private var videoGroups = NativeVideoPacketGroupAssembler()

    init(continuation: AsyncStream<NativeQuicDataPlaneEvent>.Continuation) {
        self.continuation = continuation
    }

    func receiveVideoPacket(
        groupID: UInt64,
        index: UInt32,
        count: UInt32,
        packet: Data
    ) {
        let pair: (Data, Data)? = lock.withLock {
            videoGroups.insert(
                groupID: groupID,
                index: index,
                count: count,
                packet: packet
            )
        }
        if let pair {
            continuation.yield(.secureVideoFrame(infoPacket: pair.0, dataPacket: pair.1))
        }
    }
}

private let nativeQuicStateCallback: RemoteQuicStateCallback = {
    context, _, state, detail, detailLength in
    guard let callback = NativeQuicDataPlane.context(from: context) else { return }
    callback.continuation.yield(.state(
        state,
        NativeQuicDataPlane.string(from: detail, count: detailLength)
    ))
}

private let nativeQuicPacketCallback: RemoteQuicPacketCallback = {
    context, _, delivery, _, groupID, packetIndex, packetCount, packet, packetLength in
    guard UInt32(bitPattern: delivery) == REMOTE_QUIC_DELIVERY_VIDEO.rawValue,
          let callback = NativeQuicDataPlane.context(from: context),
          let packet else { return }
    callback.receiveVideoPacket(
        groupID: groupID,
        index: packetIndex,
        count: packetCount,
        packet: Data(bytes: packet, count: packetLength)
    )
}

private let nativeQuicDisconnectCallback: RemoteQuicDisconnectCallback = {
    context, _, result, reason, reasonLength in
    guard let callback = NativeQuicDataPlane.context(from: context) else { return }
    callback.continuation.yield(.disconnected(
        recoverable: UInt32(bitPattern: result) == REMOTE_CONTROLLER_TRANSPORT_ERROR.rawValue,
        reason: NativeQuicDataPlane.string(from: reason, count: reasonLength)
    ))
}

private let nativeQuicClosedCallback: RemoteQuicClosedCallback = { context, _ in
    NativeQuicDataPlane.context(from: context)?.continuation.yield(.closed)
}

final class NativeQuicDataPlane: @unchecked Sendable {
    let events: AsyncStream<NativeQuicDataPlaneEvent>

    private let callbackContext: Unmanaged<NativeQuicCallbackContext>
    private let lock = NSLock()
    private var handle: UInt64

    init(session: NativeControllerSession) throws {
        var continuation: AsyncStream<NativeQuicDataPlaneEvent>.Continuation!
        events = AsyncStream { continuation = $0 }
        callbackContext = Unmanaged.passRetained(NativeQuicCallbackContext(
            continuation: continuation
        ))
        handle = remote_controller_quic_transport_create(
            try session.rawHandleForQuicTransport(),
            RemoteQuicCallbacks(
                context: UInt64(UInt(bitPattern: callbackContext.toOpaque())),
                on_state: nativeQuicStateCallback,
                on_packet: nativeQuicPacketCallback,
                on_disconnect: nativeQuicDisconnectCallback,
                on_closed: nativeQuicClosedCallback
            )
        )
        guard handle != 0 else {
            callbackContext.release()
            throw NativeControllerCoreError.invalidState
        }
    }

    deinit {
        let ownedHandle = lock.withLock { () -> UInt64 in
            defer { handle = 0 }
            return handle
        }
        if ownedHandle != 0 {
            _ = remote_controller_quic_transport_close(ownedHandle)
            _ = remote_controller_quic_transport_destroy(ownedHandle)
        }
        callbackContext.takeUnretainedValue().continuation.finish()
        callbackContext.release()
    }

    func bind(socketFD: Int32, peerCertificateDER: Data) throws {
        let handle = try requireHandle()
        let result = peerCertificateDER.withUnsafeBytes { certificate in
            remote_controller_quic_transport_bind_socket(
                handle,
                socketFD,
                certificate.bindMemory(to: UInt8.self).baseAddress,
                certificate.count
            )
        }
        try check(result)
    }

    func connect(remoteEndpoint: String, serverName: String) throws {
        let handle = try requireHandle()
        let endpoint = Data(remoteEndpoint.utf8)
        let name = Data(serverName.utf8)
        let result = endpoint.withUnsafeBytes { endpointBytes in
            name.withUnsafeBytes { nameBytes in
                remote_controller_quic_transport_connect(
                    handle,
                    endpointBytes.bindMemory(to: UInt8.self).baseAddress,
                    endpointBytes.count,
                    nameBytes.bindMemory(to: UInt8.self).baseAddress,
                    nameBytes.count
                )
            }
        }
        try check(result)
    }

    func send(_ packet: Data, realtime: Bool) throws {
        let handle = try requireHandle()
        let result = packet.withUnsafeBytes { bytes in
            if realtime {
                remote_controller_quic_transport_send_realtime(
                    handle,
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count
                )
            } else {
                remote_controller_quic_transport_send_reliable(
                    handle,
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count
                )
            }
        }
        try check(result)
    }

    func close() {
        guard let handle = try? requireHandle() else { return }
        _ = remote_controller_quic_transport_close(handle)
    }

    fileprivate static func context(from rawValue: UInt64) -> NativeQuicCallbackContext? {
        guard rawValue != 0,
              let pointer = UnsafeRawPointer(bitPattern: UInt(rawValue)) else { return nil }
        return Unmanaged<NativeQuicCallbackContext>.fromOpaque(pointer).takeUnretainedValue()
    }

    fileprivate static func string(from bytes: UnsafePointer<UInt8>?, count: Int) -> String {
        guard let bytes, count > 0 else { return "" }
        return String(decoding: UnsafeBufferPointer(start: bytes, count: count), as: UTF8.self)
    }

    private func requireHandle() throws -> UInt64 {
        let value = lock.withLock { handle }
        guard value != 0 else { throw NativeControllerCoreError.invalidHandle }
        return value
    }

    private func check(_ result: Int32) throws {
        switch UInt32(bitPattern: result) {
        case REMOTE_CONTROLLER_OK.rawValue: return
        case REMOTE_CONTROLLER_INVALID_HANDLE.rawValue: throw NativeControllerCoreError.invalidHandle
        case REMOTE_CONTROLLER_INVALID_STATE.rawValue: throw NativeControllerCoreError.invalidState
        case REMOTE_CONTROLLER_INVALID_INPUT.rawValue,
             REMOTE_CONTROLLER_INVALID_ARGUMENT.rawValue: throw NativeControllerCoreError.invalidInput
        case REMOTE_CONTROLLER_TRANSPORT_ERROR.rawValue: throw NativeControllerCoreError.transport
        case REMOTE_CONTROLLER_SECURITY_ERROR.rawValue: throw NativeControllerCoreError.security
        default: throw NativeControllerCoreError.internalFailure(result)
        }
    }
}
#endif
