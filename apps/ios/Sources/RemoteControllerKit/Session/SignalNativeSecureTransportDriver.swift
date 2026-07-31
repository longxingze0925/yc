#if REMOTE_CORE_FFI && canImport(Darwin)
import CryptoKit
import Darwin
import Foundation
import RemoteIOSFFI
import Security

public struct SignalNativeSecureTransportDriverFactory: NativeSecureTransportDriverFactory {
    private let signal: SignalClient
    private let router: SignalSessionEventRouter
    private let identityStore: DeviceIdentityStore

    public init(
        signal: SignalClient,
        router: SignalSessionEventRouter,
        identityStore: DeviceIdentityStore
    ) {
        self.signal = signal
        self.router = router
        self.identityStore = identityStore
    }

    public func makeDriver(
        for descriptor: SessionDescriptor
    ) async throws -> any NativeSecureTransportDriver {
        SignalNativeSecureTransportDriver(
            descriptor: descriptor,
            signal: signal,
            router: router,
            identityStore: identityStore,
            routedEvents: await router.events(for: descriptor.sessionID)
        )
    }
}

private enum SignalNativeTransportError: LocalizedError {
    case invalidState
    case noPrivateIPv4Interface
    case socket(String)
    case candidateTokenMismatch
    case peerMismatch
    case probeFailed
    case quicNotConnected

    var errorDescription: String? {
        switch self {
        case .invalidState: return "Signal 会话传输状态无效"
        case .noPrivateIPv4Interface: return "未找到可用的私网 IPv4 接口"
        case let .socket(operation): return "UDP socket 操作失败：\(operation)"
        case .candidateTokenMismatch: return "候选 token 与本机候选不匹配"
        case .peerMismatch: return "Signal 对端设备绑定不匹配"
        case .probeFailed: return "授权 UDP probe 未在时限内收到原样回显"
        case .quicNotConnected: return "QUIC 数据面尚未连接"
        }
    }
}

private struct LocalControllerCandidate {
    let socket: DarwinLANCandidateSocket
    let candidate: SignalConnectionCandidate
    let tokenRequest: SignalCandidateTokenRequest
}

private final class DarwinLANCandidateSocket: @unchecked Sendable {
    struct Interface {
        let name: String
        let index: UInt32
        let address: in_addr
        let addressText: String
        let network: UInt32
        let mask: UInt32
    }

    let endpoint: String
    let interface: Interface

    private let lock = NSLock()
    private var descriptor: Int32

    private init(descriptor: Int32, endpoint: String, interface: Interface) {
        self.descriptor = descriptor
        self.endpoint = endpoint
        self.interface = interface
    }

    deinit { close() }

    static func open() throws -> DarwinLANCandidateSocket {
        let interface = try discoverInterface()
        let descriptor = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else { throw SignalNativeTransportError.socket("socket") }
        do {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = 0
            address.sin_addr = interface.address
            let bindResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bindResult == 0 else { throw SignalNativeTransportError.socket("bind") }

            var bound = sockaddr_in()
            var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let nameResult = withUnsafeMutablePointer(to: &bound) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.getsockname(descriptor, $0, &boundLength)
                }
            }
            let port = UInt16(bigEndian: bound.sin_port)
            guard nameResult == 0, port >= 49_152 else {
                throw SignalNativeTransportError.socket("ephemeral_port")
            }
            return DarwinLANCandidateSocket(
                descriptor: descriptor,
                endpoint: "\(interface.addressText):\(port)",
                interface: interface
            )
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    func probe(_ peer: ControlledSignalCandidate) async throws {
        let packet = try Self.probePacket(peer)
        let remote = try remoteAddress(
            endpoint: peer.candidate.endpoint,
            localInterface: interface
        )
        let descriptor = try duplicateDescriptor()
        try await Task.detached(priority: .userInitiated) {
            defer { Darwin.close(descriptor) }
            var remote = remote
            let sent = packet.withUnsafeBytes { bytes in
                withUnsafePointer(to: &remote) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.sendto(
                            descriptor,
                            bytes.baseAddress,
                            bytes.count,
                            0,
                            $0,
                            socklen_t(MemoryLayout<sockaddr_in>.size)
                        )
                    }
                }
            }
            guard sent == packet.count else { throw SignalNativeTransportError.probeFailed }

            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            guard Darwin.poll(&pollDescriptor, 1, 3_000) == 1,
                  pollDescriptor.revents & Int16(POLLIN) != 0 else {
                throw SignalNativeTransportError.probeFailed
            }
            var response = [UInt8](repeating: 0, count: 2_305)
            var sender = sockaddr_in()
            var senderLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let received = response.withUnsafeMutableBytes { bytes in
                withUnsafeMutablePointer(to: &sender) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.recvfrom(
                            descriptor,
                            bytes.baseAddress,
                            bytes.count,
                            0,
                            $0,
                            &senderLength
                        )
                    }
                }
            }
            guard received == packet.count,
                  sender.sin_addr.s_addr == remote.sin_addr.s_addr,
                  sender.sin_port == remote.sin_port,
                  Data(response.prefix(received)) == packet else {
                throw SignalNativeTransportError.probeFailed
            }
        }.value
    }

    func withDescriptor<T>(_ operation: (Int32) throws -> T) throws -> T {
        try operation(requireDescriptor())
    }

    func close() {
        let owned = lock.withLock { () -> Int32 in
            defer { descriptor = -1 }
            return descriptor
        }
        if owned >= 0 { Darwin.close(owned) }
    }

    private func requireDescriptor() throws -> Int32 {
        let value = lock.withLock { descriptor }
        guard value >= 0 else { throw SignalNativeTransportError.invalidState }
        return value
    }

    private func duplicateDescriptor() throws -> Int32 {
        try lock.withLock {
            guard descriptor >= 0 else { throw SignalNativeTransportError.invalidState }
            let duplicate = Darwin.dup(descriptor)
            guard duplicate >= 0 else { throw SignalNativeTransportError.socket("dup") }
            return duplicate
        }
    }

    private static func discoverInterface() throws -> Interface {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard Darwin.getifaddrs(&first) == 0, let first else {
            throw SignalNativeTransportError.noPrivateIPv4Interface
        }
        defer { Darwin.freeifaddrs(first) }
        var matches: [Interface] = []
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let item = current {
            defer { current = item.pointee.ifa_next }
            guard let addressPointer = item.pointee.ifa_addr,
                  let maskPointer = item.pointee.ifa_netmask,
                  addressPointer.pointee.sa_family == sa_family_t(AF_INET),
                  item.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  item.pointee.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            let address = addressPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                $0.pointee.sin_addr
            }
            let mask = maskPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                $0.pointee.sin_addr
            }
            let hostOrder = UInt32(bigEndian: address.s_addr)
            guard isPrivateIPv4(hostOrder) else { continue }
            let name = String(cString: item.pointee.ifa_name)
            let index = Darwin.if_nametoindex(name)
            guard index > 0, let addressText = ipv4Text(address) else { continue }
            let hostMask = UInt32(bigEndian: mask.s_addr)
            matches.append(Interface(
                name: name,
                index: index,
                address: address,
                addressText: addressText,
                network: hostOrder & hostMask,
                mask: hostMask
            ))
        }
        guard let selected = matches.sorted(by: { lhs, rhs in
            if (lhs.name == "en0") != (rhs.name == "en0") {
                return lhs.name == "en0"
            }
            return lhs.name < rhs.name
        }).first else {
            throw SignalNativeTransportError.noPrivateIPv4Interface
        }
        return selected
    }

    private static func remoteAddress(
        endpoint: String,
        localInterface: Interface
    ) throws -> sockaddr_in {
        guard let separator = endpoint.lastIndex(of: ":"),
              let port = UInt16(endpoint[endpoint.index(after: separator)...]),
              port >= 49_152 else { throw SignalNativeTransportError.peerMismatch }
        let host = String(endpoint[..<separator])
        var address = in_addr()
        guard host.withCString({ Darwin.inet_pton(AF_INET, $0, &address) }) == 1 else {
            throw SignalNativeTransportError.peerMismatch
        }
        let hostOrder = UInt32(bigEndian: address.s_addr)
        guard isPrivateIPv4(hostOrder),
              hostOrder & localInterface.mask == localInterface.network else {
            throw SignalNativeTransportError.peerMismatch
        }
        var remote = sockaddr_in()
        remote.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        remote.sin_family = sa_family_t(AF_INET)
        remote.sin_port = port.bigEndian
        remote.sin_addr = address
        return remote
    }

    private static func probePacket(_ peer: ControlledSignalCandidate) throws -> Data {
        guard let sessionID = Data(uuid: peer.candidate.sessionID),
              let candidateID = Data(lowerHex128: peer.candidate.candidateID),
              !peer.authorization.candidateToken.isEmpty,
              peer.authorization.candidateToken.count <= 2_048,
              peer.authorization.candidateTokenBindingHash.count == 32 else {
            throw SignalNativeTransportError.probeFailed
        }
        var nonce = try randomBytes(count: 32)
        if nonce.allSatisfy({ $0 == 0 }) { nonce[0] = 1 }
        var packet = Data("RCP1".utf8)
        packet.append(sessionID)
        packet.append(candidateID)
        packet.append(1)
        packet.append(integer(UInt16(peer.authorization.candidateToken.count)))
        packet.append(contentsOf: peer.authorization.candidateToken)
        packet.append(contentsOf: peer.authorization.candidateTokenBindingHash)
        packet.append(contentsOf: nonce)
        return packet
    }

    private static func ipv4Text(_ address: in_addr) -> String? {
        var address = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard Darwin.inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func isPrivateIPv4(_ address: UInt32) -> Bool {
        let first = UInt8((address >> 24) & 0xff)
        let second = UInt8((address >> 16) & 0xff)
        return first == 10
            || (first == 172 && (16...31).contains(second))
            || (first == 192 && second == 168)
    }
}

private actor SignalNativeSecureTransportDriver: NativeSecureTransportDriver {
    nonisolated let events: AsyncThrowingStream<NativeSecureTransportEvent, Error>

    private let descriptor: SessionDescriptor
    private let signal: SignalClient
    private let router: SignalSessionEventRouter
    private let identityStore: DeviceIdentityStore
    private let routedEvents: AsyncStream<RoutedSignalSessionEvent>
    private let continuation: AsyncThrowingStream<NativeSecureTransportEvent, Error>.Continuation
    private var routedEventsTask: Task<Void, Never>?
    private var quicEventsTask: Task<Void, Never>?
    private var local: LocalControllerCandidate?
    private var localAuthorization: SignalCandidateAuthorization?
    private var peer: ControlledSignalCandidate?
    private var quic: NativeQuicDataPlane?
    private var pendingPackets: [(Data, Bool)] = []
    private var selected = false
    private var selectionInProgress = false
    private var quicConnected = false
    private var started = false
    private var closed = false
    private var signalConnected = true
    private var sessionAuthorized = false
    private var candidateStartedEpoch: UInt64?
    private var connectionEpoch: UInt64 = 0

    init(
        descriptor: SessionDescriptor,
        signal: SignalClient,
        router: SignalSessionEventRouter,
        identityStore: DeviceIdentityStore,
        routedEvents: AsyncStream<RoutedSignalSessionEvent>
    ) {
        self.descriptor = descriptor
        self.signal = signal
        self.router = router
        self.identityStore = identityStore
        self.routedEvents = routedEvents
        var captured: AsyncThrowingStream<NativeSecureTransportEvent, Error>.Continuation!
        events = AsyncThrowingStream { captured = $0 }
        continuation = captured
    }

    func start(descriptor: SessionDescriptor, connectionEpoch: UInt64) async throws {
        guard descriptor == self.descriptor, !closed, connectionEpoch > 0 else {
            throw SignalNativeTransportError.invalidState
        }
        if self.connectionEpoch == connectionEpoch { return }
        guard connectionEpoch > self.connectionEpoch else {
            throw SignalNativeTransportError.invalidState
        }
        resetAttempt()
        started = true
        self.connectionEpoch = connectionEpoch
        if routedEventsTask == nil {
            let routedEvents = self.routedEvents
            routedEventsTask = Task { [weak self] in
                for await event in routedEvents {
                    guard !Task.isCancelled else { return }
                    await self?.handle(event)
                }
            }
        }
        if sessionAuthorized, signalConnected {
            try await beginCandidateGatheringIfNeeded(epoch: connectionEpoch)
        }
    }

    func sendKeyExchange(_ message: Data) async throws {
        try requireStarted()
        guard selected else { throw SignalNativeTransportError.invalidState }
        try await signal.sendSessionMessage(
            kind: .keyExchangeMessage,
            sessionID: descriptor.sessionID,
            payload: message
        )
    }

    func sendKeyConfirm(_ message: Data) async throws {
        try requireStarted()
        guard selected else { throw SignalNativeTransportError.invalidState }
        try await signal.sendSessionMessage(
            kind: .keyConfirm,
            sessionID: descriptor.sessionID,
            payload: message
        )
    }

    func sendSecurePacket(_ packet: Data, realtime: Bool) async throws {
        try requireStarted()
        guard let quic else { throw SignalNativeTransportError.quicNotConnected }
        if !quicConnected {
            guard pendingPackets.count < 64 else { throw SignalNativeTransportError.quicNotConnected }
            pendingPackets.append((packet, realtime))
            return
        }
        try quic.send(packet, realtime: realtime)
    }

    func secureSessionDidBecomeReady(session: NativeControllerSession) async throws {
        guard started, !closed, selected,
              let local, let peer, quic == nil else {
            throw SignalNativeTransportError.invalidState
        }
        let plane = try NativeQuicDataPlane(session: session)
        try local.socket.withDescriptor { descriptor in
            try plane.bind(
                socketFD: descriptor,
                peerCertificateDER: peer.transportCertificateDER
            )
        }
        local.socket.close()
        try plane.connect(
            remoteEndpoint: peer.candidate.endpoint,
            serverName: peer.serverName
        )
        quic = plane
        consumeQuicEvents(plane.events)
    }

    func close(reason: String) async {
        guard !closed else { return }
        closed = true
        routedEventsTask?.cancel()
        routedEventsTask = nil
        quicEventsTask?.cancel()
        quicEventsTask = nil
        quic?.close()
        quic = nil
        local?.socket.close()
        local = nil
        pendingPackets.removeAll()
        await router.remove(sessionID: descriptor.sessionID)
        continuation.finish()
    }

    private func makeLocalCandidate() throws -> LocalControllerCandidate {
        let identity = try identityStore.loadOrCreate()
        guard identity.deviceID == descriptor.controllerDeviceID else {
            throw SignalNativeTransportError.peerMismatch
        }
        let socket = try DarwinLANCandidateSocket.open()
        do {
            let unsigned = SignalConnectionCandidate(
                candidateID: String(repeating: "0", count: 32),
                sessionID: descriptor.sessionID,
                deviceID: descriptor.controllerDeviceID,
                role: .controller,
                kind: .lanDirect,
                endpoint: socket.endpoint,
                source: .localInterface
            )
            let candidate = SignalConnectionCandidate(
                candidateID: try unsigned.computedCandidateID(),
                sessionID: unsigned.sessionID,
                deviceID: unsigned.deviceID,
                role: unsigned.role,
                kind: unsigned.kind,
                endpoint: unsigned.endpoint,
                source: unsigned.source
            )
            let timestamp = try nowEpochMillis()
            let interfaceNameHash = Array(SHA256.hash(data: Data(socket.interface.name.utf8)))
            let interfaceIndexHash = Array(SHA256.hash(
                data: Data(String(socket.interface.index).utf8)
            ))
            var socketNonce = try Self.randomBytes(count: 32)
            if socketNonce.allSatisfy({ $0 == 0 }) { socketNonce[0] = 1 }
            let claimHash = Data(try SignalCandidateCanonical.localInterfaceClaimHash(
                sessionID: descriptor.sessionID,
                deviceID: descriptor.controllerDeviceID,
                role: .controller,
                candidateID: candidate.candidateID,
                endpoint: candidate.endpoint,
                interfaceNameHash: interfaceNameHash,
                interfaceIndexHash: interfaceIndexHash,
                localSocketNonce: socketNonce,
                timestampEpochMillis: timestamp
            ))
            let request = SignalCandidateTokenRequest(
                sessionID: descriptor.sessionID,
                deviceID: descriptor.controllerDeviceID,
                role: .controller,
                candidateID: candidate.candidateID,
                kind: .lanDirect,
                endpoint: candidate.endpoint,
                source: .localInterface,
                localInterfaceClaimHash: Array(claimHash),
                localInterfaceSignature: Array(try identityStore.sign(digest: claimHash)),
                interfaceNameHash: interfaceNameHash,
                interfaceIndexHash: interfaceIndexHash,
                localSocketNonce: socketNonce,
                timestampEpochMillis: timestamp,
                requestedTTLMillis: 30_000
            )
            return LocalControllerCandidate(
                socket: socket,
                candidate: candidate,
                tokenRequest: request
            )
        } catch {
            socket.close()
            throw error
        }
    }

    private func handle(_ event: RoutedSignalSessionEvent) async {
        guard !closed else { return }
        do {
            switch event {
            case let .candidateToken(token):
                try await handleCandidateToken(token)
            case let .message(message):
                try await handleMessage(message)
            case let .state(state, _):
                if state == "accepted" || state == "unattended_verified" {
                    sessionAuthorized = true
                    try await beginCandidateGatheringIfNeeded(epoch: connectionEpoch)
                } else if Self.terminalSessionStates.contains(state) {
                    sessionAuthorized = false
                    started = false
                    resetAttempt()
                    continuation.yield(.closed)
                }
            case let .connectionLost(reason):
                signalConnected = false
                resetAttempt()
                continuation.yield(.disconnected(recoverable: true, reason: reason))
            case .connectionRestored:
                signalConnected = true
                try await beginCandidateGatheringIfNeeded(epoch: connectionEpoch)
            }
        } catch {
            continuation.finish(throwing: error)
        }
    }

    private func handleCandidateToken(_ token: SignalCandidateTokenIssued) async throws {
        guard token.sessionID == descriptor.sessionID,
              token.deviceID == descriptor.controllerDeviceID,
              token.role == .controller else {
            throw SignalNativeTransportError.candidateTokenMismatch
        }
        guard let local, token.candidateID == local.candidate.candidateID else { return }
        let authorization = SignalCandidateAuthorization(
            candidateToken: token.candidateToken,
            candidateTokenBindingHash: token.candidateTokenBindingHash,
            expiresAtEpochMillis: token.expiresAtEpochMillis
        )
        try authorization.validate(
            candidate: local.candidate,
            nowEpochMillis: try nowEpochMillis()
        )
        guard localAuthorization == nil else { return }
        localAuthorization = authorization
        try await signal.sendSessionMessage(
            kind: .connectionCandidate,
            sessionID: descriptor.sessionID,
            payload: try SignalCandidateEnvelopeCodec.encodeController(
                candidate: local.candidate,
                authorization: authorization
            )
        )
        try await selectPathIfReady()
    }

    private func handleMessage(_ message: SignalSessionMessage) async throws {
        guard message.sessionID == descriptor.sessionID,
              message.role == .controlled,
              message.fromDeviceID == descriptor.controlledDeviceID else {
            throw SignalNativeTransportError.peerMismatch
        }
        switch message.kind {
        case .connectionCandidate:
            peer = try SignalCandidateEnvelopeCodec.decodeControlled(
                message.payload,
                descriptor: descriptor,
                nowEpochMillis: try nowEpochMillis()
            )
            try await selectPathIfReady()
        case .keyExchangeMessage:
            guard selected else { throw SignalNativeTransportError.invalidState }
            continuation.yield(.peerKeyExchange(
                message: message.payload,
                authoritativeDevicePublicKey: try await signal.authoritativePublicKey(
                    for: descriptor.controlledDeviceID
                )
            ))
        case .keyConfirm:
            guard selected else { throw SignalNativeTransportError.invalidState }
            continuation.yield(.peerKeyConfirm(message.payload))
        }
    }

    private func beginCandidateGatheringIfNeeded(epoch: UInt64) async throws {
        guard started,
              !closed,
              signalConnected,
              sessionAuthorized,
              connectionEpoch == epoch,
              candidateStartedEpoch != epoch else { return }
        candidateStartedEpoch = epoch
        let local = try makeLocalCandidate()
        guard started, !closed, connectionEpoch == epoch else {
            local.socket.close()
            return
        }
        self.local = local
        do {
            try await signal.requestCandidateToken(local.tokenRequest)
        } catch {
            guard started,
                  !closed,
                  connectionEpoch == epoch,
                  self.local?.candidate.candidateID == local.candidate.candidateID else { return }
            candidateStartedEpoch = nil
            self.local?.socket.close()
            self.local = nil
            throw error
        }
    }

    private func selectPathIfReady() async throws {
        guard !selected,
              !selectionInProgress,
              let local,
              localAuthorization != nil,
              let peer else { return }
        guard peer.candidate.kind == local.candidate.kind else {
            throw SignalNativeTransportError.peerMismatch
        }
        selectionInProgress = true
        let attemptEpoch = connectionEpoch
        let localCandidateID = local.candidate.candidateID
        do {
            try await local.socket.probe(peer)
        } catch {
            guard !closed,
                  connectionEpoch == attemptEpoch,
                  self.local?.candidate.candidateID == localCandidateID else { return }
            selectionInProgress = false
            throw error
        }
        guard started,
              !closed,
              !selected,
              connectionEpoch == attemptEpoch,
              self.local?.candidate.candidateID == localCandidateID else {
            return
        }
        selectionInProgress = false
        let pairID = try SignalCandidateEnvelopeCodec.candidatePairID(
            sessionID: descriptor.sessionID,
            controllerCandidateID: local.candidate.candidateID,
            controlledCandidateID: peer.candidate.candidateID,
            selectedTransportPath: peer.candidate.kind,
            relayNodeID: peer.candidate.relayNodeID
        )
        selected = true
        continuation.yield(.transportSelected(NativeTransportSelection(
            protocolVersion: ProtocolConstants.version,
            path: peer.candidate.kind,
            candidatePairID: pairID,
            relayNodeID: peer.candidate.relayNodeID
        )))
    }

    private func consumeQuicEvents(_ events: AsyncStream<NativeQuicDataPlaneEvent>) {
        quicEventsTask?.cancel()
        quicEventsTask = Task { [weak self] in
            for await event in events {
                guard !Task.isCancelled else { return }
                await self?.handleQuic(event)
            }
        }
    }

    private func handleQuic(_ event: NativeQuicDataPlaneEvent) {
        guard !closed else { return }
        do {
            switch event {
            case let .state(state, _):
                guard state == REMOTE_QUIC_STATE_CONNECTED.rawValue else { return }
                quicConnected = true
                let queued = pendingPackets
                pendingPackets.removeAll()
                guard let quic else { throw SignalNativeTransportError.quicNotConnected }
                for (packet, realtime) in queued {
                    try quic.send(packet, realtime: realtime)
                }
            case let .secureVideoFrame(infoPacket, dataPacket):
                continuation.yield(.secureVideoFrame(
                    infoPacket: infoPacket,
                    dataPacket: dataPacket
                ))
            case let .disconnected(recoverable, reason):
                quicConnected = false
                continuation.yield(.disconnected(recoverable: recoverable, reason: reason))
            case .closed:
                quicConnected = false
                continuation.yield(.closed)
            }
        } catch {
            continuation.finish(throwing: error)
        }
    }

    private func resetAttempt() {
        quicEventsTask?.cancel()
        quicEventsTask = nil
        quic?.close()
        quic = nil
        local?.socket.close()
        local = nil
        localAuthorization = nil
        peer = nil
        pendingPackets.removeAll()
        selected = false
        selectionInProgress = false
        quicConnected = false
        candidateStartedEpoch = nil
    }

    private func requireStarted() throws {
        guard started, !closed else { throw SignalNativeTransportError.invalidState }
    }

    private func nowEpochMillis() throws -> UInt64 {
        guard let value = UInt64(exactly: Date.now.epochMillis),
              value < UInt64(descriptor.expiresAtEpochMillis) else {
            throw SignalNativeTransportError.invalidState
        }
        return value
    }

    private static func randomBytes(count: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw SignalNativeTransportError.invalidState
        }
        return bytes
    }

    private static let terminalSessionStates: Set<String> = [
        "cancelled", "closed", "rejected", "failed"
    ]
}

private extension Data {
    init?(uuid: UUID) {
        var value = uuid.uuid
        self = withUnsafeBytes(of: &value) { Data($0) }
    }

    init?(lowerHex128 value: String) {
        guard SignalConnectionCandidate.isLowerHex128(value) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        var index = value.startIndex
        for _ in 0..<16 {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

private func integer<T: FixedWidthInteger>(_ value: T) -> Data {
    var bigEndian = value.bigEndian
    return Data(bytes: &bigEndian, count: MemoryLayout<T>.size)
}

private func randomBytes(count: Int) throws -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
        throw SignalNativeTransportError.invalidState
    }
    return bytes
}
#endif
