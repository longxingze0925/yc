import CryptoKit
import Foundation

public enum SignalSessionContractError: LocalizedError, Equatable {
    case invalidEnvelope
    case invalidCandidate
    case invalidAuthorization
    case invalidTransportIdentity
    case invalidCandidatePair

    public var errorDescription: String? {
        switch self {
        case .invalidEnvelope: return "Signal 候选消息字段不符合协议"
        case .invalidCandidate: return "Signal 候选地址绑定无效"
        case .invalidAuthorization: return "Signal 候选授权无效或已过期"
        case .invalidTransportIdentity: return "单会话 QUIC 证书或服务器名无效"
        case .invalidCandidatePair: return "候选对绑定无效"
        }
    }
}

public struct SignalConnectionCandidate: Codable, Equatable, Sendable {
    public let candidateID: String
    public let sessionID: UUID
    public let deviceID: String
    public let role: SignalSessionRole
    public let kind: TransportPath
    public let endpoint: String
    public let source: SignalCandidateSource
    public let observeResultID: String?
    public let priority: UInt32
    public let rttMillis: UInt32?
    public let lossPPM: UInt32?
    public let jitterMillis: UInt32?
    public let relayNodeID: String?

    public init(
        candidateID: String,
        sessionID: UUID,
        deviceID: String,
        role: SignalSessionRole,
        kind: TransportPath,
        endpoint: String,
        source: SignalCandidateSource,
        observeResultID: String? = nil,
        priority: UInt32 = 0,
        rttMillis: UInt32? = nil,
        lossPPM: UInt32? = nil,
        jitterMillis: UInt32? = nil,
        relayNodeID: String? = nil
    ) {
        self.candidateID = candidateID
        self.sessionID = sessionID
        self.deviceID = deviceID
        self.role = role
        self.kind = kind
        self.endpoint = endpoint
        self.source = source
        self.observeResultID = observeResultID
        self.priority = priority
        self.rttMillis = rttMillis
        self.lossPPM = lossPPM
        self.jitterMillis = jitterMillis
        self.relayNodeID = relayNodeID
    }

    private enum CodingKeys: String, CodingKey {
        case candidateID = "candidate_id"
        case sessionID = "session_id"
        case deviceID = "device_id"
        case role
        case kind
        case endpoint
        case source
        case observeResultID = "observe_result_id"
        case priority
        case rttMillis = "rtt_ms"
        case lossPPM = "loss_ppm"
        case jitterMillis = "jitter_ms"
        case relayNodeID = "relay_node_id"
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(candidateID, forKey: .candidateID)
        try values.encode(sessionID.uuidString.lowercased(), forKey: .sessionID)
        try values.encode(deviceID, forKey: .deviceID)
        try values.encode(role, forKey: .role)
        try values.encode(kind, forKey: .kind)
        try values.encode(endpoint, forKey: .endpoint)
        try values.encode(source, forKey: .source)
        try values.encode(observeResultID, forKey: .observeResultID)
        try values.encode(priority, forKey: .priority)
        try values.encode(rttMillis, forKey: .rttMillis)
        try values.encode(lossPPM, forKey: .lossPPM)
        try values.encode(jitterMillis, forKey: .jitterMillis)
        try values.encode(relayNodeID, forKey: .relayNodeID)
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        candidateID = try values.decode(String.self, forKey: .candidateID)
        let session = try values.decode(String.self, forKey: .sessionID)
        guard let sessionID = UUID(uuidString: session) else {
            throw SignalSessionContractError.invalidCandidate
        }
        self.sessionID = sessionID
        deviceID = try values.decode(String.self, forKey: .deviceID)
        role = try values.decode(SignalSessionRole.self, forKey: .role)
        kind = try values.decode(TransportPath.self, forKey: .kind)
        endpoint = try values.decode(String.self, forKey: .endpoint)
        source = try values.decode(SignalCandidateSource.self, forKey: .source)
        observeResultID = try values.decodeIfPresent(String.self, forKey: .observeResultID)
        priority = try values.decode(UInt32.self, forKey: .priority)
        rttMillis = try values.decodeIfPresent(UInt32.self, forKey: .rttMillis)
        lossPPM = try values.decodeIfPresent(UInt32.self, forKey: .lossPPM)
        jitterMillis = try values.decodeIfPresent(UInt32.self, forKey: .jitterMillis)
        relayNodeID = try values.decodeIfPresent(String.self, forKey: .relayNodeID)
    }

    public func computedCandidateID() throws -> String {
        let canonical = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-candidate-id-v1",
            fields: [
                ("session_id", try ProtocolCanonicalEncoder.uuid(sessionID.uuidString)),
                ("device_id", ProtocolCanonicalEncoder.string(deviceID)),
                ("role", ProtocolCanonicalEncoder.string(role.rawValue)),
                ("kind", ProtocolCanonicalEncoder.string(kind.rawValue)),
                ("endpoint", ProtocolCanonicalEncoder.string(endpoint)),
                ("source", ProtocolCanonicalEncoder.string(source.rawValue)),
                ("relay_node_id", relayNodeID.map(ProtocolCanonicalEncoder.string))
            ]
        )
        return Data(SHA256.hash(data: canonical).prefix(16)).lowercaseHexString
    }

    public func validated(
        sessionID expectedSessionID: UUID,
        deviceID expectedDeviceID: String,
        role expectedRole: SignalSessionRole
    ) throws -> Self {
        let isRelay = kind == .quicRelay || kind == .tls443Relay
        let sourceMatchesPath = (kind == .lanDirect && source == .localInterface)
            || (kind == .udpP2P && source == .udpObserved)
            || (isRelay && source == .relayAllocated)
        guard sessionID == expectedSessionID,
              deviceID == expectedDeviceID,
              role == expectedRole,
              !endpoint.isEmpty,
              sourceMatchesPath,
              isRelay == (relayNodeID != nil),
              (source == .udpObserved) == (observeResultID != nil),
              Self.isLowerHex128(candidateID),
              candidateID == (try computedCandidateID()) else {
            throw SignalSessionContractError.invalidCandidate
        }
        return self
    }

    static func isLowerHex128(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (97...102).contains(byte)
        }
    }
}

public struct SignalCandidateAuthorization: Codable, Equatable, Sendable {
    public let candidateToken: [UInt8]
    public let candidateTokenBindingHash: [UInt8]
    public let expiresAtEpochMillis: UInt64

    public init(
        candidateToken: [UInt8],
        candidateTokenBindingHash: [UInt8],
        expiresAtEpochMillis: UInt64
    ) {
        self.candidateToken = candidateToken
        self.candidateTokenBindingHash = candidateTokenBindingHash
        self.expiresAtEpochMillis = expiresAtEpochMillis
    }

    private enum CodingKeys: String, CodingKey {
        case candidateToken = "candidate_token"
        case candidateTokenBindingHash = "candidate_token_binding_hash"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
    }

    public func validate(
        candidate: SignalConnectionCandidate,
        nowEpochMillis: UInt64
    ) throws {
        guard !candidateToken.isEmpty,
              candidateTokenBindingHash.count == 32,
              expiresAtEpochMillis > nowEpochMillis,
              expiresAtEpochMillis - nowEpochMillis <= 60_000 else {
            throw SignalSessionContractError.invalidAuthorization
        }
        guard try Self.bindingHash(
            candidate: candidate,
            expiresAtEpochMillis: expiresAtEpochMillis
        ) == candidateTokenBindingHash else {
            throw SignalSessionContractError.invalidAuthorization
        }
    }

    public static func bindingHash(
        candidate: SignalConnectionCandidate,
        expiresAtEpochMillis: UInt64
    ) throws -> [UInt8] {
        guard let candidateID = Data(lowerHex128: candidate.candidateID) else {
            throw SignalSessionContractError.invalidAuthorization
        }
        let canonical = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-candidate-token-binding-v1",
            fields: [
                ("session_id", try ProtocolCanonicalEncoder.uuid(candidate.sessionID.uuidString)),
                ("device_id", ProtocolCanonicalEncoder.string(candidate.deviceID)),
                ("role", ProtocolCanonicalEncoder.string(candidate.role.rawValue)),
                ("candidate_id", candidateID),
                ("kind", ProtocolCanonicalEncoder.string(candidate.kind.rawValue)),
                ("endpoint", ProtocolCanonicalEncoder.string(candidate.endpoint)),
                ("source", ProtocolCanonicalEncoder.string(candidate.source.rawValue)),
                ("observe_result_id", candidate.observeResultID.map(ProtocolCanonicalEncoder.string)),
                ("expires_at_epoch_millis", ProtocolCanonicalEncoder.integer(expiresAtEpochMillis))
            ]
        )
        return Array(SHA256.hash(data: canonical))
    }
}

public struct ControlledSignalCandidate: Equatable, Sendable {
    public let candidate: SignalConnectionCandidate
    public let authorization: SignalCandidateAuthorization
    public let transportCertificateDER: Data
    public let serverName: String
}

public enum SignalCandidateCanonical {
    public static func localInterfaceClaimHash(
        sessionID: UUID,
        deviceID: String,
        role: SignalSessionRole,
        candidateID: String,
        endpoint: String,
        interfaceNameHash: [UInt8],
        interfaceIndexHash: [UInt8],
        localSocketNonce: [UInt8],
        timestampEpochMillis: UInt64
    ) throws -> [UInt8] {
        guard !deviceID.isEmpty,
              !endpoint.isEmpty,
              interfaceNameHash.count == 32,
              interfaceIndexHash.count == 32,
              localSocketNonce.count == 32,
              !localSocketNonce.allSatisfy({ $0 == 0 }),
              let candidateID = Data(lowerHex128: candidateID) else {
            throw SignalSessionContractError.invalidCandidate
        }
        let canonical = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-local-interface-claim-v1",
            fields: [
                ("session_id", try ProtocolCanonicalEncoder.uuid(sessionID.uuidString)),
                ("device_id", ProtocolCanonicalEncoder.string(deviceID)),
                ("role", ProtocolCanonicalEncoder.string(role.rawValue)),
                ("candidate_id", candidateID),
                ("endpoint", ProtocolCanonicalEncoder.string(endpoint)),
                ("interface_name_hash", Data(interfaceNameHash)),
                ("interface_index_hash", Data(interfaceIndexHash)),
                ("local_socket_nonce", Data(localSocketNonce)),
                ("timestamp_epoch_millis", ProtocolCanonicalEncoder.integer(timestampEpochMillis))
            ]
        )
        return Array(SHA256.hash(data: canonical))
    }
}

public enum SignalCandidateEnvelopeCodec {
    private struct ControlledWire: Decodable {
        let candidate: SignalConnectionCandidate
        let authorization: SignalCandidateAuthorization
        let transportCertificateDER: String
        let serverName: String

        private enum CodingKeys: String, CodingKey {
            case candidate
            case authorization
            case transportCertificateDER = "transport_certificate_der"
            case serverName = "server_name"
        }
    }

    private struct ControllerWire: Encodable {
        let candidate: SignalConnectionCandidate
        let authorization: SignalCandidateAuthorization
    }

    public static func decodeControlled(
        _ data: Data,
        descriptor: SessionDescriptor,
        nowEpochMillis: UInt64
    ) throws -> ControlledSignalCandidate {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "candidate", "authorization", "transport_certificate_der", "server_name"
              ]) else {
            throw SignalSessionContractError.invalidEnvelope
        }
        let wire: ControlledWire
        do {
            wire = try JSONDecoder().decode(ControlledWire.self, from: data)
        } catch {
            throw SignalSessionContractError.invalidEnvelope
        }
        let candidate = try wire.candidate.validated(
            sessionID: descriptor.sessionID,
            deviceID: descriptor.controlledDeviceID,
            role: .controlled
        )
        try wire.authorization.validate(candidate: candidate, nowEpochMillis: nowEpochMillis)
        guard let certificate = Data(base64URLEncoded: wire.transportCertificateDER),
              !certificate.isEmpty,
              certificate.count <= 16 * 1024,
              isValidServerName(wire.serverName) else {
            throw SignalSessionContractError.invalidTransportIdentity
        }
        return ControlledSignalCandidate(
            candidate: candidate,
            authorization: wire.authorization,
            transportCertificateDER: certificate,
            serverName: wire.serverName
        )
    }

    public static func encodeController(
        candidate: SignalConnectionCandidate,
        authorization: SignalCandidateAuthorization
    ) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(ControllerWire(
            candidate: candidate,
            authorization: authorization
        ))
    }

    public static func candidatePairID(
        sessionID: UUID,
        controllerCandidateID: String,
        controlledCandidateID: String,
        selectedTransportPath: TransportPath,
        relayNodeID: String?
    ) throws -> String {
        let isRelay = selectedTransportPath == .quicRelay || selectedTransportPath == .tls443Relay
        guard SignalConnectionCandidate.isLowerHex128(controllerCandidateID),
              SignalConnectionCandidate.isLowerHex128(controlledCandidateID),
              isRelay == (relayNodeID != nil),
              let controllerID = Data(lowerHex128: controllerCandidateID),
              let controlledID = Data(lowerHex128: controlledCandidateID) else {
            throw SignalSessionContractError.invalidCandidatePair
        }
        let canonical = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-candidate-pair-id-v1",
            fields: [
                ("session_id", try ProtocolCanonicalEncoder.uuid(sessionID.uuidString)),
                ("controller_candidate_id", controllerID),
                ("controlled_candidate_id", controlledID),
                ("selected_transport_path", ProtocolCanonicalEncoder.string(selectedTransportPath.rawValue)),
                ("relay_node_id", relayNodeID.map(ProtocolCanonicalEncoder.string))
            ]
        )
        return Data(SHA256.hash(data: canonical).prefix(16)).lowercaseHexString
    }

    private static func isValidServerName(_ value: String) -> Bool {
        value.utf8.count <= 253
            && value.hasPrefix("rctl-")
            && value.hasSuffix(".invalid")
            && value.utf8.allSatisfy { byte in
                (97...122).contains(byte)
                    || (48...57).contains(byte)
                    || byte == 45
                    || byte == 46
            }
    }
}

public enum RoutedSignalSessionEvent: Sendable {
    case state(state: String, eventID: String?)
    case candidateToken(SignalCandidateTokenIssued)
    case message(SignalSessionMessage)
    case connectionLost(String)
    case connectionRestored
}

public actor SignalSessionEventRouter {
    private struct Subscriber {
        let id: UUID
        let continuation: AsyncStream<RoutedSignalSessionEvent>.Continuation
    }

    private let maximumPendingEventsPerSession: Int
    private var subscribers: [UUID: Subscriber] = [:]
    private var pendingEvents: [UUID: [RoutedSignalSessionEvent]] = [:]

    public init(maximumPendingEventsPerSession: Int = 32) {
        self.maximumPendingEventsPerSession = max(1, maximumPendingEventsPerSession)
    }

    public func events(for sessionID: UUID) -> AsyncStream<RoutedSignalSessionEvent> {
        let subscriptionID = UUID()
        let pair = AsyncStream<RoutedSignalSessionEvent>.makeStream()
        subscribers.removeValue(forKey: sessionID)?.continuation.finish()
        subscribers[sessionID] = Subscriber(id: subscriptionID, continuation: pair.continuation)
        pair.continuation.onTermination = { [weak self] _ in
            Task { await self?.remove(sessionID: sessionID, subscriptionID: subscriptionID) }
        }
        for event in pendingEvents.removeValue(forKey: sessionID) ?? [] {
            pair.continuation.yield(event)
        }
        return pair.stream
    }

    public func route(_ event: SignalEvent) {
        switch event {
        case let .sessionState(sessionID, state, eventID):
            yield(.state(state: state, eventID: eventID), to: sessionID)
        case let .candidateTokenIssued(token):
            yield(.candidateToken(token), to: token.sessionID)
        case let .sessionMessage(message):
            yield(.message(message), to: message.sessionID)
        case let .disconnected(reason):
            broadcast(.connectionLost(reason))
        case .authenticated:
            broadcast(.connectionRestored)
        case let .authenticationFailed(reason):
            broadcast(.connectionLost(reason))
        case .connecting, .onlineDevices:
            break
        }
    }

    public func remove(sessionID: UUID) {
        subscribers.removeValue(forKey: sessionID)?.continuation.finish()
        pendingEvents.removeValue(forKey: sessionID)
    }

    public func removeAll() {
        for subscriber in subscribers.values {
            subscriber.continuation.finish()
        }
        subscribers.removeAll()
        pendingEvents.removeAll()
    }

    private func remove(sessionID: UUID, subscriptionID: UUID) {
        guard subscribers[sessionID]?.id == subscriptionID else { return }
        subscribers.removeValue(forKey: sessionID)
    }

    private func yield(_ event: RoutedSignalSessionEvent, to sessionID: UUID) {
        if let subscriber = subscribers[sessionID] {
            subscriber.continuation.yield(event)
            return
        }
        var events = pendingEvents[sessionID] ?? []
        if events.count == maximumPendingEventsPerSession {
            events.removeFirst()
        }
        events.append(event)
        pendingEvents[sessionID] = events
    }

    private func broadcast(_ event: RoutedSignalSessionEvent) {
        for subscriber in subscribers.values {
            subscriber.continuation.yield(event)
        }
    }
}

private extension Data {
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
