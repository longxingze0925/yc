import CryptoKit
import Foundation
import Security

public enum SignalEvent: Sendable {
    case connecting
    case authenticated(connectionID: String)
    case onlineDevices([SignalOnlineDevice])
    case sessionState(sessionID: UUID, state: String, eventID: String?)
    case candidateTokenIssued(SignalCandidateTokenIssued)
    case sessionMessage(SignalSessionMessage)
    case disconnected(String)
    case authenticationFailed(String)
}

public enum SignalSessionMessageKind: String, Codable, Sendable {
    case connectionCandidate = "connection_candidate"
    case keyExchangeMessage = "key_exchange_message"
    case keyConfirm = "key_confirm"
}

public struct SignalSessionMessage: Sendable, Equatable {
    public let kind: SignalSessionMessageKind
    public let sessionID: UUID
    public let role: SignalSessionRole
    public let fromDeviceID: String
    public let payload: Data
}

private enum SignalJSONValue: Codable, Sendable, Equatable {
    case object([String: SignalJSONValue])
    case array([SignalJSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([SignalJSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: SignalJSONValue].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .object(value): try container.encode(value)
        case let .array(value): try container.encode(value)
        case let .string(value): try container.encode(value)
        case let .number(value): try container.encode(value)
        case let .bool(value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public enum SignalSessionRole: String, Codable, Sendable {
    case controller
    case controlled
}

public enum SignalCandidateSource: String, Codable, Sendable {
    case localInterface = "local_interface"
    case udpObserved = "udp_observed"
    case relayAllocated = "relay_allocated"
}

public struct SignalCandidateTokenRequest: Encodable, Sendable {
    public let sessionID: UUID
    public let deviceID: String
    public let role: SignalSessionRole
    public let candidateID: String
    public let kind: TransportPath
    public let endpoint: String
    public let source: SignalCandidateSource
    public let relayNodeID: String?
    public let observeResultID: String?
    public let observeResultBindingHash: [UInt8]?
    public let localInterfaceClaimHash: [UInt8]?
    public let localInterfaceSignature: [UInt8]?
    public let interfaceNameHash: [UInt8]?
    public let interfaceIndexHash: [UInt8]?
    public let localSocketNonce: [UInt8]?
    public let timestampEpochMillis: UInt64?
    public let requestedTTLMillis: UInt32

    public init(
        sessionID: UUID,
        deviceID: String,
        role: SignalSessionRole,
        candidateID: String,
        kind: TransportPath,
        endpoint: String,
        source: SignalCandidateSource,
        relayNodeID: String? = nil,
        observeResultID: String? = nil,
        observeResultBindingHash: [UInt8]? = nil,
        localInterfaceClaimHash: [UInt8]? = nil,
        localInterfaceSignature: [UInt8]? = nil,
        interfaceNameHash: [UInt8]? = nil,
        interfaceIndexHash: [UInt8]? = nil,
        localSocketNonce: [UInt8]? = nil,
        timestampEpochMillis: UInt64? = nil,
        requestedTTLMillis: UInt32
    ) {
        self.sessionID = sessionID
        self.deviceID = deviceID
        self.role = role
        self.candidateID = candidateID
        self.kind = kind
        self.endpoint = endpoint
        self.source = source
        self.relayNodeID = relayNodeID
        self.observeResultID = observeResultID
        self.observeResultBindingHash = observeResultBindingHash
        self.localInterfaceClaimHash = localInterfaceClaimHash
        self.localInterfaceSignature = localInterfaceSignature
        self.interfaceNameHash = interfaceNameHash
        self.interfaceIndexHash = interfaceIndexHash
        self.localSocketNonce = localSocketNonce
        self.timestampEpochMillis = timestampEpochMillis
        self.requestedTTLMillis = requestedTTLMillis
    }

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case deviceID = "device_id"
        case role
        case candidateID = "candidate_id"
        case kind
        case endpoint
        case source
        case relayNodeID = "relay_node_id"
        case observeResultID = "observe_result_id"
        case observeResultBindingHash = "observe_result_binding_hash"
        case localInterfaceClaimHash = "local_interface_claim_hash"
        case localInterfaceSignature = "local_interface_signature"
        case interfaceNameHash = "interface_name_hash"
        case interfaceIndexHash = "interface_index_hash"
        case localSocketNonce = "local_socket_nonce"
        case timestampEpochMillis = "timestamp_epoch_millis"
        case requestedTTLMillis = "requested_ttl_millis"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sessionID.uuidString.lowercased(), forKey: .sessionID)
        try container.encode(deviceID, forKey: .deviceID)
        try container.encode(role, forKey: .role)
        try container.encode(candidateID, forKey: .candidateID)
        try container.encode(kind, forKey: .kind)
        try container.encode(endpoint, forKey: .endpoint)
        try container.encode(source, forKey: .source)
        try container.encodeIfPresent(relayNodeID, forKey: .relayNodeID)
        try container.encodeIfPresent(observeResultID, forKey: .observeResultID)
        try container.encodeIfPresent(observeResultBindingHash, forKey: .observeResultBindingHash)
        try container.encodeIfPresent(localInterfaceClaimHash, forKey: .localInterfaceClaimHash)
        try container.encodeIfPresent(localInterfaceSignature, forKey: .localInterfaceSignature)
        try container.encodeIfPresent(interfaceNameHash, forKey: .interfaceNameHash)
        try container.encodeIfPresent(interfaceIndexHash, forKey: .interfaceIndexHash)
        try container.encodeIfPresent(localSocketNonce, forKey: .localSocketNonce)
        try container.encodeIfPresent(timestampEpochMillis, forKey: .timestampEpochMillis)
        try container.encode(requestedTTLMillis, forKey: .requestedTTLMillis)
    }
}

public struct SignalCandidateTokenIssued: Decodable, Sendable {
    public let sessionID: UUID
    public let deviceID: String
    public let role: SignalSessionRole
    public let candidateID: String
    public let candidateToken: [UInt8]
    public let candidateTokenBindingHash: [UInt8]
    public let expiresAtEpochMillis: UInt64

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case deviceID = "device_id"
        case role
        case candidateID = "candidate_id"
        case candidateToken = "candidate_token"
        case candidateTokenBindingHash = "candidate_token_binding_hash"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
    }
}

public struct SignalOnlineDevice: Decodable, Equatable, Sendable {
    public let accountID: String
    public let deviceID: String
    public let publicKeyID: String
    public let publicKeyVersion: UInt32
    public let publicKey: String
    public let clientCapabilitiesHash: String
    public let status: DeviceStatus
    public let lastSeenEpochMillis: Int64
    public let connectionID: String

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
        case publicKey = "public_key"
        case clientCapabilitiesHash = "client_capabilities_hash"
        case status
        case lastSeenEpochMillis = "last_seen_epoch_millis"
        case connectionID = "connection_id"
    }
}

struct SignalHelloResponse: Encodable, Sendable {
    let accountID: String
    let deviceID: String
    let clientNonce: String
    let timestamp: UInt64
    let clientSupportedProtocolVersions: [UInt16]
    let clientMinProtocolVersion: UInt16
    let publicKeyID: String
    let publicKeyVersion: UInt32
    let clientSupportedProtocolVersionsHash: String
    let clientCapabilities: ClientCapabilities
    let clientCapabilitiesHash: String
    let deviceSignature: String

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
        case clientNonce = "client_nonce"
        case timestamp
        case clientSupportedProtocolVersions = "client_supported_protocol_versions"
        case clientMinProtocolVersion = "client_min_protocol_version"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
        case clientSupportedProtocolVersionsHash = "client_supported_protocol_versions_hash"
        case clientCapabilities = "client_capabilities"
        case clientCapabilitiesHash = "client_capabilities_hash"
        case deviceSignature = "device_signature"
    }
}

public actor SignalClient {
    public nonisolated let events: AsyncStream<SignalEvent>

    private struct Incoming: Decodable {
        let type: String
        let accountID: String?
        let deviceID: String?
        let protocolVersion: UInt16?
        let serverNonce: String?
        let expiresAtEpochMillis: Int64?
        let serverSupportedProtocolVersions: [UInt16]?
        let connectionID: String?
        let clientSupportedProtocolVersionsHash: String?
        let clientCapabilitiesHash: String?
        let devices: [SignalOnlineDevice]?
        let sessionID: UUID?
        let state: String?
        let status: String?
        let eventID: String?
        let role: SignalSessionRole?
        let fromDeviceID: String?
        let payload: SignalJSONValue?
        let candidateID: String?
        let candidateToken: [UInt8]?
        let candidateTokenBindingHash: [UInt8]?
        let code: String?
        let message: String?

        private enum CodingKeys: String, CodingKey {
            case type
            case accountID = "account_id"
            case deviceID = "device_id"
            case protocolVersion = "protocol_version"
            case serverNonce = "server_nonce"
            case expiresAtEpochMillis = "expires_at_epoch_millis"
            case serverSupportedProtocolVersions = "server_supported_protocol_versions"
            case connectionID = "connection_id"
            case clientSupportedProtocolVersionsHash = "client_supported_protocol_versions_hash"
            case clientCapabilitiesHash = "client_capabilities_hash"
            case devices
            case sessionID = "session_id"
            case state
            case status
            case eventID = "event_id"
            case role
            case fromDeviceID = "from_device_id"
            case payload
            case candidateID = "candidate_id"
            case candidateToken = "candidate_token"
            case candidateTokenBindingHash = "candidate_token_binding_hash"
            case code
            case message
        }
    }

    private struct EmptyPayload: Encodable {}

    private let configuration: ServiceConfiguration
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let continuation: AsyncStream<SignalEvent>.Continuation
    private var connectionLoop: Task<Void, Never>?
    private var socket: URLSessionWebSocketTask?
    private var stopped = true
    private var expectedAccountID: String?
    private var expectedDeviceID: String?
    private var expectedProtocolVersion: UInt16?
    private var expectedServerVersions: [UInt16]?
    private var expectedVersionHash: String?
    private var expectedCapabilitiesHash: String?
    private var onlineDevicesByID: [String: SignalOnlineDevice] = [:]

    public init(configuration: ServiceConfiguration) {
        self.configuration = configuration
        session = PinnedSignalSession.make(fingerprint: configuration.serverPublicKeyFingerprint)
        encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        decoder = JSONDecoder()

        var captured: AsyncStream<SignalEvent>.Continuation!
        events = AsyncStream { captured = $0 }
        continuation = captured
    }

    deinit {
        connectionLoop?.cancel()
        socket?.cancel(with: .goingAway, reason: nil)
        continuation.finish()
    }

    public func start(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities,
        accessTokenProvider: @escaping @Sendable () async throws -> String
    ) throws {
        stop()
        let identity = try identityStore.loadOrCreate()
        guard !accountID.isEmpty,
              identity.publicKeyID != nil,
              identity.publicKeyVersion > 0 else {
            throw APIClientError.authenticationRequired
        }
        stopped = false
        connectionLoop = Task {
            await runConnectionLoop(
                accountID: accountID,
                identityStore: identityStore,
                capabilities: capabilities,
                accessTokenProvider: accessTokenProvider
            )
        }
    }

    public func stop() {
        stopped = true
        connectionLoop?.cancel()
        connectionLoop = nil
        socket?.cancel(with: .normalClosure, reason: nil)
        socket = nil
        onlineDevicesByID.removeAll()
    }

    public func authoritativePublicKey(for deviceID: String) throws -> Data {
        guard !deviceID.isEmpty,
              let device = onlineDevicesByID[deviceID],
              let publicKey = Data(base64URLEncoded: device.publicKey),
              publicKey.count == 32 else {
            throw APIClientError.transport("Signal 在线设备公钥不可用")
        }
        return publicKey
    }

    public func requestOnlineDevices() async throws {
        try await send(type: "list_online_devices", payload: EmptyPayload())
    }

    public func requestCandidateToken(_ request: SignalCandidateTokenRequest) async throws {
        guard request.deviceID == expectedDeviceID,
              request.requestedTTLMillis > 0,
              request.candidateID.count == 32,
              request.candidateID.unicodeScalars.allSatisfy({ scalar in
                  CharacterSet(charactersIn: "0123456789abcdef").contains(scalar)
              }) else {
            throw APIClientError.transport("候选授权请求与当前设备不匹配")
        }
        try await sendEnvelope(type: "request_candidate_token", payload: request)
    }

    public func sendSessionMessage(
        kind: SignalSessionMessageKind,
        sessionID: UUID,
        role: SignalSessionRole = .controller,
        payload: Data
    ) async throws {
        guard role == .controller,
              sessionID.uuidString != "00000000-0000-0000-0000-000000000000",
              !payload.isEmpty,
              payload.count <= 64 * 1024,
              let payloadObject = try JSONSerialization.jsonObject(with: payload) as? [String: Any]
        else {
            throw APIClientError.transport("Signal 会话消息绑定无效")
        }
        try await sendSessionEnvelope(
            kind: kind,
            sessionID: sessionID,
            role: role,
            payloadObject: payloadObject
        )
    }

    private func runConnectionLoop(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities,
        accessTokenProvider: @escaping @Sendable () async throws -> String
    ) async {
        var retryDelay: UInt64 = 1
        while !Task.isCancelled, !stopped {
            do {
                continuation.yield(.connecting)
                let accessToken = try await accessTokenProvider()
                try await connect(accessToken: accessToken)
                retryDelay = 1
                try await receiveLoop(accountID: accountID, identityStore: identityStore, capabilities: capabilities)
            } catch {
                if Task.isCancelled || stopped { return }
                if (error as? APIClientError) == .authenticationRequired {
                    stopped = true
                    continuation.yield(.authenticationFailed(
                        APIClientError.authenticationRequired.localizedDescription
                    ))
                    return
                }
                continuation.yield(.disconnected(error.localizedDescription))
                try? await Task.sleep(nanoseconds: retryDelay * 1_000_000_000)
                retryDelay = min(retryDelay * 2, 30)
            }
        }
    }

    private func connect(accessToken: String) async throws {
        expectedAccountID = nil
        expectedDeviceID = nil
        expectedProtocolVersion = nil
        expectedServerVersions = nil
        expectedVersionHash = nil
        expectedCapabilitiesHash = nil
        var request = URLRequest(url: configuration.signalURL)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(
            ProtocolConstants.supportedVersions.map(String.init).joined(separator: ","),
            forHTTPHeaderField: "X-Rctl-Protocol-Versions"
        )
        request.setValue(
            String(ProtocolConstants.minimumVersion),
            forHTTPHeaderField: "X-Rctl-Min-Protocol-Version"
        )
        let task = session.webSocketTask(with: request)
        socket = task
        task.resume()
    }

    private func receiveLoop(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        guard let socket else { throw APIClientError.transport("Signal 连接不存在") }
        while !Task.isCancelled, !stopped {
            let message = try await socket.receive()
            let data: Data
            switch message {
            case let .data(value): data = value
            case let .string(value): data = Data(value.utf8)
            @unknown default: continue
            }
            let incoming = try decoder.decode(Incoming.self, from: data)
            try await handle(incoming, accountID: accountID, identityStore: identityStore, capabilities: capabilities)
        }
    }

    private func handle(
        _ incoming: Incoming,
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        switch incoming.type {
        case "hello_challenge":
            let identity = try identityStore.loadOrCreate()
            guard incoming.accountID == accountID,
                  incoming.deviceID == nil || incoming.deviceID == identity.deviceID,
                  let protocolVersion = incoming.protocolVersion,
                  ProtocolConstants.supportedVersions.contains(protocolVersion),
                  let serverVersions = incoming.serverSupportedProtocolVersions,
                  serverVersions.contains(protocolVersion),
                  let expiresAt = incoming.expiresAtEpochMillis,
                  expiresAt > Date.now.epochMillis,
                  let encodedServerNonce = incoming.serverNonce,
                  let serverNonce = Data(base64URLEncoded: encodedServerNonce),
                  serverNonce.count == 32 else {
                throw APIClientError.transport("Signal 握手上下文不匹配")
            }
            try await sendHelloResponse(
                accountID: accountID,
                protocolVersion: protocolVersion,
                serverNonce: serverNonce,
                serverSupportedVersions: serverVersions,
                identityStore: identityStore,
                capabilities: capabilities
            )
        case "hello_ok":
            guard incoming.accountID == expectedAccountID,
                  incoming.deviceID == expectedDeviceID,
                  incoming.protocolVersion == expectedProtocolVersion,
                  incoming.clientSupportedProtocolVersionsHash == expectedVersionHash,
                  incoming.clientCapabilitiesHash == expectedCapabilitiesHash,
                  normalizedVersions(incoming.serverSupportedProtocolVersions) == expectedServerVersions,
                  let connectionID = incoming.connectionID else {
                throw APIClientError.transport("Signal 握手回显校验失败")
            }
            continuation.yield(.authenticated(connectionID: connectionID))
            try await requestOnlineDevices()
        case "online_devices":
            let devices = incoming.devices ?? []
            guard devices.allSatisfy({ device in
                Data(base64URLEncoded: device.publicKey)?.count == 32
            }) else {
                throw APIClientError.transport("Signal 在线设备公钥无效")
            }
            onlineDevicesByID = Dictionary(
                devices.map { ($0.deviceID, $0) },
                uniquingKeysWith: { _, latest in latest }
            )
            continuation.yield(.onlineDevices(devices))
        case "connection_state", "session_accept_ack", "session_close_ack", "session_cancel_ack", "session_reject_ack":
            if let sessionID = incoming.sessionID, let state = incoming.status ?? incoming.state {
                continuation.yield(.sessionState(sessionID: sessionID, state: state, eventID: incoming.eventID))
            }
        case "candidate_token_issued":
            guard let sessionID = incoming.sessionID,
                  incoming.deviceID == expectedDeviceID,
                  let deviceID = incoming.deviceID,
                  let role = incoming.role,
                  let candidateID = incoming.candidateID,
                  candidateID.count == 32,
                  candidateID.unicodeScalars.allSatisfy({ scalar in
                      CharacterSet(charactersIn: "0123456789abcdef").contains(scalar)
                  }),
                  let token = incoming.candidateToken,
                  !token.isEmpty,
                  let bindingHash = incoming.candidateTokenBindingHash,
                  bindingHash.count == 32,
                  let expiresAt = incoming.expiresAtEpochMillis,
                  expiresAt > Date.now.epochMillis else {
                throw APIClientError.transport("候选授权响应绑定无效")
            }
            continuation.yield(.candidateTokenIssued(SignalCandidateTokenIssued(
                sessionID: sessionID,
                deviceID: deviceID,
                role: role,
                candidateID: candidateID,
                candidateToken: token,
                candidateTokenBindingHash: bindingHash,
                expiresAtEpochMillis: UInt64(expiresAt)
            )))
        case "connection_candidate", "key_exchange_message", "key_confirm":
            guard let kind = SignalSessionMessageKind(rawValue: incoming.type),
                  let sessionID = incoming.sessionID,
                  sessionID.uuidString != "00000000-0000-0000-0000-000000000000",
                  incoming.role == .controlled,
                  let fromDeviceID = incoming.fromDeviceID,
                  !fromDeviceID.isEmpty,
                  let payload = incoming.payload,
                  case .object = payload else {
                throw APIClientError.transport("Signal 对端会话消息绑定无效")
            }
            let payloadEncoder = JSONEncoder()
            payloadEncoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let payloadData = try payloadEncoder.encode(payload)
            guard !payloadData.isEmpty, payloadData.count <= 64 * 1024 else {
                throw APIClientError.transport("Signal 对端会话消息长度无效")
            }
            continuation.yield(.sessionMessage(SignalSessionMessage(
                kind: kind,
                sessionID: sessionID,
                role: .controlled,
                fromDeviceID: fromDeviceID,
                payload: payloadData
            )))
        case "auth_failed":
            stopped = true
            continuation.yield(.authenticationFailed(incoming.message ?? "Signal 身份验证失败"))
            throw APIClientError.authenticationRequired
        case "error":
            throw APIClientError.server(
                code: incoming.code ?? "signal_error",
                message: incoming.message ?? "Signal 返回错误",
                status: 0
            )
        default:
            break
        }
    }

    private func sendHelloResponse(
        accountID: String,
        protocolVersion: UInt16,
        serverNonce: Data,
        serverSupportedVersions: [UInt16],
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        let identity = try identityStore.loadOrCreate()
        guard let publicKeyID = identity.publicKeyID, identity.publicKeyVersion > 0 else {
            throw APIClientError.authenticationRequired
        }
        let clientNonce = try Self.randomBytes(count: 32)
        guard let timestamp = UInt64(exactly: Date.now.epochMillis) else {
            throw APIClientError.transport("系统时间无效")
        }
        let supportedVersions = Array(Set(ProtocolConstants.supportedVersions)).sorted()
        let versionsHash = try SignalHandshakeCanonical.protocolVersionsHash(
            versions: supportedVersions,
            minimumVersion: ProtocolConstants.minimumVersion
        )
        let capabilitiesHash = try capabilities.canonicalHash()
        let signedCanonical = try SignalHandshakeCanonical.helloSignatureInput(
            serverNonce: serverNonce,
            clientNonce: clientNonce,
            accountID: accountID,
            deviceID: identity.deviceID,
            protocolVersion: protocolVersion,
            timestamp: timestamp,
            versionsHash: versionsHash,
            capabilitiesHash: capabilitiesHash
        )
        let signature = try identityStore.sign(digest: Data(SHA256.hash(data: signedCanonical)))
        expectedAccountID = accountID
        expectedDeviceID = identity.deviceID
        expectedProtocolVersion = protocolVersion
        expectedServerVersions = normalizedVersions(serverSupportedVersions)
        expectedVersionHash = versionsHash.lowercaseHexString
        expectedCapabilitiesHash = capabilitiesHash.lowercaseHexString

        let response = SignalHelloResponse(
            accountID: accountID,
            deviceID: identity.deviceID,
            clientNonce: clientNonce.base64URLEncodedString(),
            timestamp: timestamp,
            clientSupportedProtocolVersions: supportedVersions,
            clientMinProtocolVersion: ProtocolConstants.minimumVersion,
            publicKeyID: publicKeyID,
            publicKeyVersion: identity.publicKeyVersion,
            clientSupportedProtocolVersionsHash: versionsHash.lowercaseHexString,
            clientCapabilities: capabilities,
            clientCapabilitiesHash: capabilitiesHash.lowercaseHexString,
            deviceSignature: signature.base64URLEncodedString()
        )
        try await send(type: "hello_response", payload: response)
    }

    private func send<T: Encodable>(type: String, payload: T) async throws {
        guard let socket else { throw APIClientError.transport("Signal 尚未连接") }
        let payloadData = try encoder.encode(payload)
        guard var object = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw APIClientError.invalidResponse
        }
        object["type"] = type
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard let text = String(data: data, encoding: .utf8) else {
            throw APIClientError.invalidResponse
        }
        try await socket.send(.string(text))
    }

    private func sendEnvelope<T: Encodable>(type: String, payload: T) async throws {
        guard let socket else { throw APIClientError.transport("Signal 尚未连接") }
        let payloadData = try encoder.encode(payload)
        let payloadObject = try JSONSerialization.jsonObject(with: payloadData)
        let data = try JSONSerialization.data(
            withJSONObject: ["type": type, "payload": payloadObject],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard let text = String(data: data, encoding: .utf8) else {
            throw APIClientError.invalidResponse
        }
        try await socket.send(.string(text))
    }

    private func sendSessionEnvelope(
        kind: SignalSessionMessageKind,
        sessionID: UUID,
        role: SignalSessionRole,
        payloadObject: [String: Any]
    ) async throws {
        guard let socket else { throw APIClientError.transport("Signal 尚未连接") }
        let data = try JSONSerialization.data(
            withJSONObject: [
                "type": kind.rawValue,
                "session_id": sessionID.uuidString.lowercased(),
                "role": role.rawValue,
                "payload": payloadObject,
            ],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard let text = String(data: data, encoding: .utf8) else {
            throw APIClientError.invalidResponse
        }
        try await socket.send(.string(text))
    }

    private func normalizedVersions(_ versions: [UInt16]?) -> [UInt16]? {
        versions.map { Array(Set($0)).sorted() }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw APIClientError.transport("无法生成 Signal 握手随机数")
        }
        return Data(bytes)
    }
}

private final class PinnedSignalSession: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let fingerprint: String?
    private init(fingerprint: String?) { self.fingerprint = fingerprint }

    static func make(fingerprint: String?) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = true
        return URLSession(
            configuration: configuration,
            delegate: PinnedSignalSession(fingerprint: fingerprint),
            delegateQueue: nil
        )
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        guard SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        guard let fingerprint else {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        guard let key = SecTrustCopyKey(trust),
              let data = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if actual == fingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
