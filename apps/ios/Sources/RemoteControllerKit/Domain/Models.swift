import Foundation

public enum ProtocolConstants {
    public static let version: UInt16 = 1
    public static let supportedVersions: [UInt16] = [1]
    public static let minimumVersion: UInt16 = 1
}

public enum PlatformKind: String, Codable, CaseIterable, Sendable {
    case windows
    case ubuntu
    case ios
}

public enum DeviceStatus: String, Codable, Sendable {
    case online
    case offline
    case busy
    case disabled
    case unknown

    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        self = DeviceStatus(rawValue: value) ?? .unknown
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct RoleCapabilities: Codable, Equatable, Sendable {
    public let controller: Bool
    public let controlled: Bool
    public let fileTransfer: Bool
    public let unattended: Bool

    public init(controller: Bool, controlled: Bool, fileTransfer: Bool, unattended: Bool) {
        self.controller = controller
        self.controlled = controlled
        self.fileTransfer = fileTransfer
        self.unattended = unattended
    }

    public static let iosControllerOnly = RoleCapabilities(
        controller: true,
        controlled: false,
        fileTransfer: true,
        unattended: false
    )

    private enum CodingKeys: String, CodingKey {
        case controller
        case controlled
        case fileTransfer = "file_transfer"
        case unattended
    }
}

public struct DeviceSummary: Codable, Identifiable, Equatable, Sendable {
    public let deviceID: String
    public let displayName: String
    public let platform: PlatformKind
    public let osVersion: String?
    public let status: DeviceStatus
    public let roleCapabilities: RoleCapabilities
    public let lastSeenEpochMillis: Int64?
    public let publicKeyID: String?
    public let publicKeyVersion: UInt32?

    public var id: String { deviceID }
    public var canBeControlled: Bool { roleCapabilities.controlled }

    public init(
        deviceID: String,
        displayName: String,
        platform: PlatformKind,
        osVersion: String? = nil,
        status: DeviceStatus,
        roleCapabilities: RoleCapabilities,
        lastSeenEpochMillis: Int64? = nil,
        publicKeyID: String? = nil,
        publicKeyVersion: UInt32? = nil
    ) {
        self.deviceID = deviceID
        self.displayName = displayName
        self.platform = platform
        self.osVersion = osVersion
        self.status = status
        self.roleCapabilities = roleCapabilities
        self.lastSeenEpochMillis = lastSeenEpochMillis
        self.publicKeyID = publicKeyID
        self.publicKeyVersion = publicKeyVersion
    }

    private enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case displayName = "display_name"
        case platform
        case osVersion = "os_version"
        case status
        case roleCapabilities = "role_capabilities"
        case lastSeenEpochMillis = "last_seen_epoch_millis"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
    }
}

public struct TokenSet: Codable, Equatable, Sendable {
    public let accountID: String
    public let accessToken: String
    public let refreshToken: String
    public let accessTokenExpiresAtEpochMillis: Int64
    public let refreshTokenExpiresAtEpochMillis: Int64

    public var accessTokenIsValid: Bool {
        accessTokenExpiresAtEpochMillis > Date.now.epochMillis + 30_000
    }

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case accessTokenExpiresAtEpochMillis = "access_token_expires_at_epoch_millis"
        case refreshTokenExpiresAtEpochMillis = "refresh_token_expires_at_epoch_millis"
    }

    public init(
        accountID: String,
        accessToken: String,
        refreshToken: String,
        accessTokenExpiresAtEpochMillis: Int64,
        refreshTokenExpiresAtEpochMillis: Int64
    ) {
        self.accountID = accountID
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.accessTokenExpiresAtEpochMillis = accessTokenExpiresAtEpochMillis
        self.refreshTokenExpiresAtEpochMillis = refreshTokenExpiresAtEpochMillis
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        accountID = try values.decode(String.self, forKey: .accountID)
        accessToken = try values.decode(String.self, forKey: .accessToken)
        refreshToken = try values.decode(String.self, forKey: .refreshToken)
        accessTokenExpiresAtEpochMillis = try values.decode(
            Int64.self,
            forKey: .accessTokenExpiresAtEpochMillis
        )
        refreshTokenExpiresAtEpochMillis = try values.decode(
            Int64.self,
            forKey: .refreshTokenExpiresAtEpochMillis
        )
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(accountID, forKey: .accountID)
        try values.encode(accessToken, forKey: .accessToken)
        try values.encode(refreshToken, forKey: .refreshToken)
        try values.encode(accessTokenExpiresAtEpochMillis, forKey: .accessTokenExpiresAtEpochMillis)
        try values.encode(refreshTokenExpiresAtEpochMillis, forKey: .refreshTokenExpiresAtEpochMillis)
    }
}

public struct LoginRequest: Encodable, Sendable {
    public let email: String
    public let password: String
    public let protocolVersion: UInt16

    public init(email: String, password: String) {
        self.email = email
        self.password = password
        protocolVersion = ProtocolConstants.version
    }

    private enum CodingKeys: String, CodingKey {
        case email
        case password
        case protocolVersion = "protocol_version"
    }
}

public struct MFAChallenge: Codable, Identifiable, Equatable, Sendable {
    public let mfaChallengeID: String
    public let allowedFactors: [String]
    public let expiresAtEpochMillis: Int64
    public let attemptsRemaining: Int?

    public var id: String { mfaChallengeID }

    private enum CodingKeys: String, CodingKey {
        case mfaChallengeID = "mfa_challenge_id"
        case allowedFactors = "allowed_factors"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case attemptsRemaining = "attempts_remaining"
    }
}

public struct LoginResponse: Decodable, Sendable {
    public let accountID: String?
    public let accessToken: String?
    public let refreshToken: String?
    public let accessTokenExpiresAtEpochMillis: Int64?
    public let refreshTokenExpiresAtEpochMillis: Int64?
    public let mfaRequired: Bool?
    public let mfaChallengeID: String?
    public let allowedFactors: [String]?
    public let expiresAtEpochMillis: Int64?
    public let attemptsRemaining: Int?

    private enum CodingKeys: String, CodingKey {
        case code
        case accountID = "account_id"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case accessTokenExpiresAtEpochMillis = "access_token_expires_at_epoch_millis"
        case refreshTokenExpiresAtEpochMillis = "refresh_token_expires_at_epoch_millis"
        case mfaRequired = "mfa_required"
        case mfaChallengeID = "mfa_challenge_id"
        case factors
        case allowedFactors = "allowed_factors"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case attemptsRemaining = "attempts_remaining"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let responseCode = try values.decodeIfPresent(String.self, forKey: .code)
        accountID = try values.decodeIfPresent(String.self, forKey: .accountID)
        accessToken = try values.decodeIfPresent(String.self, forKey: .accessToken)
        refreshToken = try values.decodeIfPresent(String.self, forKey: .refreshToken)
        accessTokenExpiresAtEpochMillis = try values.decodeIfPresent(
            Int64.self,
            forKey: .accessTokenExpiresAtEpochMillis
        )
        refreshTokenExpiresAtEpochMillis = try values.decodeIfPresent(
            Int64.self,
            forKey: .refreshTokenExpiresAtEpochMillis
        )
        mfaRequired = try values.decodeIfPresent(Bool.self, forKey: .mfaRequired)
            ?? (responseCode == "mfa_required")
        mfaChallengeID = try values.decodeIfPresent(String.self, forKey: .mfaChallengeID)
        allowedFactors = try values.decodeIfPresent([String].self, forKey: .allowedFactors)
            ?? values.decodeIfPresent([String].self, forKey: .factors)
        expiresAtEpochMillis = try values.decodeIfPresent(Int64.self, forKey: .expiresAtEpochMillis)
        attemptsRemaining = try values.decodeIfPresent(Int.self, forKey: .attemptsRemaining)
    }

    public var tokenSet: TokenSet? {
        guard let accountID,
              let accessToken,
              let refreshToken,
              let accessTokenExpiresAtEpochMillis,
              let refreshTokenExpiresAtEpochMillis else {
            return nil
        }
        return TokenSet(
            accountID: accountID,
            accessToken: accessToken,
            refreshToken: refreshToken,
            accessTokenExpiresAtEpochMillis: accessTokenExpiresAtEpochMillis,
            refreshTokenExpiresAtEpochMillis: refreshTokenExpiresAtEpochMillis
        )
    }

    public var challenge: MFAChallenge? {
        guard mfaRequired == true,
              let mfaChallengeID,
              let expiresAtEpochMillis else {
            return nil
        }
        return MFAChallenge(
            mfaChallengeID: mfaChallengeID,
            allowedFactors: allowedFactors ?? ["totp", "recovery_code"],
            expiresAtEpochMillis: expiresAtEpochMillis,
            attemptsRemaining: attemptsRemaining
        )
    }
}

public struct MFAVerifyRequest: Encodable, Sendable {
    public let mfaChallengeID: String
    public let factor: String
    public let code: String

    public init(challengeID: String, factor: String, code: String) {
        mfaChallengeID = challengeID
        self.factor = factor
        self.code = code
    }

    private enum CodingKeys: String, CodingKey {
        case mfaChallengeID = "mfa_challenge_id"
        case factor
        case code
    }
}

public struct DeviceRegistrationRequest: Encodable, Sendable {
    public let deviceID: String
    public let platform: PlatformKind
    public let displayName: String
    public let osVersion: String
    public let arch: String
    public let publicKey: String
    public let roleCapabilities: RoleCapabilities

    public init(
        deviceID: String,
        platform: PlatformKind,
        displayName: String,
        osVersion: String,
        arch: String,
        publicKey: String,
        roleCapabilities: RoleCapabilities
    ) {
        self.deviceID = deviceID
        self.platform = platform
        self.displayName = displayName
        self.osVersion = osVersion
        self.arch = arch
        self.publicKey = publicKey
        self.roleCapabilities = roleCapabilities
    }

    private enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case platform
        case displayName = "display_name"
        case osVersion = "os_version"
        case arch
        case publicKey = "public_key"
        case roleCapabilities = "role_capabilities"
    }
}

public struct DeviceRegistrationResponse: Decodable, Sendable {
    public let deviceID: String
    public let publicKeyID: String
    public let publicKeyVersion: UInt32

    private enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
    }
}

public enum SessionAuthMethod: String, Codable, Sendable {
    case accountPrompt = "account_prompt"
    case temporaryCode = "temporary_code"
    case unattended
}

public struct SessionCreateRequest: Encodable, Sendable {
    public let controllerDeviceID: String
    public let controlledDeviceID: String
    public let authMethod: SessionAuthMethod
    public let requestedPermissions: SessionPermissions
    public let idempotencyKey: UUID

    public init(
        controllerDeviceID: String,
        controlledDeviceID: String,
        authMethod: SessionAuthMethod,
        requestedPermissions: SessionPermissions,
        idempotencyKey: UUID
    ) {
        self.controllerDeviceID = controllerDeviceID
        self.controlledDeviceID = controlledDeviceID
        self.authMethod = authMethod
        self.requestedPermissions = requestedPermissions
        self.idempotencyKey = idempotencyKey
    }

    private enum CodingKeys: String, CodingKey {
        case controllerDeviceID = "controller_device_id"
        case controlledDeviceID = "controlled_device_id"
        case authMethod = "auth_method"
        case requestedPermissions = "requested_permissions"
        case idempotencyKey = "idempotency_key"
    }
}

public struct SessionCreateResponse: Decodable, Sendable {
    public let sessionID: UUID
    public let status: String
    public let controlledDeviceID: String
    public let controlledDeviceName: String?
    public let permissions: SessionPermissions?
    public let permissionsDigest: String?
    public let sessionExpiresAtEpochMillis: Int64?
    public let codeID: String?
    public let codeChallenge: String?
    public let serverNonce: String?

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case status
        case controlledDeviceID = "controlled_device_id"
        case controlledDeviceName = "controlled_device_name"
        case permissions
        case permissionsDigest = "permissions_digest"
        case sessionExpiresAtEpochMillis = "session_expires_at_epoch_millis"
        case codeID = "code_id"
        case codeChallenge = "code_challenge"
        case serverNonce = "server_nonce"
    }
}

public struct SessionPermissions: Codable, Equatable, Sendable {
    public let remoteDesktop: Bool
    public let inputControl: Bool
    public let clipboard: Bool
    public let fileTransfer: Bool
    public let unattended: Bool
    public let privacyScreen: Bool
    public let blockLocalInput: Bool
    public let requirePrompt: Bool
    public let allowRelay: Bool

    public static let requestedControllerDefaults = SessionPermissions(
        remoteDesktop: true,
        inputControl: true,
        clipboard: false,
        fileTransfer: false,
        unattended: false,
        privacyScreen: false,
        blockLocalInput: false,
        requirePrompt: true,
        allowRelay: true
    )

    public init(
        remoteDesktop: Bool,
        inputControl: Bool,
        clipboard: Bool,
        fileTransfer: Bool,
        unattended: Bool,
        privacyScreen: Bool,
        blockLocalInput: Bool,
        requirePrompt: Bool,
        allowRelay: Bool
    ) {
        self.remoteDesktop = remoteDesktop
        self.inputControl = inputControl
        self.clipboard = clipboard
        self.fileTransfer = fileTransfer
        self.unattended = unattended
        self.privacyScreen = privacyScreen
        self.blockLocalInput = blockLocalInput
        self.requirePrompt = requirePrompt
        self.allowRelay = allowRelay
    }

    private enum CodingKeys: String, CodingKey {
        case remoteDesktop = "remote_desktop"
        case inputControl = "input_control"
        case clipboard
        case fileTransfer = "file_transfer"
        case unattended
        case privacyScreen = "privacy_screen"
        case blockLocalInput = "block_local_input"
        case requirePrompt = "require_prompt"
        case allowRelay = "allow_relay"
    }
}

public struct SessionDescriptor: Identifiable, Equatable, Sendable {
    public let sessionID: UUID
    public let accountID: String
    public let controllerDeviceID: String
    public let controlledDeviceID: String
    public let controlledDeviceName: String
    public let permissions: SessionPermissions
    public let permissionsDigest: Data
    public let expiresAtEpochMillis: Int64

    public var id: UUID { sessionID }
}

public enum SessionLifecycleState: Equatable, Sendable {
    case idle
    case waitingForApproval
    case connecting
    case establishingSecureSession
    case connected
    case degraded(String)
    case reconnecting
    case closing
    case closed
    case failed(String)
}

public enum TransportPath: String, Codable, Sendable {
    case lanDirect = "lan_direct"
    case udpP2P = "udp_p2p"
    case quicRelay = "quic_relay"
    case tls443Relay = "tls_443_relay"
}

public enum MediaQualityProfile: String, Codable, CaseIterable, Identifiable, Sendable {
    case balanced
    case textClear = "text_clear"
    case lowLatency = "low_latency"
    case lowBandwidth = "low_bandwidth"

    public var id: String { rawValue }
}

public enum RemoteInputMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case textFirst = "text_first"
    case physicalKey = "physical_key"

    public var id: String { rawValue }
}

public struct RemoteSessionStats: Equatable, Sendable {
    public var transportPath: TransportPath?
    public var rttMillis: Int = 0
    public var lossPPM: Int = 0
    public var jitterMillis: Int = 0
    public var bitrateKbps: Int = 0
    public var framesPerSecond: Int = 0
    public var codec: String = "H.264"
    public var width: Int = 0
    public var height: Int = 0
    public var decodeMillis: Double = 0
    public var hardwareAcceleration = false
}

public struct DisplayDescriptor: Codable, Identifiable, Equatable, Sendable {
    public let displayID: String
    public let name: String
    public let width: UInt32
    public let height: UInt32
    public let scaleFactor: Double
    public let isPrimary: Bool

    public var id: String { displayID }

    private enum CodingKeys: String, CodingKey {
        case displayID = "display_id"
        case name
        case width
        case height
        case scaleFactor = "scale_factor"
        case isPrimary = "is_primary"
    }
}

public struct DisplayCapabilities: Codable, Equatable, Sendable {
    public let maxDisplays: UInt16
    public let maxWidth: UInt32
    public let maxHeight: UInt32
    public let rotation: Bool
    public let dynamicResize: Bool

    private enum CodingKeys: String, CodingKey {
        case maxDisplays = "max_displays"
        case maxWidth = "max_width"
        case maxHeight = "max_height"
        case rotation
        case dynamicResize = "dynamic_resize"
    }
}

public struct CodecCapabilities: Codable, Equatable, Sendable {
    public let h264: Bool
    public let h265Reserved: Bool
    public let av1Reserved: Bool
    public let maxDecodeWidth: UInt32
    public let maxDecodeHeight: UInt32
    public let maxDecodeFps: UInt32
    public let maxEncodeWidth: UInt32
    public let maxEncodeHeight: UInt32
    public let maxEncodeFps: UInt32
    public let hardwareEncode: Bool
    public let hardwareDecode: Bool
    public let softwareEncode: Bool
    public let softwareDecode: Bool
    public let profiles: [String]
    public let pixelFormats: [String]
    public let colorModes: [String]

    private enum CodingKeys: String, CodingKey {
        case h264
        case h265Reserved = "h265_reserved"
        case av1Reserved = "av1_reserved"
        case maxDecodeWidth = "max_decode_width"
        case maxDecodeHeight = "max_decode_height"
        case maxDecodeFps = "max_decode_fps"
        case maxEncodeWidth = "max_encode_width"
        case maxEncodeHeight = "max_encode_height"
        case maxEncodeFps = "max_encode_fps"
        case hardwareEncode = "hardware_encode"
        case hardwareDecode = "hardware_decode"
        case softwareEncode = "software_encode"
        case softwareDecode = "software_decode"
        case profiles
        case pixelFormats = "pixel_formats"
        case colorModes = "color_modes"
    }
}

public struct InputCapabilities: Codable, Equatable, Sendable {
    public let mouse: Bool
    public let physicalKeyboard: Bool
    public let textCommit: Bool
    public let imeComposition: Bool
    public let touch: Bool
    public let externalPointer: Bool

    private enum CodingKeys: String, CodingKey {
        case mouse
        case physicalKeyboard = "physical_keyboard"
        case textCommit = "text_commit"
        case imeComposition = "ime_composition"
        case touch
        case externalPointer = "external_pointer"
    }
}

public struct TransportCapabilities: Codable, Equatable, Sendable {
    public let lanDirect: Bool
    public let udpP2P: Bool
    public let quicRelay: Bool
    public let tls443Relay: Bool
    public let quicDatagram: Bool
    public let maxDatagramBytes: UInt32

    private enum CodingKeys: String, CodingKey {
        case lanDirect = "lan_direct"
        case udpP2P = "udp_p2p"
        case quicRelay = "quic_relay"
        case tls443Relay = "tls_443_relay"
        case quicDatagram = "quic_datagram"
        case maxDatagramBytes = "max_datagram_bytes"
    }
}

public struct ClientCapabilities: Codable, Equatable, Sendable {
    public let platform: PlatformKind
    public let osVersion: String
    public let arch: String
    public let appVersion: String
    public let protocolVersion: UInt16
    public let roleCapabilities: RoleCapabilities
    public let displayCapabilities: DisplayCapabilities
    public let codecCapabilities: CodecCapabilities
    public let inputCapabilities: InputCapabilities
    public let transportCapabilities: TransportCapabilities

    private enum CodingKeys: String, CodingKey {
        case platform
        case osVersion = "os_version"
        case arch
        case appVersion = "app_version"
        case protocolVersion = "protocol_version"
        case roleCapabilities = "role_capabilities"
        case displayCapabilities = "display_capabilities"
        case codecCapabilities = "codec_capabilities"
        case inputCapabilities = "input_capabilities"
        case transportCapabilities = "transport_capabilities"
    }

    public static func ios(appVersion: String, osVersion: String, arch: String) -> ClientCapabilities {
        ClientCapabilities(
            platform: .ios,
            osVersion: osVersion,
            arch: arch,
            appVersion: appVersion,
            protocolVersion: ProtocolConstants.version,
            roleCapabilities: .iosControllerOnly,
            displayCapabilities: DisplayCapabilities(
                maxDisplays: 8,
                maxWidth: 4096,
                maxHeight: 4096,
                rotation: true,
                dynamicResize: true
            ),
            codecCapabilities: CodecCapabilities(
                h264: true,
                h265Reserved: false,
                av1Reserved: false,
                maxDecodeWidth: 4096,
                maxDecodeHeight: 4096,
                maxDecodeFps: 60,
                maxEncodeWidth: 0,
                maxEncodeHeight: 0,
                maxEncodeFps: 0,
                hardwareEncode: false,
                hardwareDecode: true,
                softwareEncode: false,
                softwareDecode: false,
                profiles: ["baseline", "high", "main"],
                pixelFormats: ["nv12"],
                colorModes: ["yuv420"]
            ),
            inputCapabilities: InputCapabilities(
                mouse: true,
                physicalKeyboard: true,
                textCommit: true,
                imeComposition: true,
                touch: true,
                externalPointer: true
            ),
            transportCapabilities: TransportCapabilities(
                lanDirect: true,
                udpP2P: true,
                quicRelay: true,
                tls443Relay: true,
                quicDatagram: true,
                maxDatagramBytes: 1200
            )
        )
    }
}

public extension Date {
    var epochMillis: Int64 { Int64((timeIntervalSince1970 * 1_000).rounded()) }
}
