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
    public let deviceID: String
    public let devicePublicKey: String
    public let publicKeyID: String?
    public let publicKeyVersion: UInt32
    public let clientNonce: String
    public let protocolVersion: UInt16

    public init(email: String, password: String, identity: DeviceIdentity, clientNonce: Data) {
        self.email = email
        self.password = password
        deviceID = identity.deviceID
        devicePublicKey = identity.publicKey.base64URLEncodedString()
        publicKeyID = identity.publicKeyID
        publicKeyVersion = identity.publicKeyVersion
        self.clientNonce = clientNonce.base64URLEncodedString()
        protocolVersion = ProtocolConstants.version
    }

    private enum CodingKeys: String, CodingKey {
        case email
        case password
        case deviceID = "device_id"
        case devicePublicKey = "device_public_key"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
        case clientNonce = "client_nonce"
        case protocolVersion = "protocol_version"
    }
}

public enum LoginDeviceState: String, Decodable, Equatable, Sendable {
    case pendingEnrollment = "pending_enrollment"
    case registered
}

public struct LoginChallenge: Decodable, Sendable {
    public let accountID: String
    public let loginChallengeID: String
    public let loginRequestBindingHash: String
    public let loginChallengeBindingHash: String
    public let serverNonce: String
    public let deviceState: LoginDeviceState
    public let requiredFactors: [String]
    public let expiresAtEpochMillis: Int64
    public let attemptsRemaining: Int
    public let clientNonce: String

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.decode(String.self, forKey: .code) == "login_challenge_required" else {
            throw DecodingError.dataCorruptedError(
                forKey: .code,
                in: values,
                debugDescription: "unexpected login challenge response code"
            )
        }
        guard !values.contains(.accessToken),
              !values.contains(.refreshToken),
              !values.contains(.accessTokenExpiresAtEpochMillis),
              !values.contains(.refreshTokenExpiresAtEpochMillis),
              !values.contains(.deviceEnrollmentGrant),
              !values.contains(.deviceEnrollmentGrantExpiresAtEpochMillis) else {
            throw DecodingError.dataCorruptedError(
                forKey: .code,
                in: values,
                debugDescription: "login challenge response must not contain credentials"
            )
        }
        accountID = try values.decode(String.self, forKey: .accountID)
        loginChallengeID = try values.decode(String.self, forKey: .loginChallengeID)
        loginRequestBindingHash = try values.decode(String.self, forKey: .loginRequestBindingHash)
        loginChallengeBindingHash = try values.decode(String.self, forKey: .loginChallengeBindingHash)
        serverNonce = try values.decode(String.self, forKey: .serverNonce)
        deviceState = try values.decode(LoginDeviceState.self, forKey: .deviceState)
        requiredFactors = try values.decode([String].self, forKey: .requiredFactors)
        expiresAtEpochMillis = try values.decode(Int64.self, forKey: .expiresAtEpochMillis)
        attemptsRemaining = try values.decode(Int.self, forKey: .attemptsRemaining)
        guard !accountID.isEmpty,
              !loginChallengeID.isEmpty,
              Self.isSHA256Hex(loginRequestBindingHash),
              Self.isSHA256Hex(loginChallengeBindingHash),
              Data(base64URLEncoded: serverNonce)?.count == 32,
              Set(requiredFactors).count == requiredFactors.count,
              requiredFactors.allSatisfy({ $0 == "totp" || $0 == "recovery_code" }),
              expiresAtEpochMillis > 0,
              attemptsRemaining > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .loginChallengeID,
                in: values,
                debugDescription: "invalid login challenge contract"
            )
        }
        guard let requestClientNonce = decoder.userInfo[.loginClientNonce] as? String,
              Data(base64URLEncoded: requestClientNonce)?.count == 32 else {
            throw DecodingError.dataCorruptedError(
                forKey: .serverNonce,
                in: values,
                debugDescription: "login challenge is missing its request client nonce"
            )
        }
        clientNonce = requestClientNonce
    }

    public var mfaChallenge: MFAChallenge {
        MFAChallenge(
            mfaChallengeID: loginChallengeID,
            allowedFactors: requiredFactors,
            expiresAtEpochMillis: expiresAtEpochMillis,
            attemptsRemaining: attemptsRemaining
        )
    }

    private enum CodingKeys: String, CodingKey {
        case code
        case accountID = "account_id"
        case loginChallengeID = "login_challenge_id"
        case loginRequestBindingHash = "login_request_binding_hash"
        case loginChallengeBindingHash = "login_challenge_binding_hash"
        case serverNonce = "server_nonce"
        case deviceState = "device_state"
        case requiredFactors = "required_factors"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case attemptsRemaining = "attempts_remaining"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case accessTokenExpiresAtEpochMillis = "access_token_expires_at_epoch_millis"
        case refreshTokenExpiresAtEpochMillis = "refresh_token_expires_at_epoch_millis"
        case deviceEnrollmentGrant = "device_enrollment_grant"
        case deviceEnrollmentGrantExpiresAtEpochMillis = "device_enrollment_grant_expires_at_epoch_millis"
    }

    private static func isSHA256Hex(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
        }
    }
}

public extension CodingUserInfoKey {
    static let loginClientNonce = CodingUserInfoKey(rawValue: "rctl.login_client_nonce")!
}

public struct MFAChallenge: Codable, Identifiable, Equatable, Sendable {
    public let mfaChallengeID: String
    public let allowedFactors: [String]
    public let expiresAtEpochMillis: Int64
    public let attemptsRemaining: Int?

    public var id: String { mfaChallengeID }

    public init(
        mfaChallengeID: String,
        allowedFactors: [String],
        expiresAtEpochMillis: Int64,
        attemptsRemaining: Int?
    ) {
        self.mfaChallengeID = mfaChallengeID
        self.allowedFactors = allowedFactors
        self.expiresAtEpochMillis = expiresAtEpochMillis
        self.attemptsRemaining = attemptsRemaining
    }

    private enum CodingKeys: String, CodingKey {
        case mfaChallengeID = "mfa_challenge_id"
        case allowedFactors = "allowed_factors"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case attemptsRemaining = "attempts_remaining"
    }
}

public struct TOTPEnrollmentStartRequest: Encodable, Sendable {
    public let recoveryDeliveryPublicKey: String

    public init(recoveryDeliveryPublicKey: String) throws {
        guard Data(base64URLEncoded: recoveryDeliveryPublicKey)?.count == 32 else {
            throw EncodingError.invalidValue(
                recoveryDeliveryPublicKey,
                EncodingError.Context(
                    codingPath: [],
                    debugDescription: "recovery delivery public key must be 32 base64url bytes"
                )
            )
        }
        self.recoveryDeliveryPublicKey = recoveryDeliveryPublicKey
    }

    private enum CodingKeys: String, CodingKey {
        case recoveryDeliveryPublicKey = "recovery_delivery_public_key"
    }
}

public struct TOTPEnrollmentStartResponse: Decodable, Equatable, Sendable {
    public let factorID: String
    public let secretBase32: String
    public let otpauthURI: String
    public let expiresInSeconds: UInt64

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        factorID = try values.decode(String.self, forKey: .factorID)
        secretBase32 = try values.decode(String.self, forKey: .secretBase32)
        otpauthURI = try values.decode(String.self, forKey: .otpauthURI)
        expiresInSeconds = try values.decode(UInt64.self, forKey: .expiresInSeconds)
        guard !factorID.isEmpty,
              !secretBase32.isEmpty,
              otpauthURI.hasPrefix("otpauth://totp/"),
              expiresInSeconds > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .factorID,
                in: values,
                debugDescription: "invalid TOTP enrollment start response"
            )
        }
    }

    private enum CodingKeys: String, CodingKey {
        case factorID = "factor_id"
        case secretBase32 = "secret_base32"
        case otpauthURI = "otpauth_uri"
        case expiresInSeconds = "expires_in_seconds"
    }
}

public struct TOTPEnrollmentFinishRequest: Encodable, Sendable {
    public let factorID: String
    public let code: String

    public init(factorID: String, code: String) throws {
        guard !factorID.isEmpty, !code.isEmpty else {
            throw EncodingError.invalidValue(
                "<redacted>",
                EncodingError.Context(
                    codingPath: [],
                    debugDescription: "factor ID and TOTP code are required"
                )
            )
        }
        self.factorID = factorID
        self.code = code
    }

    private enum CodingKeys: String, CodingKey {
        case factorID = "factor_id"
        case code
    }
}

public struct RecoveryCodeDeliveryEnvelope: Decodable, Equatable, Sendable {
    public static let maximumLifetimeMillis: Int64 = 24 * 60 * 60 * 1_000

    public let deliveryID: String
    public let serverEphemeralPublicKey: Data
    public let nonce: Data
    public let ciphertext: Data
    public let createdAtEpochMillis: Int64
    public let expiresAtEpochMillis: Int64
    public let recoveryCodeCount: UInt16

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        deliveryID = try values.decode(String.self, forKey: .deliveryID)
        let encodedServerKey = try values.decode(String.self, forKey: .serverEphemeralPublicKey)
        let encodedNonce = try values.decode(String.self, forKey: .nonce)
        let encodedCiphertext = try values.decode(String.self, forKey: .ciphertext)
        guard let serverKey = Data(base64URLEncoded: encodedServerKey), serverKey.count == 32,
              let decodedNonce = Data(base64URLEncoded: encodedNonce), decodedNonce.count == 12,
              let decodedCiphertext = Data(base64URLEncoded: encodedCiphertext),
              decodedCiphertext.count >= 16 else {
            throw DecodingError.dataCorruptedError(
                forKey: .ciphertext,
                in: values,
                debugDescription: "invalid recovery code delivery encoding"
            )
        }
        serverEphemeralPublicKey = serverKey
        nonce = decodedNonce
        ciphertext = decodedCiphertext
        createdAtEpochMillis = try values.decode(Int64.self, forKey: .createdAtEpochMillis)
        expiresAtEpochMillis = try values.decode(Int64.self, forKey: .expiresAtEpochMillis)
        recoveryCodeCount = try values.decode(UInt16.self, forKey: .recoveryCodeCount)
        guard !deliveryID.isEmpty,
              createdAtEpochMillis > 0,
              expiresAtEpochMillis > createdAtEpochMillis,
              expiresAtEpochMillis - createdAtEpochMillis <= Self.maximumLifetimeMillis,
              recoveryCodeCount > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .deliveryID,
                in: values,
                debugDescription: "invalid recovery code delivery contract"
            )
        }
    }

    init(
        deliveryID: String,
        serverEphemeralPublicKey: Data,
        nonce: Data,
        ciphertext: Data,
        createdAtEpochMillis: Int64,
        expiresAtEpochMillis: Int64,
        recoveryCodeCount: UInt16
    ) {
        self.deliveryID = deliveryID
        self.serverEphemeralPublicKey = serverEphemeralPublicKey
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.createdAtEpochMillis = createdAtEpochMillis
        self.expiresAtEpochMillis = expiresAtEpochMillis
        self.recoveryCodeCount = recoveryCodeCount
    }

    private enum CodingKeys: String, CodingKey {
        case deliveryID = "delivery_id"
        case serverEphemeralPublicKey = "server_ephemeral_public_key"
        case nonce
        case ciphertext
        case createdAtEpochMillis = "created_at_epoch_millis"
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case recoveryCodeCount = "recovery_code_count"
    }
}

public struct RecoveryCodeDelivery: Identifiable, Equatable, Sendable {
    public let deliveryID: String
    public let recoveryCodes: [String]
    public let expiresAtEpochMillis: Int64

    public var id: String { deliveryID }

    public init(deliveryID: String, recoveryCodes: [String], expiresAtEpochMillis: Int64) {
        self.deliveryID = deliveryID
        self.recoveryCodes = recoveryCodes
        self.expiresAtEpochMillis = expiresAtEpochMillis
    }
}

public struct LoginResponse: Decodable, Sendable {
    public let accountID: String
    public let accessToken: String
    public let refreshToken: String
    public let accessTokenExpiresAtEpochMillis: Int64
    public let refreshTokenExpiresAtEpochMillis: Int64
    public let deviceEnrollmentGrant: String?
    public let deviceEnrollmentGrantExpiresAtEpochMillis: Int64?

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case accessTokenExpiresAtEpochMillis = "access_token_expires_at_epoch_millis"
        case refreshTokenExpiresAtEpochMillis = "refresh_token_expires_at_epoch_millis"
        case deviceEnrollmentGrant = "device_enrollment_grant"
        case deviceEnrollmentGrantExpiresAtEpochMillis = "device_enrollment_grant_expires_at_epoch_millis"
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
        deviceEnrollmentGrant = try values.decodeIfPresent(
            String.self,
            forKey: .deviceEnrollmentGrant
        )
        deviceEnrollmentGrantExpiresAtEpochMillis = try values.decodeIfPresent(
            Int64.self,
            forKey: .deviceEnrollmentGrantExpiresAtEpochMillis
        )
        guard !accountID.isEmpty,
              !accessToken.isEmpty,
              !refreshToken.isEmpty,
              accessTokenExpiresAtEpochMillis > 0,
              refreshTokenExpiresAtEpochMillis > 0,
              (deviceEnrollmentGrant == nil) == (deviceEnrollmentGrantExpiresAtEpochMillis == nil),
              deviceEnrollmentGrant?.isEmpty != true else {
            throw DecodingError.dataCorruptedError(
                forKey: .accountID,
                in: values,
                debugDescription: "invalid login token or enrollment grant response"
            )
        }
    }

    public var tokenSet: TokenSet {
        TokenSet(
            accountID: accountID,
            accessToken: accessToken,
            refreshToken: refreshToken,
            accessTokenExpiresAtEpochMillis: accessTokenExpiresAtEpochMillis,
            refreshTokenExpiresAtEpochMillis: refreshTokenExpiresAtEpochMillis
        )
    }
}

public struct LoginFinishRequest: Encodable, Sendable {
    public let loginChallengeID: String
    public let loginRequestBindingHash: String
    public let loginChallengeBindingHash: String
    public let clientNonce: String
    public let serverNonce: String
    public let factor: String?
    public let code: String?
    public let protocolVersion: UInt16

    public init(challenge: LoginChallenge, factor: String?, code: String?) throws {
        let validProof: Bool
        if challenge.requiredFactors.isEmpty {
            validProof = factor == nil && code == nil
        } else {
            validProof = factor.map { challenge.requiredFactors.contains($0) } == true
                && code?.isEmpty == false
        }
        guard validProof else {
            throw EncodingError.invalidValue(
                "<redacted>",
                EncodingError.Context(
                    codingPath: [],
                    debugDescription: "factor and code do not satisfy the login challenge"
                )
            )
        }
        loginChallengeID = challenge.loginChallengeID
        loginRequestBindingHash = challenge.loginRequestBindingHash
        loginChallengeBindingHash = challenge.loginChallengeBindingHash
        clientNonce = challenge.clientNonce
        serverNonce = challenge.serverNonce
        self.factor = factor
        self.code = code
        protocolVersion = ProtocolConstants.version
    }

    private enum CodingKeys: String, CodingKey {
        case loginChallengeID = "login_challenge_id"
        case loginRequestBindingHash = "login_request_binding_hash"
        case loginChallengeBindingHash = "login_challenge_binding_hash"
        case clientNonce = "client_nonce"
        case serverNonce = "server_nonce"
        case factor
        case code
        case protocolVersion = "protocol_version"
    }
}

public struct DeviceRegistrationRequest: Encodable, Sendable {
    public let deviceEnrollmentGrant: String
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
        roleCapabilities: RoleCapabilities,
        deviceEnrollmentGrant: String
    ) {
        self.deviceID = deviceID
        self.platform = platform
        self.displayName = displayName
        self.osVersion = osVersion
        self.arch = arch
        self.publicKey = publicKey
        self.roleCapabilities = roleCapabilities
        self.deviceEnrollmentGrant = deviceEnrollmentGrant
    }

    private enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case platform
        case displayName = "display_name"
        case osVersion = "os_version"
        case arch
        case publicKey = "public_key"
        case roleCapabilities = "role_capabilities"
        case deviceEnrollmentGrant = "device_enrollment_grant"
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

public enum SessionDescriptorError: LocalizedError, Equatable {
    case missingPermissions
    case invalidPermissionsDigest
    case missingExpiration
    case expired
    case invalidDeviceBinding

    public var errorDescription: String? {
        switch self {
        case .missingPermissions:
            return "会话响应缺少最终权限"
        case .invalidPermissionsDigest:
            return "会话权限摘要无效"
        case .missingExpiration:
            return "会话响应缺少过期时间"
        case .expired:
            return "会话已过期"
        case .invalidDeviceBinding:
            return "会话设备绑定无效"
        }
    }
}

public extension SessionCreateResponse {
    func descriptor(
        accountID: String,
        controllerDeviceID: String,
        nowEpochMillis: Int64 = Date.now.epochMillis
    ) throws -> SessionDescriptor {
        guard !accountID.isEmpty,
              !controllerDeviceID.isEmpty,
              !controlledDeviceID.isEmpty,
              controllerDeviceID != controlledDeviceID else {
            throw SessionDescriptorError.invalidDeviceBinding
        }
        guard let permissions else {
            throw SessionDescriptorError.missingPermissions
        }
        guard let digest = permissionsDigest.flatMap(Data.init(hexEncoded:)), digest.count == 32 else {
            throw SessionDescriptorError.invalidPermissionsDigest
        }
        guard let expiresAtEpochMillis = sessionExpiresAtEpochMillis else {
            throw SessionDescriptorError.missingExpiration
        }
        guard expiresAtEpochMillis > nowEpochMillis else {
            throw SessionDescriptorError.expired
        }
        return SessionDescriptor(
            sessionID: sessionID,
            accountID: accountID,
            controllerDeviceID: controllerDeviceID,
            controlledDeviceID: controlledDeviceID,
            controlledDeviceName: controlledDeviceName ?? controlledDeviceID,
            permissions: permissions,
            permissionsDigest: digest,
            expiresAtEpochMillis: expiresAtEpochMillis
        )
    }
}

private extension Data {
    init?(hexEncoded value: String) {
        guard value.count == 64 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var index = value.startIndex
        for _ in 0..<32 {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
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
