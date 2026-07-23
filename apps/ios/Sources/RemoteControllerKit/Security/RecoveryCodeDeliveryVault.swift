import CryptoKit
import Foundation
import Security

public enum RecoveryCodeDeliveryError: LocalizedError, Equatable, Sendable {
    case invalidAccessToken
    case authorizationExpired
    case pendingEnrollmentConflict
    case missingPendingEnrollment
    case missingEnrollmentFactor
    case enrollmentBindingMismatch
    case invalidDelivery
    case deliveryExpired
    case authenticationFailed
    case recoveryCodeCountMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidAccessToken:
            return "登录凭据缺少恢复码交付上下文"
        case .authorizationExpired:
            return "恢复码交付授权已过期，请重新登录后轮换恢复码"
        case .pendingEnrollmentConflict:
            return "已有未确认的 MFA 恢复码交付"
        case .missingPendingEnrollment:
            return "没有可继续的 MFA 恢复码交付"
        case .missingEnrollmentFactor:
            return "TOTP enrollment 尚未完成 start"
        case .enrollmentBindingMismatch:
            return "MFA 恢复码交付绑定不匹配"
        case .invalidDelivery:
            return "恢复码密文响应无效"
        case .deliveryExpired:
            return "恢复码密文已过期"
        case .authenticationFailed:
            return "恢复码密文认证失败"
        case .recoveryCodeCountMismatch:
            return "恢复码数量与服务响应不一致"
        }
    }
}

struct RecoveryDeliveryStartMaterial: Equatable, Sendable {
    let recoveryDeliveryPublicKey: String
    let authorizationToken: String
    let existingFactorID: String?
}

struct RecoveryDeliveryFinishMaterial: Equatable, Sendable {
    let factorID: String
    let idempotencyKey: String
    let authorizationToken: String
}

public final class RecoveryCodeDeliveryVault: @unchecked Sendable {
    private struct AccessTokenClaims: Decodable {
        let accountID: String
        let accountSessionID: String
        let expiresAtEpochMillis: Int64
        let tokenType: String

        private enum CodingKeys: String, CodingKey {
            case accountID = "account_id"
            case accountSessionID = "account_session_id"
            case expiresAtEpochMillis = "expires_at_epoch_millis"
            case tokenType = "token_type"
        }
    }

    private struct PendingDelivery: Codable {
        let version: UInt8
        let accountID: String
        let accountSessionID: String
        let authorizationToken: String
        let authorizationExpiresAtEpochMillis: Int64
        var privateKey: Data
        let publicKey: Data
        let idempotencyKey: String
        var factorID: String?
        var decryptedDeliveryID: String?
    }

    private enum Constant {
        static let storageKey = "mfa.recovery-delivery.pending.v1"
        static let stateVersion: UInt8 = 1
    }

    private let store: any SecureStoring
    private let privateKeyGenerator: () throws -> Curve25519.KeyAgreement.PrivateKey
    private let idempotencyKeyGenerator: () -> String
    private let lock = NSLock()

    public init(store: any SecureStoring) {
        self.store = store
        privateKeyGenerator = { Curve25519.KeyAgreement.PrivateKey() }
        idempotencyKeyGenerator = { UUID().uuidString.lowercased() }
    }

    init(
        store: any SecureStoring,
        privateKeyGenerator: @escaping () throws -> Curve25519.KeyAgreement.PrivateKey,
        idempotencyKeyGenerator: @escaping () -> String
    ) {
        self.store = store
        self.privateKeyGenerator = privateKeyGenerator
        self.idempotencyKeyGenerator = idempotencyKeyGenerator
    }

    func prepareStart(tokens: TokenSet, nowEpochMillis: Int64 = Date.now.epochMillis) throws -> RecoveryDeliveryStartMaterial {
        lock.lock()
        defer { lock.unlock() }

        if var pending = try loadPending() {
            defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
            guard pending.accountID == tokens.accountID else {
                throw RecoveryCodeDeliveryError.pendingEnrollmentConflict
            }
            try validate(pending)
            guard pending.authorizationExpiresAtEpochMillis > nowEpochMillis else {
                throw RecoveryCodeDeliveryError.authorizationExpired
            }
            return RecoveryDeliveryStartMaterial(
                recoveryDeliveryPublicKey: pending.publicKey.base64URLEncodedString(),
                authorizationToken: pending.authorizationToken,
                existingFactorID: pending.factorID
            )
        }

        let claims = try accessClaims(from: tokens)
        guard claims.expiresAtEpochMillis > nowEpochMillis else {
            throw RecoveryCodeDeliveryError.authorizationExpired
        }
        let privateKey = try privateKeyGenerator()
        let pending = PendingDelivery(
            version: Constant.stateVersion,
            accountID: claims.accountID,
            accountSessionID: claims.accountSessionID,
            authorizationToken: tokens.accessToken,
            authorizationExpiresAtEpochMillis: claims.expiresAtEpochMillis,
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation,
            idempotencyKey: idempotencyKeyGenerator(),
            factorID: nil,
            decryptedDeliveryID: nil
        )
        try validate(pending)
        try save(pending)
        return RecoveryDeliveryStartMaterial(
            recoveryDeliveryPublicKey: pending.publicKey.base64URLEncodedString(),
            authorizationToken: pending.authorizationToken,
            existingFactorID: nil
        )
    }

    func recordStart(_ response: TOTPEnrollmentStartResponse) throws {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else {
            throw RecoveryCodeDeliveryError.missingPendingEnrollment
        }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        if let factorID = pending.factorID, factorID != response.factorID {
            throw RecoveryCodeDeliveryError.enrollmentBindingMismatch
        }
        pending.factorID = response.factorID
        try save(pending)
    }

    func finishMaterial(nowEpochMillis: Int64 = Date.now.epochMillis) throws -> RecoveryDeliveryFinishMaterial {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else {
            throw RecoveryCodeDeliveryError.missingPendingEnrollment
        }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        guard pending.authorizationExpiresAtEpochMillis > nowEpochMillis else {
            throw RecoveryCodeDeliveryError.authorizationExpired
        }
        guard let factorID = pending.factorID else {
            throw RecoveryCodeDeliveryError.missingEnrollmentFactor
        }
        return RecoveryDeliveryFinishMaterial(
            factorID: factorID,
            idempotencyKey: pending.idempotencyKey,
            authorizationToken: pending.authorizationToken
        )
    }

    public func decrypt(
        _ envelope: RecoveryCodeDeliveryEnvelope,
        nowEpochMillis: Int64 = Date.now.epochMillis
    ) throws -> RecoveryCodeDelivery {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else {
            throw RecoveryCodeDeliveryError.missingPendingEnrollment
        }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        guard let factorID = pending.factorID else {
            throw RecoveryCodeDeliveryError.missingEnrollmentFactor
        }
        guard envelope.expiresAtEpochMillis > nowEpochMillis else {
            throw RecoveryCodeDeliveryError.deliveryExpired
        }
        if let deliveryID = pending.decryptedDeliveryID, deliveryID != envelope.deliveryID {
            throw RecoveryCodeDeliveryError.enrollmentBindingMismatch
        }

        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let serverPublicKey: Curve25519.KeyAgreement.PublicKey
        do {
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: pending.privateKey)
            serverPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: envelope.serverEphemeralPublicKey
            )
        } catch {
            throw RecoveryCodeDeliveryError.invalidDelivery
        }
        guard privateKey.publicKey.rawRepresentation == pending.publicKey else {
            throw RecoveryCodeDeliveryError.enrollmentBindingMismatch
        }

        let idempotencyKeyHash = Data(SHA256.hash(data: Data(pending.idempotencyKey.utf8)))
        let saltInput = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-recovery-delivery-salt-v1",
            fields: [
                ("account_id", ProtocolCanonicalEncoder.string(pending.accountID)),
                ("account_session_id", ProtocolCanonicalEncoder.string(pending.accountSessionID)),
                ("factor_id", ProtocolCanonicalEncoder.string(factorID)),
                ("delivery_id", ProtocolCanonicalEncoder.string(envelope.deliveryID)),
                ("idempotency_key_hash", idempotencyKeyHash)
            ]
        )
        let salt = Data(SHA256.hash(data: saltInput))
        let info = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-recovery-delivery-v1",
            fields: [
                ("account_id", ProtocolCanonicalEncoder.string(pending.accountID)),
                ("account_session_id", ProtocolCanonicalEncoder.string(pending.accountSessionID)),
                ("factor_id", ProtocolCanonicalEncoder.string(factorID)),
                ("delivery_id", ProtocolCanonicalEncoder.string(envelope.deliveryID)),
                ("client_ephemeral_public_key", pending.publicKey),
                ("server_ephemeral_public_key", envelope.serverEphemeralPublicKey),
                (
                    "created_at_epoch_millis",
                    ProtocolCanonicalEncoder.integer(UInt64(envelope.createdAtEpochMillis))
                ),
                (
                    "expires_at_epoch_millis",
                    ProtocolCanonicalEncoder.integer(UInt64(envelope.expiresAtEpochMillis))
                )
            ]
        )

        var plaintext = Data()
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        do {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
            let deliveryKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: salt,
                sharedInfo: info,
                outputByteCount: 32
            )
            var combined = envelope.nonce
            combined.append(envelope.ciphertext)
            let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
            plaintext = try ChaChaPoly.open(sealedBox, using: deliveryKey, authenticating: info)
        } catch {
            throw RecoveryCodeDeliveryError.authenticationFailed
        }

        let recoveryCodes = try parseRecoveryCodes(
            plaintext,
            expectedCount: Int(envelope.recoveryCodeCount)
        )
        pending.decryptedDeliveryID = envelope.deliveryID
        try save(pending)
        return RecoveryCodeDelivery(
            deliveryID: envelope.deliveryID,
            recoveryCodes: recoveryCodes,
            expiresAtEpochMillis: envelope.expiresAtEpochMillis
        )
    }

    public func confirmSaved(deliveryID: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else {
            throw RecoveryCodeDeliveryError.missingPendingEnrollment
        }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        guard pending.decryptedDeliveryID == deliveryID else {
            throw RecoveryCodeDeliveryError.enrollmentBindingMismatch
        }
        try store.remove(Constant.storageKey)
    }

    public func pendingFactorID() throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else { return nil }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        return pending.factorID
    }

    public func hasPendingEnrollment() throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = try loadPending() else { return false }
        defer { pending.privateKey.resetBytes(in: 0..<pending.privateKey.count) }
        try validate(pending)
        return true
    }

    private func accessClaims(from tokens: TokenSet) throws -> AccessTokenClaims {
        let segments = tokens.accessToken.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 2,
              let payload = Data(base64URLEncoded: String(segments[0])),
              let claims = try? JSONDecoder().decode(AccessTokenClaims.self, from: payload),
              claims.tokenType == "access",
              claims.accountID == tokens.accountID,
              claims.expiresAtEpochMillis == tokens.accessTokenExpiresAtEpochMillis,
              !claims.accountSessionID.isEmpty else {
            throw RecoveryCodeDeliveryError.invalidAccessToken
        }
        return claims
    }

    private func loadPending() throws -> PendingDelivery? {
        guard let data = try store.data(for: Constant.storageKey) else { return nil }
        guard let pending = try? JSONDecoder().decode(PendingDelivery.self, from: data) else {
            throw KeychainError.corruptValue(Constant.storageKey)
        }
        return pending
    }

    private func save(_ pending: PendingDelivery) throws {
        let data = try JSONEncoder().encode(pending)
        try store.set(
            data,
            for: Constant.storageKey,
            accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    private func validate(_ pending: PendingDelivery) throws {
        guard pending.version == Constant.stateVersion,
              !pending.accountID.isEmpty,
              !pending.accountSessionID.isEmpty,
              !pending.authorizationToken.isEmpty,
              pending.authorizationExpiresAtEpochMillis > 0,
              pending.privateKey.count == 32,
              pending.publicKey.count == 32,
              !pending.idempotencyKey.isEmpty,
              pending.idempotencyKey.utf8.count <= 128,
              pending.idempotencyKey.utf8.allSatisfy({ (0x21...0x7E).contains($0) }),
              pending.factorID?.isEmpty != true,
              pending.decryptedDeliveryID?.isEmpty != true else {
            throw KeychainError.corruptValue(Constant.storageKey)
        }
        guard let privateKey = try? Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: pending.privateKey
        ), privateKey.publicKey.rawRepresentation == pending.publicKey else {
            throw KeychainError.corruptValue(Constant.storageKey)
        }
    }

    private func parseRecoveryCodes(_ plaintext: Data, expectedCount: Int) throws -> [String] {
        let canonical: Data
        do {
            canonical = try JSONCanonicalizer.canonicalize(plaintext)
        } catch {
            throw RecoveryCodeDeliveryError.invalidDelivery
        }
        guard canonical == plaintext,
              let object = try? JSONSerialization.jsonObject(with: plaintext),
              let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Set(["recovery_codes"]),
              let recoveryCodes = dictionary["recovery_codes"] as? [String],
              recoveryCodes.allSatisfy({ code in
                  !code.isEmpty
                      && code.utf8.count <= 128
                      && code.utf8.allSatisfy({ (0x21...0x7E).contains($0) })
              }),
              Set(recoveryCodes).count == recoveryCodes.count else {
            throw RecoveryCodeDeliveryError.invalidDelivery
        }
        guard recoveryCodes.count == expectedCount else {
            throw RecoveryCodeDeliveryError.recoveryCodeCountMismatch
        }
        return recoveryCodes
    }
}
