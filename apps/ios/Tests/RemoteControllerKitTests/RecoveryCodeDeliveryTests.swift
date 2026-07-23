import CryptoKit
import Foundation
import Security
import XCTest
@testable import RemoteControllerKit

final class RecoveryCodeDeliveryTests: XCTestCase {
    func testTOTPWireRequestsUseFrozenFieldNames() throws {
        let start = try TOTPEnrollmentStartRequest(
            recoveryDeliveryPublicKey: Vector.clientPublicKey
        )
        let finish = try TOTPEnrollmentFinishRequest(factorID: Vector.factorID, code: "123456")
        let startObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(start)) as? [String: Any]
        )
        let finishObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(finish)) as? [String: Any]
        )

        XCTAssertEqual(Set(startObject.keys), Set(["recovery_delivery_public_key"]))
        XCTAssertEqual(Set(finishObject.keys), Set(["factor_id", "code"]))
        XCTAssertThrowsError(try TOTPEnrollmentStartRequest(recoveryDeliveryPublicKey: "AA"))
        XCTAssertThrowsError(try TOTPEnrollmentFinishRequest(factorID: Vector.factorID, code: ""))
    }

    func testStartRejectsAccessTokenWithoutBoundSessionBeforeSavingAKey() throws {
        let store = RecoveryMemorySecureStore()
        let vault = try makeVault(store: store)
        let tokens = TokenSet(
            accountID: Vector.accountID,
            accessToken: "opaque-access-token",
            refreshToken: "refresh-vector",
            accessTokenExpiresAtEpochMillis: 2_000_100_000_000,
            refreshTokenExpiresAtEpochMillis: 2_002_000_000_000
        )

        XCTAssertThrowsError(try vault.prepareStart(
            tokens: tokens,
            nowEpochMillis: Vector.created
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .invalidAccessToken)
        }
        XCTAssertFalse(store.containsPendingDelivery)
    }

    func testFrozenHKDFAndChaChaVectorSurvivesRetryUntilConfirmation() throws {
        let store = RecoveryMemorySecureStore()
        let vault = try makeVault(store: store)
        let firstStart = try vault.prepareStart(tokens: vectorTokens, nowEpochMillis: Vector.created - 1)

        XCTAssertEqual(firstStart.recoveryDeliveryPublicKey, Vector.clientPublicKey)
        XCTAssertTrue(store.containsPendingDelivery)

        try vault.recordStart(try startResponse())
        let firstFinish = try vault.finishMaterial(nowEpochMillis: Vector.created)

        let restoredVault = RecoveryCodeDeliveryVault(
            store: store,
            privateKeyGenerator: { Curve25519.KeyAgreement.PrivateKey() },
            idempotencyKeyGenerator: { "must-not-replace-the-persisted-key" }
        )
        let replayFinish = try restoredVault.finishMaterial(nowEpochMillis: Vector.created)

        XCTAssertEqual(replayFinish, firstFinish)
        XCTAssertEqual(replayFinish.factorID, Vector.factorID)
        XCTAssertEqual(replayFinish.idempotencyKey, Vector.idempotencyKey)
        XCTAssertEqual(replayFinish.authorizationToken, vectorTokens.accessToken)

        let delivery = try restoredVault.decrypt(
            try vectorEnvelope(),
            nowEpochMillis: Vector.created + 1
        )
        XCTAssertEqual(delivery.recoveryCodes, Vector.recoveryCodes)
        XCTAssertTrue(try restoredVault.hasPendingEnrollment())

        try restoredVault.confirmSaved(deliveryID: delivery.deliveryID)
        XCTAssertFalse(try restoredVault.hasPendingEnrollment())
        XCTAssertFalse(store.containsPendingDelivery)
    }

    func testTamperingWrongKeyAndExpiryFailClosedWithoutDeletingPendingKey() throws {
        let store = RecoveryMemorySecureStore()
        let vault = try preparedVault(store: store)
        let envelope = try vectorEnvelope()

        var tamperedCiphertext = envelope.ciphertext
        tamperedCiphertext[tamperedCiphertext.startIndex] ^= 0x01
        XCTAssertThrowsError(try vault.decrypt(
            replacing(envelope, ciphertext: tamperedCiphertext),
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authenticationFailed)
        }

        var tamperedNonce = envelope.nonce
        tamperedNonce[tamperedNonce.startIndex] ^= 0x01
        XCTAssertThrowsError(try vault.decrypt(
            replacing(envelope, nonce: tamperedNonce),
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authenticationFailed)
        }

        var tamperedServerKey = envelope.serverEphemeralPublicKey
        tamperedServerKey[tamperedServerKey.startIndex] ^= 0x01
        XCTAssertThrowsError(try vault.decrypt(
            replacing(envelope, serverEphemeralPublicKey: tamperedServerKey),
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authenticationFailed)
        }

        XCTAssertThrowsError(try vault.decrypt(
            replacing(
                envelope,
                createdAtEpochMillis: envelope.createdAtEpochMillis + 1,
                expiresAtEpochMillis: envelope.expiresAtEpochMillis + 1
            ),
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authenticationFailed)
        }

        XCTAssertThrowsError(try vault.decrypt(
            envelope,
            nowEpochMillis: envelope.expiresAtEpochMillis
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .deliveryExpired)
        }

        XCTAssertTrue(try vault.hasPendingEnrollment())
        XCTAssertTrue(store.containsPendingDelivery)

        let wrongKeyStore = RecoveryMemorySecureStore()
        let wrongKeyVault = try preparedVault(
            store: wrongKeyStore,
            privateKeyRaw: Data(repeating: 0x12, count: 32)
        )
        XCTAssertThrowsError(try wrongKeyVault.decrypt(
            envelope,
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authenticationFailed)
        }
        XCTAssertTrue(try wrongKeyVault.hasPendingEnrollment())
    }

    func testRecoveryCodeCountMismatchFailsClosed() throws {
        let store = RecoveryMemorySecureStore()
        let vault = try preparedVault(store: store)
        let envelope = replacing(try vectorEnvelope(), recoveryCodeCount: 3)

        XCTAssertThrowsError(try vault.decrypt(
            envelope,
            nowEpochMillis: Vector.created + 1
        )) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .recoveryCodeCountMismatch)
        }
        XCTAssertTrue(try vault.hasPendingEnrollment())
    }

    func testFinishReplayRejectsExpiredOriginalAuthorizationWithoutDeletingKey() throws {
        let store = RecoveryMemorySecureStore()
        let vault = try preparedVault(store: store)

        XCTAssertThrowsError(
            try vault.finishMaterial(nowEpochMillis: 2_000_100_000_000)
        ) { error in
            XCTAssertEqual(error as? RecoveryCodeDeliveryError, .authorizationExpired)
        }
        XCTAssertTrue(try vault.hasPendingEnrollment())
    }

    func testEnvelopeDecoderRejectsMalformedLengthsLifetimeAndCount() throws {
        let valid = try vectorEnvelopeJSON()
        _ = try JSONDecoder().decode(RecoveryCodeDeliveryEnvelope.self, from: valid)

        for mutation in [
            try replacingJSON(valid, key: "server_ephemeral_public_key", value: "AA"),
            try replacingJSON(valid, key: "nonce", value: "AA"),
            try replacingJSON(valid, key: "ciphertext", value: "AA"),
            try replacingJSON(valid, key: "expires_at_epoch_millis", value: Vector.created),
            try replacingJSON(
                valid,
                key: "expires_at_epoch_millis",
                value: Vector.created + RecoveryCodeDeliveryEnvelope.maximumLifetimeMillis + 1
            ),
            try replacingJSON(valid, key: "recovery_code_count", value: 0)
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(RecoveryCodeDeliveryEnvelope.self, from: mutation)
            )
        }
    }

    private func preparedVault(
        store: RecoveryMemorySecureStore,
        privateKeyRaw: Data = Vector.clientPrivateKey
    ) throws -> RecoveryCodeDeliveryVault {
        let vault = try makeVault(store: store, privateKeyRaw: privateKeyRaw)
        _ = try vault.prepareStart(tokens: vectorTokens, nowEpochMillis: Vector.created - 1)
        try vault.recordStart(try startResponse())
        return vault
    }

    private func makeVault(
        store: RecoveryMemorySecureStore,
        privateKeyRaw: Data = Vector.clientPrivateKey
    ) throws -> RecoveryCodeDeliveryVault {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyRaw)
        return RecoveryCodeDeliveryVault(
            store: store,
            privateKeyGenerator: { privateKey },
            idempotencyKeyGenerator: { Vector.idempotencyKey }
        )
    }

    private func startResponse() throws -> TOTPEnrollmentStartResponse {
        try JSONDecoder().decode(
            TOTPEnrollmentStartResponse.self,
            from: Data(
                #"{"factor_id":"factor-vector-1","secret_base32":"JBSWY3DPEHPK3PXP","otpauth_uri":"otpauth://totp/Rctl:account-vector-1?secret=JBSWY3DPEHPK3PXP&issuer=Rctl","expires_in_seconds":300}"#.utf8
            )
        )
    }

    private var vectorTokens: TokenSet {
        let payload = Data(
            #"{"account_id":"account-vector-1","account_session_id":"session-vector-1","issued_at_epoch_millis":1999999900000,"expires_at_epoch_millis":2000100000000,"mfa_verified":false,"token_type":"access"}"#.utf8
        ).base64URLEncodedString()
        return TokenSet(
            accountID: Vector.accountID,
            accessToken: "\(payload).c2lnbmF0dXJl",
            refreshToken: "refresh-vector",
            accessTokenExpiresAtEpochMillis: 2_000_100_000_000,
            refreshTokenExpiresAtEpochMillis: 2_002_000_000_000
        )
    }

    private func vectorEnvelope() throws -> RecoveryCodeDeliveryEnvelope {
        try JSONDecoder().decode(
            RecoveryCodeDeliveryEnvelope.self,
            from: try vectorEnvelopeJSON()
        )
    }

    private func vectorEnvelopeJSON() throws -> Data {
        try XCTUnwrap(
            #"{"delivery_id":"delivery-vector-1","server_ephemeral_public_key":"D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA","nonce":"AAECAwQFBgcICQoL","ciphertext":"jtI7abALcO4TFN9MidReQgNDURNFgfSTPzlyXgZ2PF24nMdDNiSwEWtEW7EYNo-TWTpSVAJeFqRSx-htyORN3qIuW6bq9G9GOOkz_Q","created_at_epoch_millis":2000000000000,"expires_at_epoch_millis":2000086400000,"recovery_code_count":2}"#.data(using: .utf8)
        )
    }

    private func replacing(
        _ envelope: RecoveryCodeDeliveryEnvelope,
        serverEphemeralPublicKey: Data? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        createdAtEpochMillis: Int64? = nil,
        expiresAtEpochMillis: Int64? = nil,
        recoveryCodeCount: UInt16? = nil
    ) -> RecoveryCodeDeliveryEnvelope {
        RecoveryCodeDeliveryEnvelope(
            deliveryID: envelope.deliveryID,
            serverEphemeralPublicKey: serverEphemeralPublicKey ?? envelope.serverEphemeralPublicKey,
            nonce: nonce ?? envelope.nonce,
            ciphertext: ciphertext ?? envelope.ciphertext,
            createdAtEpochMillis: createdAtEpochMillis ?? envelope.createdAtEpochMillis,
            expiresAtEpochMillis: expiresAtEpochMillis ?? envelope.expiresAtEpochMillis,
            recoveryCodeCount: recoveryCodeCount ?? envelope.recoveryCodeCount
        )
    }

    private func replacingJSON(_ data: Data, key: String, value: Any) throws -> Data {
        guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CanonicalEncodingError.invalidJSON
        }
        object[key] = value
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

private enum Vector {
    static let accountID = "account-vector-1"
    static let factorID = "factor-vector-1"
    static let idempotencyKey = "ios-totp-finish-vector-1"
    static let created: Int64 = 2_000_000_000_000
    static let clientPrivateKey = Data(repeating: 0x11, count: 32)
    static let clientPublicKey = "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM"
    static let recoveryCodes = ["ABCD2345-EFGH6789", "JKLM2345-NPQR6789"]
}

private final class RecoveryMemorySecureStore: SecureStoring, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

    var containsPendingDelivery: Bool {
        lock.lock()
        defer { lock.unlock() }
        return values["mfa.recovery-delivery.pending.v1"] != nil
    }

    func data(for key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    func set(_ data: Data, for key: String, accessibility: CFString) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = data
    }

    func remove(_ key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: key)
    }
}
