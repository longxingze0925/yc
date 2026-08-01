import CryptoKit
import Foundation
import Security
import XCTest
@testable import RemoteControllerKit

final class DeviceIdentityStoreTests: XCTestCase {
    func testIdentityIsStableAndSignsDigest() throws {
        let secureStore = MemorySecureStore()
        let identityStore = DeviceIdentityStore(store: secureStore)
        let first = try identityStore.loadOrCreate()
        let second = try identityStore.loadOrCreate()
        let digest = Data(repeating: 0x5a, count: 32)
        let signature = try identityStore.sign(digest: digest)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: first.publicKey)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.publicKey.count, 32)
        XCTAssertNil(first.publicKeyID)
        XCTAssertEqual(first.publicKeyVersion, 0)
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: digest))
    }

    @MainActor
    func testRegistrationIsControllerOnlyAndPersistsServerKeyBinding() throws {
        let secureStore = MemorySecureStore()
        let identityStore = DeviceIdentityStore(store: secureStore)
        let request = try identityStore.registration(
            enrollmentGrant: "grant-id.grant-secret",
            displayName: "QA iPhone"
        )

        XCTAssertEqual(request.platform, .ios)
        XCTAssertEqual(request.roleCapabilities, .iosControllerOnly)
        XCTAssertFalse(request.roleCapabilities.fileTransfer)
        XCTAssertFalse(request.osVersion.isEmpty)
        XCTAssertFalse(request.publicKey.contains("="))
        XCTAssertEqual(request.deviceEnrollmentGrant, "grant-id.grant-secret")

        try identityStore.updateRegistration(publicKeyID: "server-key-1", publicKeyVersion: 3)
        let updated = try identityStore.loadOrCreate()
        XCTAssertEqual(updated.publicKeyID, "server-key-1")
        XCTAssertEqual(updated.publicKeyVersion, 3)
    }

    func testSigningRejectsNonSHA256Input() throws {
        let identityStore = DeviceIdentityStore(store: MemorySecureStore())
        _ = try identityStore.loadOrCreate()
        XCTAssertThrowsError(try identityStore.sign(digest: Data([1, 2, 3]))) { error in
            XCTAssertEqual(error as? DeviceIdentityError, .invalidDigestLength)
        }
    }

    func testPartialIdentityIsRejectedInsteadOfSilentlyRotated() throws {
        let secureStore = MemorySecureStore()
        try secureStore.set(
            Data("device-1".utf8),
            for: "device.identity.id.v1",
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
        let identityStore = DeviceIdentityStore(store: secureStore)
        XCTAssertThrowsError(try identityStore.loadOrCreate()) { error in
            guard case KeychainError.corruptValue(_) = error else {
                return XCTFail("Expected corrupt Keychain identity, got \(error)")
            }
        }
    }

    func testSignalCannotStartForUnregisteredIdentity() async throws {
        let identityStore = DeviceIdentityStore(store: MemorySecureStore())
        _ = try identityStore.loadOrCreate()
        let configuration = try ServiceConfiguration(
            environment: .official,
            apiBaseURL: try XCTUnwrap(URL(string: "https://api.example.test")),
            signalURL: try XCTUnwrap(URL(string: "wss://signal.example.test/ws"))
        )
        let client = SignalClient(configuration: configuration)

        do {
            try await client.start(
                accountID: "account-1",
                identityStore: identityStore,
                capabilities: .ios(appVersion: "1.0.0", osVersion: "16.7", arch: "aarch64"),
                accessTokenProvider: { () async throws -> String in "unused" }
            )
            XCTFail("unregistered identity must not start Signal")
        } catch {
            XCTAssertEqual(error as? APIClientError, .authenticationRequired)
        }
    }
}

private final class MemorySecureStore: SecureStoring, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

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
