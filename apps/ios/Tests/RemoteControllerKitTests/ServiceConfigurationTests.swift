import Foundation
import XCTest
@testable import RemoteControllerKit

final class ServiceConfigurationTests: XCTestCase {
    func testDerivesSecureSignalURLAndDropsAPIQuery() throws {
        let apiURL = try XCTUnwrap(URL(string: "https://private.example/v1?tenant=acme#fragment"))
        let signalURL = try ServiceConfiguration.deriveSignalURL(from: apiURL)
        XCTAssertEqual(signalURL.absoluteString, "wss://private.example/ws")
    }

    func testPrivateDeploymentRequiresNormalizedSHA256Fingerprint() throws {
        let fingerprint = (0..<32).map { String(format: "%02x", $0) }.joined(separator: ":")
        let configuration = try ServiceConfiguration(
            environment: .privateDeployment,
            apiBaseURL: try XCTUnwrap(URL(string: "https://private.example")),
            signalURL: try XCTUnwrap(URL(string: "wss://private.example/ws")),
            serverPublicKeyFingerprint: fingerprint,
            organizationName: " Example "
        )

        XCTAssertEqual(configuration.serverPublicKeyFingerprint?.count, 64)
        XCTAssertEqual(configuration.organizationName, "Example")
    }

    func testPrivateDeploymentRejectsMissingFingerprint() throws {
        XCTAssertThrowsError(try ServiceConfiguration(
            environment: .privateDeployment,
            apiBaseURL: try XCTUnwrap(URL(string: "https://private.example")),
            signalURL: try XCTUnwrap(URL(string: "wss://private.example/ws"))
        )) { error in
            XCTAssertEqual(error as? ServiceConfigurationError, .invalidServerPublicKeyFingerprint)
        }
    }

    func testFingerprintRejectsNonSeparatorGarbage() {
        let hex = String(repeating: "ab", count: 32)
        XCTAssertNil(ServiceConfiguration.normalizedFingerprint("prefix\(hex)"))
        XCTAssertEqual(ServiceConfiguration.normalizedFingerprint(hex), hex)
    }

    func testPersistedConfigurationIsRevalidatedWhenDecoded() throws {
        let data = Data(
            #"{"environment":"official","apiBaseURL":"ftp:\/\/example.test","signalURL":"wss:\/\/example.test\/ws"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ServiceConfiguration.self, from: data))
    }

    func testNonWebSchemeIsRejectedForLoopback() throws {
        XCTAssertThrowsError(try ServiceConfiguration(
            environment: .official,
            apiBaseURL: try XCTUnwrap(URL(string: "ftp://127.0.0.1/api")),
            signalURL: try XCTUnwrap(URL(string: "wss://127.0.0.1/ws"))
        )) { error in
            XCTAssertEqual(error as? ServiceConfigurationError, .insecureURL("API"))
        }
    }

#if DEBUG
    func testDebugBuildAllowsOnlyLoopbackInsecureServices() throws {
        XCTAssertNoThrow(try ServiceConfiguration(
            environment: .official,
            apiBaseURL: try XCTUnwrap(URL(string: "http://[::1]:18080")),
            signalURL: try XCTUnwrap(URL(string: "ws://[::1]:18081/ws"))
        ))
        XCTAssertThrowsError(try ServiceConfiguration(
            environment: .official,
            apiBaseURL: try XCTUnwrap(URL(string: "http://private.example")),
            signalURL: try XCTUnwrap(URL(string: "wss://private.example/ws"))
        ))
    }
#endif

    func testCanonicalRequestTargetSortsEncodedQueryPairs() throws {
        let url = try XCTUnwrap(URL(string: "https://example.test/v1/devices?b=2&a=3&a=1"))
        XCTAssertEqual(
            try CanonicalDeviceRequestAuthenticator.normalizedRequestTarget(url),
            "/v1/devices?a=1&a=3&b=2"
        )
    }

    func testCanonicalRequestTargetNormalizesPathAndPercentEncoding() throws {
        let url = try XCTUnwrap(URL(string:
            "https://example.test/v1/a/./b/../c/%7euser?space=%20&slash=/&reserved=%2f"
        ))
        XCTAssertEqual(
            try CanonicalDeviceRequestAuthenticator.normalizedRequestTarget(url),
            "/v1/a/c/~user?reserved=%2F&slash=%2F&space=%20"
        )
    }

    func testCanonicalRequestTargetRejectsPlusInQuery() throws {
        let url = try XCTUnwrap(URL(string: "https://example.test/v1/devices?name=a+b"))
        XCTAssertThrowsError(try CanonicalDeviceRequestAuthenticator.normalizedRequestTarget(url))
    }
}
