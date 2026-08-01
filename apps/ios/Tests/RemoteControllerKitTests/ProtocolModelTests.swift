import CryptoKit
import Foundation
import XCTest
@testable import RemoteControllerKit

final class ProtocolModelTests: XCTestCase {
    func testPlatformEnumIsFrozenAndOSVersionIsSeparate() throws {
        XCTAssertEqual(PlatformKind.allCases.map(\.rawValue), ["windows", "ubuntu", "ios"])
        XCTAssertThrowsError(try JSONDecoder().decode(PlatformKind.self, from: Data("\"ubuntu_26_04\"".utf8)))

        let data = Data(
            #"{"device_id":"device-1","display_name":"Desk","platform":"ubuntu","os_version":"26.04","status":"online","role_capabilities":{"controller":true,"controlled":true,"file_transfer":true,"unattended":true},"public_key_id":"key-1","public_key_version":1}"#.utf8
        )
        let device = try JSONDecoder().decode(DeviceSummary.self, from: data)

        XCTAssertEqual(device.platform, .ubuntu)
        XCTAssertEqual(device.osVersion, "26.04")
        XCTAssertEqual(device.publicKeyID, "key-1")
        XCTAssertEqual(device.status, .online)
        XCTAssertTrue(device.canBeControlled)
    }

    func testUnknownDeviceStatusDegradesWithoutExpandingPlatformEnum() throws {
        let data = Data(
            #"{"device_id":"device-1","display_name":"Desk","platform":"windows","os_version":"11","status":"maintenance","role_capabilities":{"controller":true,"controlled":true,"file_transfer":true,"unattended":true}}"#.utf8
        )
        let device = try JSONDecoder().decode(DeviceSummary.self, from: data)
        XCTAssertEqual(device.status, .unknown)
    }

    func testTokenResponseDecodesFrozenExpirationNames() throws {
        let data = Data(
            #"{"account_id":"account-1","access_token":"access","refresh_token":"refresh","access_token_expires_at_epoch_millis":4102444800000,"refresh_token_expires_at_epoch_millis":4105036800000}"#.utf8
        )
        let response = try JSONDecoder().decode(LoginResponse.self, from: data)

        XCTAssertEqual(response.tokenSet.accountID, "account-1")
        XCTAssertEqual(response.tokenSet.accessTokenExpiresAtEpochMillis, 4_102_444_800_000)
        XCTAssertNil(response.deviceEnrollmentGrant)
    }

    func testTokenSetEncodesFrozenExpirationNames() throws {
        let tokens = TokenSet(
            accountID: "account-1",
            accessToken: "access",
            refreshToken: "refresh",
            accessTokenExpiresAtEpochMillis: 100,
            refreshTokenExpiresAtEpochMillis: 200
        )
        let object = try jsonObject(tokens)

        XCTAssertEqual(object["access_token_expires_at_epoch_millis"] as? Int, 100)
        XCTAssertEqual(object["refresh_token_expires_at_epoch_millis"] as? Int, 200)
        XCTAssertNil(object["access_expires_at_epoch_millis"])
        XCTAssertNil(object["refresh_expires_at_epoch_millis"])
    }

    func testTokenSetRejectsLegacyExpirationNames() {
        let data = Data(
            #"{"account_id":"account-1","access_token":"access","refresh_token":"refresh","access_expires_at_epoch_millis":100,"refresh_expires_at_epoch_millis":200}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(TokenSet.self, from: data))
    }

    func testTwoStageLoginUsesFrozenDeviceBindingFields() throws {
        let identity = DeviceIdentity(
            deviceID: "ios-1",
            publicKeyID: nil,
            publicKeyVersion: 0,
            publicKey: Data(repeating: 7, count: 32)
        )
        let login = try jsonObject(LoginRequest(
            email: "qa@example.test",
            password: "secret",
            identity: identity,
            clientNonce: Data(repeating: 9, count: 32)
        ))
        XCTAssertEqual(Set(login.keys), [
            "email", "password", "device_id", "device_public_key", "public_key_version",
            "client_nonce", "protocol_version"
        ])
        XCTAssertNil(login["public_key_id"])
        XCTAssertEqual(login["public_key_version"] as? Int, 0)

        let challengeData = Data(
            #"{"code":"login_challenge_required","account_id":"account-1","login_challenge_id":"challenge-1","login_request_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","login_challenge_binding_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","server_nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_state":"pending_enrollment","required_factors":["totp"],"expires_at_epoch_millis":4102444800000,"attempts_remaining":5}"#.utf8
        )
        let decoder = JSONDecoder()
        decoder.userInfo[.loginClientNonce] = Data(repeating: 9, count: 32).base64URLEncodedString()
        let challenge = try decoder.decode(LoginChallenge.self, from: challengeData)
        let finish = try jsonObject(try LoginFinishRequest(
            challenge: challenge,
            factor: "totp",
            code: "123456"
        ))
        XCTAssertEqual(Set(finish.keys), [
            "login_challenge_id", "login_request_binding_hash", "login_challenge_binding_hash",
            "client_nonce", "server_nonce", "factor", "code", "protocol_version"
        ])
    }

    func testLoginChallengeMapsRequiredFactorsToMFAUI() throws {
        let data = Data(
            #"{"code":"login_challenge_required","account_id":"account-1","login_challenge_id":"challenge-1","login_request_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","login_challenge_binding_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","server_nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_state":"registered","required_factors":["totp","recovery_code"],"expires_at_epoch_millis":4102444800000,"attempts_remaining":5}"#.utf8
        )
        let decoder = JSONDecoder()
        decoder.userInfo[.loginClientNonce] = Data(repeating: 9, count: 32).base64URLEncodedString()
        let response = try decoder.decode(LoginChallenge.self, from: data)

        XCTAssertEqual(response.deviceState, .registered)
        XCTAssertEqual(response.mfaChallenge.mfaChallengeID, "challenge-1")
        XCTAssertEqual(response.mfaChallenge.allowedFactors, ["totp", "recovery_code"])
        XCTAssertEqual(response.mfaChallenge.attemptsRemaining, 5)
    }

    func testLoginChallengeRejectsCredentialsAndMissingRequestNonce() throws {
        let valid = Data(
            #"{"code":"login_challenge_required","account_id":"account-1","login_challenge_id":"challenge-1","login_request_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","login_challenge_binding_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","server_nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_state":"registered","required_factors":[],"expires_at_epoch_millis":4102444800000,"attempts_remaining":5}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(LoginChallenge.self, from: valid))

        let withToken = Data(
            #"{"code":"login_challenge_required","account_id":"account-1","login_challenge_id":"challenge-1","login_request_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","login_challenge_binding_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","server_nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_state":"registered","required_factors":[],"expires_at_epoch_millis":4102444800000,"attempts_remaining":5,"access_token":"must-not-exist"}"#.utf8
        )
        let decoder = JSONDecoder()
        decoder.userInfo[.loginClientNonce] = Data(repeating: 9, count: 32).base64URLEncodedString()
        XCTAssertThrowsError(try decoder.decode(LoginChallenge.self, from: withToken))
    }

    func testLoginFinishOmitsMFAFieldsWhenChallengeDoesNotRequireThem() throws {
        let data = Data(
            #"{"code":"login_challenge_required","account_id":"account-1","login_challenge_id":"challenge-1","login_request_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","login_challenge_binding_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","server_nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_state":"registered","required_factors":[],"expires_at_epoch_millis":4102444800000,"attempts_remaining":5}"#.utf8
        )
        let decoder = JSONDecoder()
        decoder.userInfo[.loginClientNonce] = Data(repeating: 9, count: 32).base64URLEncodedString()
        let challenge = try decoder.decode(LoginChallenge.self, from: data)
        let finish = try jsonObject(try LoginFinishRequest(
            challenge: challenge,
            factor: nil,
            code: nil
        ))

        XCTAssertNil(finish["factor"])
        XCTAssertNil(finish["code"])
        XCTAssertThrowsError(try LoginFinishRequest(
            challenge: challenge,
            factor: "totp",
            code: "123456"
        ))
    }

    func testLoginResponseRequiresCompleteTokenAndGrantPairs() {
        let partialToken = Data(
            #"{"account_id":"account-1","access_token":"access","access_token_expires_at_epoch_millis":4102444800000,"refresh_token_expires_at_epoch_millis":4105036800000}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(LoginResponse.self, from: partialToken))

        let grantWithoutExpiry = Data(
            #"{"account_id":"account-1","access_token":"access","refresh_token":"refresh","access_token_expires_at_epoch_millis":4102444800000,"refresh_token_expires_at_epoch_millis":4105036800000,"device_enrollment_grant":"grant.secret"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(LoginResponse.self, from: grantWithoutExpiry))
    }

    func testDeviceRegistrationUsesCapabilitiesAndKeepsOSVersionSeparate() throws {
        let request = DeviceRegistrationRequest(
            deviceID: "ios-1",
            platform: .ios,
            displayName: "Phone",
            osVersion: "16.7.12",
            arch: "aarch64",
            publicKey: "cHVibGljLWtleQ==",
            roleCapabilities: .iosControllerOnly,
            deviceEnrollmentGrant: "grant-id.grant-secret"
        )
        let object = try jsonObject(request)

        XCTAssertEqual(object["platform"] as? String, "ios")
        XCTAssertEqual(object["os_version"] as? String, "16.7.12")
        XCTAssertNil(object["ios_16"])
        XCTAssertNil(object["public_key_id"])
        XCTAssertEqual(object["device_enrollment_grant"] as? String, "grant-id.grant-secret")
        let capabilities = try XCTUnwrap(object["role_capabilities"] as? [String: Any])
        XCTAssertEqual(Set(capabilities.keys), ["controller", "controlled", "file_transfer", "unattended"])
        XCTAssertEqual(capabilities["controller"] as? Bool, true)
        XCTAssertEqual(capabilities["controlled"] as? Bool, false)
        XCTAssertEqual(capabilities["file_transfer"] as? Bool, false)
        XCTAssertEqual(capabilities["unattended"] as? Bool, false)
    }

    func testSessionCreateCarriesControllerAndIdempotencyBindings() throws {
        let idempotencyKey = try XCTUnwrap(UUID(uuidString: "00000000-0000-4000-8000-000000000003"))
        let request = SessionCreateRequest(
            controllerDeviceID: "ios-1",
            controlledDeviceID: "windows-1",
            authMethod: .accountPrompt,
            requestedPermissions: .requestedControllerDefaults,
            idempotencyKey: idempotencyKey
        )
        let object = try jsonObject(request)

        XCTAssertEqual(object["controller_device_id"] as? String, "ios-1")
        XCTAssertEqual(object["controlled_device_id"] as? String, "windows-1")
        XCTAssertEqual(object["auth_method"] as? String, "account_prompt")
        XCTAssertEqual(object["idempotency_key"] as? String, idempotencyKey.uuidString)
        let permissions = try XCTUnwrap(object["requested_permissions"] as? [String: Any])
        XCTAssertEqual(permissions["remote_desktop"] as? Bool, true)
        XCTAssertEqual(permissions["require_prompt"] as? Bool, true)
    }

    func testSignalCandidateAuthorizationUsesFrozenStringIdentifiers() throws {
        let sessionID = try XCTUnwrap(UUID(uuidString: "00000000-0000-4000-8000-000000000001"))
        let request = SignalCandidateTokenRequest(
            sessionID: sessionID,
            deviceID: "ios-1",
            role: .controller,
            candidateID: "00000000000000000000000000000002",
            kind: .lanDirect,
            endpoint: "192.168.1.20:50001",
            source: .localInterface,
            localInterfaceClaimHash: [UInt8](repeating: 1, count: 32),
            localInterfaceSignature: [UInt8](repeating: 2, count: 64),
            interfaceNameHash: [UInt8](repeating: 3, count: 32),
            interfaceIndexHash: [UInt8](repeating: 4, count: 32),
            localSocketNonce: [UInt8](repeating: 5, count: 32),
            timestampEpochMillis: 1_000,
            requestedTTLMillis: 30_000
        )
        let encoded = try jsonObject(request)
        XCTAssertEqual(encoded["session_id"] as? String, sessionID.uuidString.lowercased())
        XCTAssertEqual(encoded["candidate_id"] as? String, "00000000000000000000000000000002")
        XCTAssertEqual(encoded["kind"] as? String, "lan_direct")
        XCTAssertEqual(encoded["source"] as? String, "local_interface")
        XCTAssertNil(encoded["relay_node_id"])

        let response = try JSONDecoder().decode(SignalCandidateTokenIssued.self, from: Data(
            #"{"session_id":"00000000-0000-4000-8000-000000000001","device_id":"ios-1","role":"controller","candidate_id":"00000000000000000000000000000002","candidate_token":[7,8,9],"candidate_token_binding_hash":[6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],"expires_at_epoch_millis":4102444800000}"#.utf8
        ))
        XCTAssertEqual(response.sessionID, sessionID)
        XCTAssertEqual(response.candidateID, "00000000000000000000000000000002")
        XCTAssertEqual(response.candidateToken, [7, 8, 9])
        XCTAssertEqual(response.candidateTokenBindingHash.count, 32)
    }

    func testSessionResponseBuildsStrictDescriptor() throws {
        let response = try JSONDecoder().decode(SessionCreateResponse.self, from: Data(
            #"{"session_id":"00000000-0000-4000-8000-000000000001","status":"accepted","controlled_device_id":"ubuntu-1","controlled_device_name":"Workstation","permissions":{"remote_desktop":true,"input_control":true,"clipboard":false,"file_transfer":false,"unattended":false,"privacy_screen":false,"block_local_input":false,"require_prompt":false,"allow_relay":true},"permissions_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_expires_at_epoch_millis":4102444800000}"#.utf8
        ))

        let descriptor = try response.descriptor(
            accountID: "account-1",
            controllerDeviceID: "ios-1",
            nowEpochMillis: 1
        )

        XCTAssertEqual(descriptor.sessionID, response.sessionID)
        XCTAssertEqual(descriptor.controlledDeviceID, "ubuntu-1")
        XCTAssertEqual(descriptor.permissionsDigest, Data(repeating: 0xaa, count: 32))
    }

    func testSessionDescriptorRejectsMissingOrExpiredBindings() throws {
        let missingDigest = try JSONDecoder().decode(SessionCreateResponse.self, from: Data(
            #"{"session_id":"00000000-0000-4000-8000-000000000001","status":"accepted","controlled_device_id":"ubuntu-1","permissions":{"remote_desktop":true,"input_control":true,"clipboard":false,"file_transfer":false,"unattended":false,"privacy_screen":false,"block_local_input":false,"require_prompt":false,"allow_relay":true},"session_expires_at_epoch_millis":4102444800000}"#.utf8
        ))
        XCTAssertThrowsError(try missingDigest.descriptor(
            accountID: "account-1",
            controllerDeviceID: "ios-1",
            nowEpochMillis: 1
        )) { error in
            XCTAssertEqual(error as? SessionDescriptorError, .invalidPermissionsDigest)
        }

        let expired = try JSONDecoder().decode(SessionCreateResponse.self, from: Data(
            #"{"session_id":"00000000-0000-4000-8000-000000000001","status":"accepted","controlled_device_id":"ubuntu-1","permissions":{"remote_desktop":true,"input_control":true,"clipboard":false,"file_transfer":false,"unattended":false,"privacy_screen":false,"block_local_input":false,"require_prompt":false,"allow_relay":true},"permissions_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_expires_at_epoch_millis":10}"#.utf8
        ))
        XCTAssertThrowsError(try expired.descriptor(
            accountID: "account-1",
            controllerDeviceID: "ios-1",
            nowEpochMillis: 10
        )) { error in
            XCTAssertEqual(error as? SessionDescriptorError, .expired)
        }
    }

    func testIOSCapabilitiesDoNotAdvertiseControlledOrEncoding() throws {
        let capabilities = iosCapabilities()
        let object = try jsonObject(capabilities)

        XCTAssertEqual(object["platform"] as? String, "ios")
        XCTAssertEqual(object["os_version"] as? String, "16.7.12")
        let roles = try XCTUnwrap(object["role_capabilities"] as? [String: Any])
        XCTAssertEqual(roles["controlled"] as? Bool, false)
        let codecs = try XCTUnwrap(object["codec_capabilities"] as? [String: Any])
        XCTAssertEqual(codecs["h264"] as? Bool, true)
        XCTAssertEqual(codecs["hardware_decode"] as? Bool, true)
        XCTAssertEqual(codecs["hardware_encode"] as? Bool, false)
        XCTAssertEqual(codecs["max_encode_width"] as? Int, 0)
        let transports = try XCTUnwrap(object["transport_capabilities"] as? [String: Any])
        XCTAssertNotNil(transports["udp_p2p"])
        XCTAssertNil(transports["udp_p2_p"])
    }

    func testSignalProtocolVersionsHashMatchesRustVector() throws {
        let hash = try SignalHandshakeCanonical.protocolVersionsHash(
            versions: [1, 1],
            minimumVersion: 1
        )
        XCTAssertEqual(
            hash.lowercaseHexString,
            "d7f737b97f9f0957de182c6990e19ee567d8de437749d34e74602f9ad53af6fc"
        )
    }

    func testSignalCapabilitiesHashMatchesRustJCSVector() throws {
        XCTAssertEqual(
            try iosCapabilities().canonicalHash().lowercaseHexString,
            "b3fe25455e46c961c18fb2b352ee63f7e7a0b4c7fae686b94446ed11b315b612"
        )
    }

    func testSignalHelloSignatureInputMatchesRustVector() throws {
        let versionsHash = try XCTUnwrap(Data(hex: "d7f737b97f9f0957de182c6990e19ee567d8de437749d34e74602f9ad53af6fc"))
        let capabilitiesHash = try XCTUnwrap(Data(hex: "b3fe25455e46c961c18fb2b352ee63f7e7a0b4c7fae686b94446ed11b315b612"))
        let canonical = try SignalHandshakeCanonical.helloSignatureInput(
            serverNonce: Data(repeating: 1, count: 32),
            clientNonce: Data(repeating: 2, count: 32),
            accountID: "account-1",
            deviceID: "ios-1",
            protocolVersion: 1,
            timestamp: 1_234,
            versionsHash: versionsHash,
            capabilitiesHash: capabilitiesHash
        )
        XCTAssertEqual(
            Data(SHA256.hash(data: canonical)).lowercaseHexString,
            "952205f4ed4ac07b94b2b817c27ebb81765fc6ca2a0dba4d4307fd84029ee35c"
        )
    }

    func testSignalHelloResponseCarriesRegisteredDeviceKeyBinding() throws {
        let response = SignalHelloResponse(
            accountID: "account-1",
            deviceID: "ios-1",
            clientNonce: Data(repeating: 2, count: 32).base64URLEncodedString(),
            timestamp: 1_234,
            clientSupportedProtocolVersions: [1],
            clientMinProtocolVersion: 1,
            publicKeyID: "server-key-1",
            publicKeyVersion: 3,
            clientSupportedProtocolVersionsHash: String(repeating: "a", count: 64),
            clientCapabilities: iosCapabilities(),
            clientCapabilitiesHash: String(repeating: "b", count: 64),
            deviceSignature: Data(repeating: 3, count: 64).base64URLEncodedString()
        )
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(response)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(object["public_key_id"] as? String, "server-key-1")
        XCTAssertEqual(object["public_key_version"] as? Int, 3)
        XCTAssertNil(object["publicKeyID"])
    }

    func testSignalOnlineDeviceDecodesPresenceShape() throws {
        let data = Data(
            #"{"account_id":"account-1","device_id":"windows-1","public_key_id":"key-1","public_key_version":1,"public_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","client_capabilities_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"online","last_seen_epoch_millis":1234,"connection_id":"connection-1"}"#.utf8
        )
        let presence = try JSONDecoder().decode(SignalOnlineDevice.self, from: data)

        XCTAssertEqual(presence.deviceID, "windows-1")
        XCTAssertEqual(presence.status, .online)
        XCTAssertEqual(presence.publicKeyVersion, 1)
        XCTAssertEqual(Data(base64URLEncoded: presence.publicKey), Data(repeating: 7, count: 32))
    }

    func testSignalBase64URLRoundTripHasNoPadding() throws {
        let value = Data((0..<32).map { UInt8($0) })
        let encoded = value.base64URLEncodedString()
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(Data(base64URLEncoded: encoded), value)
        XCTAssertNil(Data(base64URLEncoded: "not+url-safe"))
    }

    func testJSONCanonicalizerRejectsDuplicateKeysAtEveryDepth() {
        XCTAssertThrowsError(try JSONCanonicalizer.canonicalize(Data(#"{"a":1,"a":2}"#.utf8)))
        XCTAssertThrowsError(try JSONCanonicalizer.canonicalize(
            Data(#"{"a":{"b":1,"b":2}}"#.utf8)
        ))
    }

    func testJSONCanonicalizerSupportsJCSNumbersAndUTF16KeyOrder() throws {
        XCTAssertEqual(
            try JSONCanonicalizer.canonicalize(Data(#"{"n":1.5,"z":1.0}"#.utf8)),
            Data(#"{"n":1.5,"z":1}"#.utf8)
        )
        XCTAssertEqual(
            try JSONCanonicalizer.canonicalize(Data("{\"\\uE000\":2,\"😀\":1}".utf8)),
            Data("{\"😀\":1,\"\":2}".utf8)
        )
    }

    func testSharedHTTPCanonicalVectorMatchesIOSImplementation() throws {
        let vector = try httpCanonicalVector()
        let body = Data(vector.body.utf8)
        let canonicalBody = try JSONCanonicalizer.canonicalize(body)
        XCTAssertEqual(String(decoding: canonicalBody, as: UTF8.self), vector.canonicalBody)
        let bodyHash = Data(SHA256.hash(data: canonicalBody))
        XCTAssertEqual(bodyHash.lowercaseHexString, vector.bodyHash)

        let url = try XCTUnwrap(URL(string: "https://example.test" + vector.requestTarget))
        let target = try CanonicalDeviceRequestAuthenticator.normalizedRequestTarget(url)
        XCTAssertEqual(target, vector.canonicalRequestTarget)

        let apiInput = try ProtocolCanonicalEncoder.encode(domain: "rctl-api-input-v1", fields: [
            ("method", ProtocolCanonicalEncoder.string(vector.method.uppercased())),
            ("path", ProtocolCanonicalEncoder.string(target)),
            ("body_hash", bodyHash),
            ("request_id", ProtocolCanonicalEncoder.string(vector.requestID)),
            ("device_id", ProtocolCanonicalEncoder.string(vector.deviceID)),
            ("account_id", ProtocolCanonicalEncoder.string(vector.accountID)),
            ("timestamp", ProtocolCanonicalEncoder.integer(vector.timestampEpochMillis)),
            ("api_nonce", ProtocolCanonicalEncoder.string(vector.apiNonce))
        ])
        XCTAssertEqual(Data(SHA256.hash(data: apiInput)).lowercaseHexString, vector.apiInputHash)

        let operation = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-operation-binding-v1",
            fields: [
                ("account_id", ProtocolCanonicalEncoder.string(vector.accountID)),
                ("device_id", ProtocolCanonicalEncoder.string(vector.deviceID)),
                ("purpose", ProtocolCanonicalEncoder.string(vector.purpose)),
                ("method", ProtocolCanonicalEncoder.string(vector.method.uppercased())),
                ("path", ProtocolCanonicalEncoder.string(target)),
                ("body_hash", bodyHash),
                ("request_id", ProtocolCanonicalEncoder.string(vector.requestID)),
                ("expires_at_epoch_millis", ProtocolCanonicalEncoder.integer(vector.expiresAtEpochMillis))
            ]
        )
        XCTAssertEqual(
            Data(SHA256.hash(data: operation)).lowercaseHexString,
            vector.operationBindingHash
        )

        let idempotency = try ProtocolCanonicalEncoder.encode(
            domain: "rctl-idempotency-binding-v1",
            fields: [
                ("account_id", ProtocolCanonicalEncoder.string(vector.accountID)),
                ("device_id", ProtocolCanonicalEncoder.string(vector.deviceID)),
                ("method", ProtocolCanonicalEncoder.string(vector.method.uppercased())),
                ("path", ProtocolCanonicalEncoder.string(target)),
                ("body_hash", bodyHash)
            ]
        )
        XCTAssertEqual(
            Data(SHA256.hash(data: idempotency)).lowercaseHexString,
            vector.idempotencyBindingHash
        )
    }

    func testCanonicalBodyHashHandlesEmptyAndRawBodies() throws {
        let empty = Data()
        XCTAssertEqual(
            try CanonicalDeviceRequestAuthenticator.canonicalBodyHash(empty, contentType: nil),
            Data(SHA256.hash(data: empty))
        )
        let raw = Data(#"{"z":1.0,"a":"text"}"#.utf8)
        XCTAssertEqual(
            try CanonicalDeviceRequestAuthenticator.canonicalBodyHash(
                raw,
                contentType: "application/octet-stream"
            ),
            Data(SHA256.hash(data: raw))
        )
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(value)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func iosCapabilities() -> ClientCapabilities {
        ClientCapabilities.ios(
            appVersion: "1.0.0",
            osVersion: "16.7.12",
            arch: "aarch64"
        )
    }

    private func httpCanonicalVector() throws -> HTTPCanonicalVector {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let url = root.appendingPathComponent(
            "test-vectors/http-canonical/rctl-api-input-v1.json"
        )
        return try JSONDecoder().decode(HTTPCanonicalVector.self, from: Data(contentsOf: url))
    }
}

private struct HTTPCanonicalVector: Decodable {
    let body: String
    let canonicalBody: String
    let bodyHash: String
    let method: String
    let requestTarget: String
    let canonicalRequestTarget: String
    let requestID: String
    let deviceID: String
    let accountID: String
    let timestampEpochMillis: UInt64
    let apiNonce: String
    let apiInputHash: String
    let purpose: String
    let expiresAtEpochMillis: UInt64
    let operationBindingHash: String
    let idempotencyBindingHash: String

    enum CodingKeys: String, CodingKey {
        case body
        case canonicalBody = "canonical_body"
        case bodyHash = "body_hash"
        case method
        case requestTarget = "request_target"
        case canonicalRequestTarget = "canonical_request_target"
        case requestID = "request_id"
        case deviceID = "device_id"
        case accountID = "account_id"
        case timestampEpochMillis = "timestamp_epoch_millis"
        case apiNonce = "api_nonce"
        case apiInputHash = "api_input_hash"
        case purpose
        case expiresAtEpochMillis = "expires_at_epoch_millis"
        case operationBindingHash = "operation_binding_hash"
        case idempotencyBindingHash = "idempotency_binding_hash"
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
