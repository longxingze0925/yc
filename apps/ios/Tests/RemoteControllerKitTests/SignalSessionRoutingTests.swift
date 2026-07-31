import Foundation
import XCTest
@testable import RemoteControllerKit

final class SignalSessionRoutingTests: XCTestCase {
    private let sessionID = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!

    func testCandidateAndPairIDsMatchRustCanonicalVectors() throws {
        let candidate = SignalConnectionCandidate(
            candidateID: String(repeating: "0", count: 32),
            sessionID: sessionID,
            deviceID: "ubuntu-1",
            role: .controlled,
            kind: .lanDirect,
            endpoint: "192.168.1.20:50000",
            source: .localInterface
        )
        XCTAssertEqual(
            try candidate.computedCandidateID(),
            "2f6d2bcf056afd09094e61fd90b08a6a"
        )
        XCTAssertEqual(
            try SignalCandidateEnvelopeCodec.candidatePairID(
                sessionID: sessionID,
                controllerCandidateID: "11111111111111111111111111111111",
                controlledCandidateID: "22222222222222222222222222222222",
                selectedTransportPath: .lanDirect,
                relayNodeID: nil
            ),
            "640e3858a133e28e206b4517d032182e"
        )
    }

    func testCandidateAuthorizationBindingMatchesRustCanonicalVector() throws {
        let candidate = try controlledCandidate()
        XCTAssertEqual(
            Data(try SignalCandidateAuthorization.bindingHash(
                candidate: candidate,
                expiresAtEpochMillis: 120_000
            )).lowercaseHexString,
            "695086f7264257441576da75f9bfa044600599114f8365683e63aa65fcd655c1"
        )
    }

    func testLocalInterfaceClaimMatchesRustCanonicalVector() throws {
        XCTAssertEqual(
            Data(try SignalCandidateCanonical.localInterfaceClaimHash(
                sessionID: sessionID,
                deviceID: "ios-1",
                role: .controller,
                candidateID: "11111111111111111111111111111111",
                endpoint: "192.168.1.10:50001",
                interfaceNameHash: [UInt8](repeating: 1, count: 32),
                interfaceIndexHash: [UInt8](repeating: 2, count: 32),
                localSocketNonce: [UInt8](repeating: 3, count: 32),
                timestampEpochMillis: 100_000
            )).lowercaseHexString,
            "9a81e9863ab7fd5e4d587bf214edbd0608692d1c44bac5b456e53df81c885fa6"
        )
    }

    func testControlledEnvelopeAcceptsOnlyTopLevelTransportIdentity() throws {
        let descriptor = descriptor()
        let valid = try controlledEnvelopeData()
        let decoded = try SignalCandidateEnvelopeCodec.decodeControlled(
            valid,
            descriptor: descriptor,
            nowEpochMillis: 90_000
        )
        XCTAssertEqual(decoded.candidate.deviceID, "ubuntu-1")
        XCTAssertEqual(decoded.transportCertificateDER, Data([0x30, 0x01, 0x00]))

        var unknown = try XCTUnwrap(
            JSONSerialization.jsonObject(with: valid) as? [String: Any]
        )
        unknown["selected_candidate_pair_id"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        XCTAssertThrowsError(try SignalCandidateEnvelopeCodec.decodeControlled(
            try JSONSerialization.data(withJSONObject: unknown),
            descriptor: descriptor,
            nowEpochMillis: 90_000
        )) { error in
            XCTAssertEqual(error as? SignalSessionContractError, .invalidEnvelope)
        }

        var padded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: valid) as? [String: Any]
        )
        padded["transport_certificate_der"] = "MAEA="
        XCTAssertThrowsError(try SignalCandidateEnvelopeCodec.decodeControlled(
            try JSONSerialization.data(withJSONObject: padded),
            descriptor: descriptor,
            nowEpochMillis: 90_000
        )) { error in
            XCTAssertEqual(error as? SignalSessionContractError, .invalidTransportIdentity)
        }
    }

    func testControllerEnvelopeNeverSendsCertificateServerNameOrPairID() throws {
        let candidate = try controlledCandidate(role: .controller, deviceID: "ios-1")
        let authorization = SignalCandidateAuthorization(
            candidateToken: [1, 2, 3],
            candidateTokenBindingHash: try SignalCandidateAuthorization.bindingHash(
                candidate: candidate,
                expiresAtEpochMillis: 120_000
            ),
            expiresAtEpochMillis: 120_000
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: try SignalCandidateEnvelopeCodec.encodeController(
                candidate: candidate,
                authorization: authorization
            )
        ) as? [String: Any])
        XCTAssertEqual(Set(object.keys), Set(["candidate", "authorization"]))
        XCTAssertNil(object["transport_certificate_der"])
        XCTAssertNil(object["server_name"])
        XCTAssertNil(object["selected_candidate_pair_id"])
    }

    func testRouterBuffersBySessionAndRemoveAllFinishesStream() async throws {
        let router = SignalSessionEventRouter()
        let message = SignalSessionMessage(
            kind: .keyConfirm,
            sessionID: sessionID,
            role: .controlled,
            fromDeviceID: "ubuntu-1",
            payload: Data("{}".utf8)
        )
        await router.route(.sessionMessage(message))
        let stream = await router.events(for: sessionID)
        var iterator = stream.makeAsyncIterator()
        guard case let .message(received)? = await iterator.next() else {
            return XCTFail("buffered session message was not delivered")
        }
        XCTAssertEqual(received, message)
        await router.removeAll()
        let finished = await iterator.next()
        XCTAssertNil(finished)
    }

    func testVideoPacketAssemblerBoundsIncompleteGroupsAndCompletesPair() {
        var assembler = NativeVideoPacketGroupAssembler(maximumIncompleteGroups: 3)
        for groupID in 1...4 {
            XCTAssertNil(assembler.insert(
                groupID: UInt64(groupID),
                index: 0,
                count: 2,
                packet: Data([UInt8(groupID)])
            ))
        }
        XCTAssertEqual(assembler.incompleteGroupCount, 3)
        let completed = assembler.insert(
            groupID: 4,
            index: 1,
            count: 2,
            packet: Data([9])
        )
        XCTAssertEqual(completed?.info, Data([4]))
        XCTAssertEqual(completed?.data, Data([9]))
        XCTAssertEqual(assembler.incompleteGroupCount, 2)
    }

    private func controlledCandidate(
        role: SignalSessionRole = .controlled,
        deviceID: String = "ubuntu-1"
    ) throws -> SignalConnectionCandidate {
        let unsigned = SignalConnectionCandidate(
            candidateID: String(repeating: "0", count: 32),
            sessionID: sessionID,
            deviceID: deviceID,
            role: role,
            kind: .lanDirect,
            endpoint: "192.168.1.20:50000",
            source: .localInterface
        )
        return SignalConnectionCandidate(
            candidateID: try unsigned.computedCandidateID(),
            sessionID: unsigned.sessionID,
            deviceID: unsigned.deviceID,
            role: unsigned.role,
            kind: unsigned.kind,
            endpoint: unsigned.endpoint,
            source: unsigned.source
        )
    }

    private func descriptor() -> SessionDescriptor {
        SessionDescriptor(
            sessionID: sessionID,
            accountID: "account-1",
            controllerDeviceID: "ios-1",
            controlledDeviceID: "ubuntu-1",
            controlledDeviceName: "Ubuntu",
            permissions: .requestedControllerDefaults,
            permissionsDigest: Data(repeating: 1, count: 32),
            expiresAtEpochMillis: 180_000
        )
    }

    private func controlledEnvelopeData() throws -> Data {
        let candidate = try controlledCandidate()
        let authorization = SignalCandidateAuthorization(
            candidateToken: [1, 2, 3],
            candidateTokenBindingHash: try SignalCandidateAuthorization.bindingHash(
                candidate: candidate,
                expiresAtEpochMillis: 120_000
            ),
            expiresAtEpochMillis: 120_000
        )
        let encoder = JSONEncoder()
        let candidateObject = try JSONSerialization.jsonObject(with: encoder.encode(candidate))
        let authorizationObject = try JSONSerialization.jsonObject(with: encoder.encode(authorization))
        return try JSONSerialization.data(withJSONObject: [
            "candidate": candidateObject,
            "authorization": authorizationObject,
            "transport_certificate_der": Data([0x30, 0x01, 0x00]).base64URLEncodedString(),
            "server_name": "rctl-123.invalid"
        ])
    }
}
