import CoreGraphics
import Foundation
import XCTest
@testable import RemoteControllerKit

final class InputAndMediaTests: XCTestCase {
    func testInputEventUsesFrozenSnakeCaseFields() throws {
        let sessionID = try XCTUnwrap(UUID(uuidString: "00000000-0000-4000-8000-000000000001"))
        let eventID = try XCTUnwrap(UUID(uuidString: "00000000-0000-4000-8000-000000000002"))
        let event = InputEvent(
            sessionID: sessionID,
            displayID: "display-1",
            inputKind: .physicalKey,
            keyEventKind: .down,
            physicalCode: 4,
            keyCode: 4,
            logicalKey: "a",
            modifiers: [.ctrl],
            keyboardLayout: "en-US",
            eventID: eventID,
            timestampEpochMillis: 1_234
        )
        let data = try JSONEncoder().encode(event)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(object["session_id"] as? String, sessionID.uuidString.lowercased())
        XCTAssertEqual(object["event_id"] as? String, eventID.uuidString.lowercased())
        XCTAssertEqual(object["input_kind"] as? String, "physical_key")
        XCTAssertEqual(object["physical_code"] as? Int, 4)
        XCTAssertEqual(object["key_code"] as? Int, 4)
        XCTAssertEqual(object["modifiers"] as? [String], ["ctrl"])
        XCTAssertEqual(object["wheel_delta_x"] as? Double, 0)
        XCTAssertEqual(object["wheel_delta_y"] as? Double, 0)
        XCTAssertEqual(object["is_auto_repeat"] as? Bool, false)
        XCTAssertNil(object["physicalCode"])
    }

    func testSharedRustInputFixtureDecodesAndReencodes() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/protocol/input_event_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        let event = try JSONDecoder().decode(InputEvent.self, from: fixtureData)

        XCTAssertEqual(event.sessionID.uuidString.lowercased(), "00000000-0000-4000-8000-000000000001")
        XCTAssertEqual(event.eventID.uuidString.lowercased(), "00000000-0000-4000-8000-000000000002")
        XCTAssertEqual(event.physicalCode, 4)
        XCTAssertEqual(event.keyCode, 4)
        XCTAssertEqual(event.modifiers, [.ctrl])
        XCTAssertEqual(event.wheelDeltaX, 0)
        XCTAssertEqual(event.wheelDeltaY, 0)

        let expected = try XCTUnwrap(JSONSerialization.jsonObject(with: fixtureData) as? NSDictionary)
        let encoded = try JSONEncoder().encode(event)
        let actual = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? NSDictionary)
        XCTAssertEqual(actual, expected)
    }

    func testReleaseAllEventDoesNotContainText() throws {
        let event = InputEvent.releaseAll(sessionID: UUID(), displayID: "display-1")
        let data = try JSONEncoder().encode(event)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(object["input_kind"] as? String, "release_all_keys")
        XCTAssertNil(object["text"])
        XCTAssertNil(object["composition_text"])
    }

    func testViewportMapperRejectsLetterboxAndMapsCenter() throws {
        let mapper = RemoteViewportMapper(
            remoteSize: CGSize(width: 1_920, height: 1_080),
            viewportSize: CGSize(width: 1_000, height: 1_000)
        )

        XCTAssertNil(mapper.normalized(CGPoint(x: 500, y: 100)))
        let center = try XCTUnwrap(mapper.normalized(CGPoint(x: 500, y: 500)))
        XCTAssertEqual(center.x, 0.5, accuracy: 0.000_001)
        XCTAssertEqual(center.y, 0.5, accuracy: 0.000_001)
    }

    func testAnnexBParserSupportsThreeAndFourByteStartCodes() {
        let accessUnit = Data([
            0, 0, 0, 1, 0x67, 0x64, 0x00,
            0, 0, 1, 0x68, 0xee,
            0, 0, 0, 1, 0x65, 0x88, 0x84
        ])
        let units = AnnexBParser.nalUnits(from: accessUnit)

        XCTAssertEqual(units.count, 3)
        XCTAssertEqual(units.map { $0.first.map { $0 & 0x1f } }, [7, 8, 5])
    }

    func testAnnexBParserRejectsLengthPrefixedPayload() {
        XCTAssertTrue(AnnexBParser.nalUnits(from: Data([0, 0, 0, 2, 0x65, 0x01])).isEmpty)
    }
}
