import CoreGraphics
import Foundation

public enum InputKind: String, Codable, Sendable {
    case mouseMove = "mouse_move"
    case mouseButton = "mouse_button"
    case mouseWheel = "mouse_wheel"
    case physicalKey = "physical_key"
    case textCommit = "text_commit"
    case imeComposition = "ime_composition"
    case shortcut
    case touchGesture = "touch_gesture"
    case releaseAllKeys = "release_all_keys"
}

public enum KeyEventKind: String, Codable, Sendable {
    case down
    case up
    case `repeat`
    case tap
}

public enum MouseButton: String, Codable, Sendable {
    case left
    case right
    case middle
    case back
    case forward
}

public enum InputModifier: String, Codable, Sendable {
    case ctrl
    case alt
    case shift
    case meta
    case capsLock = "caps_lock"
}

public enum RemoteShortcut: String, Codable, CaseIterable, Identifiable, Sendable {
    case copy = "ctrl_c"
    case paste = "ctrl_v"
    case cut = "ctrl_x"
    case undo = "ctrl_z"
    case redo = "ctrl_y"
    case switchWindow = "alt_tab"
    case superKey = "super_win"
    case ctrlAltDeleteReserved = "ctrl_alt_delete_reserved"
    case printScreenReserved = "print_screen_reserved"

    public var id: String { rawValue }
    public var isReserved: Bool {
        self == .ctrlAltDeleteReserved || self == .printScreenReserved
    }
}

public struct InputEvent: Codable, Equatable, Sendable {
    public let sessionID: UUID
    public let eventID: UUID
    public let displayID: String
    public let inputKind: InputKind
    public let keyEventKind: KeyEventKind?
    public let physicalCode: UInt32?
    public let keyCode: UInt32
    public let scanCode: UInt32?
    public let virtualKey: UInt32?
    public let logicalKey: String?
    public let text: String?
    public let compositionText: String?
    public let compositionState: String?
    public let modifiers: [InputModifier]
    public let keyboardLayout: String?
    public let isAutoRepeat: Bool
    public let xNorm: Double?
    public let yNorm: Double?
    public let button: MouseButton?
    public let wheelDeltaX: Double
    public let wheelDeltaY: Double
    public let timestampEpochMillis: Int64

    private enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case eventID = "event_id"
        case displayID = "display_id"
        case inputKind = "input_kind"
        case keyEventKind = "key_event_kind"
        case physicalCode = "physical_code"
        case keyCode = "key_code"
        case scanCode = "scan_code"
        case virtualKey = "virtual_key"
        case logicalKey = "logical_key"
        case text
        case compositionText = "composition_text"
        case compositionState = "composition_state"
        case modifiers
        case keyboardLayout = "keyboard_layout"
        case isAutoRepeat = "is_auto_repeat"
        case xNorm = "x_norm"
        case yNorm = "y_norm"
        case button
        case wheelDeltaX = "wheel_delta_x"
        case wheelDeltaY = "wheel_delta_y"
        case timestampEpochMillis = "timestamp_epoch_millis"
    }

    public init(
        sessionID: UUID,
        displayID: String,
        inputKind: InputKind,
        keyEventKind: KeyEventKind? = nil,
        physicalCode: UInt32? = nil,
        keyCode: UInt32 = 0,
        scanCode: UInt32? = nil,
        virtualKey: UInt32? = nil,
        logicalKey: String? = nil,
        text: String? = nil,
        compositionText: String? = nil,
        compositionState: String? = nil,
        modifiers: [InputModifier] = [],
        keyboardLayout: String? = nil,
        isAutoRepeat: Bool = false,
        xNorm: Double? = nil,
        yNorm: Double? = nil,
        button: MouseButton? = nil,
        wheelDeltaX: Double = 0,
        wheelDeltaY: Double = 0,
        eventID: UUID = UUID(),
        timestampEpochMillis: Int64 = Date.now.epochMillis
    ) {
        self.sessionID = sessionID
        self.eventID = eventID
        self.displayID = displayID
        self.inputKind = inputKind
        self.keyEventKind = keyEventKind
        self.physicalCode = physicalCode
        self.keyCode = keyCode
        self.scanCode = scanCode
        self.virtualKey = virtualKey
        self.logicalKey = logicalKey
        self.text = text
        self.compositionText = compositionText
        self.compositionState = compositionState
        self.modifiers = modifiers
        self.keyboardLayout = keyboardLayout
        self.isAutoRepeat = isAutoRepeat
        self.xNorm = xNorm
        self.yNorm = yNorm
        self.button = button
        self.wheelDeltaX = wheelDeltaX
        self.wheelDeltaY = wheelDeltaY
        self.timestampEpochMillis = timestampEpochMillis
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let sessionIDValue = try values.decode(String.self, forKey: .sessionID)
        let eventIDValue = try values.decode(String.self, forKey: .eventID)
        guard let sessionID = UUID(uuidString: sessionIDValue) else {
            throw DecodingError.dataCorruptedError(
                forKey: .sessionID,
                in: values,
                debugDescription: "session_id must be a UUID string"
            )
        }
        guard let eventID = UUID(uuidString: eventIDValue) else {
            throw DecodingError.dataCorruptedError(
                forKey: .eventID,
                in: values,
                debugDescription: "event_id must be a UUID string"
            )
        }
        self.sessionID = sessionID
        self.eventID = eventID
        displayID = try values.decode(String.self, forKey: .displayID)
        inputKind = try values.decode(InputKind.self, forKey: .inputKind)
        keyEventKind = try values.decodeIfPresent(KeyEventKind.self, forKey: .keyEventKind)
        physicalCode = try values.decodeIfPresent(UInt32.self, forKey: .physicalCode)
        keyCode = try values.decodeIfPresent(UInt32.self, forKey: .keyCode) ?? 0
        scanCode = try values.decodeIfPresent(UInt32.self, forKey: .scanCode)
        virtualKey = try values.decodeIfPresent(UInt32.self, forKey: .virtualKey)
        logicalKey = try values.decodeIfPresent(String.self, forKey: .logicalKey)
        text = try values.decodeIfPresent(String.self, forKey: .text)
        compositionText = try values.decodeIfPresent(String.self, forKey: .compositionText)
        compositionState = try values.decodeIfPresent(String.self, forKey: .compositionState)
        modifiers = try values.decodeIfPresent([InputModifier].self, forKey: .modifiers) ?? []
        keyboardLayout = try values.decodeIfPresent(String.self, forKey: .keyboardLayout)
        isAutoRepeat = try values.decodeIfPresent(Bool.self, forKey: .isAutoRepeat) ?? false
        xNorm = try values.decodeIfPresent(Double.self, forKey: .xNorm)
        yNorm = try values.decodeIfPresent(Double.self, forKey: .yNorm)
        button = try values.decodeIfPresent(MouseButton.self, forKey: .button)
        wheelDeltaX = try values.decodeIfPresent(Double.self, forKey: .wheelDeltaX) ?? 0
        wheelDeltaY = try values.decodeIfPresent(Double.self, forKey: .wheelDeltaY) ?? 0
        timestampEpochMillis = try values.decode(Int64.self, forKey: .timestampEpochMillis)
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(sessionID.uuidString.lowercased(), forKey: .sessionID)
        try values.encode(eventID.uuidString.lowercased(), forKey: .eventID)
        try values.encode(displayID, forKey: .displayID)
        try values.encode(inputKind, forKey: .inputKind)
        try values.encodeIfPresent(keyEventKind, forKey: .keyEventKind)
        try values.encodeIfPresent(physicalCode, forKey: .physicalCode)
        try values.encode(keyCode, forKey: .keyCode)
        try values.encodeIfPresent(scanCode, forKey: .scanCode)
        try values.encodeIfPresent(virtualKey, forKey: .virtualKey)
        try values.encodeIfPresent(logicalKey, forKey: .logicalKey)
        try values.encodeIfPresent(text, forKey: .text)
        try values.encodeIfPresent(compositionText, forKey: .compositionText)
        try values.encodeIfPresent(compositionState, forKey: .compositionState)
        try values.encode(modifiers, forKey: .modifiers)
        try values.encodeIfPresent(keyboardLayout, forKey: .keyboardLayout)
        try values.encode(isAutoRepeat, forKey: .isAutoRepeat)
        try values.encodeIfPresent(xNorm, forKey: .xNorm)
        try values.encodeIfPresent(yNorm, forKey: .yNorm)
        try values.encodeIfPresent(button, forKey: .button)
        try values.encode(wheelDeltaX, forKey: .wheelDeltaX)
        try values.encode(wheelDeltaY, forKey: .wheelDeltaY)
        try values.encode(timestampEpochMillis, forKey: .timestampEpochMillis)
    }

    public static func pointer(
        sessionID: UUID,
        displayID: String,
        point: NormalizedPoint
    ) -> InputEvent {
        InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .mouseMove,
            xNorm: point.x,
            yNorm: point.y
        )
    }

    public static func button(
        sessionID: UUID,
        displayID: String,
        point: NormalizedPoint,
        button: MouseButton,
        state: KeyEventKind
    ) -> InputEvent {
        InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .mouseButton,
            keyEventKind: state,
            xNorm: point.x,
            yNorm: point.y,
            button: button
        )
    }

    public static func releaseAll(sessionID: UUID, displayID: String) -> InputEvent {
        InputEvent(sessionID: sessionID, displayID: displayID, inputKind: .releaseAllKeys)
    }

    public static func wheel(
        sessionID: UUID,
        displayID: String,
        deltaX: Double,
        deltaY: Double
    ) -> InputEvent {
        InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .mouseWheel,
            wheelDeltaX: deltaX,
            wheelDeltaY: deltaY
        )
    }

    public static func textCommit(sessionID: UUID, displayID: String, text: String) -> InputEvent {
        InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .textCommit,
            text: text
        )
    }

    public static func shortcut(
        sessionID: UUID,
        displayID: String,
        shortcut: RemoteShortcut
    ) -> InputEvent {
        InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .shortcut,
            keyEventKind: .tap,
            logicalKey: shortcut.rawValue
        )
    }
}

public struct NormalizedPoint: Equatable, Sendable {
    public let x: Double
    public let y: Double
}

public struct RemoteViewportMapper: Equatable, Sendable {
    public var remoteSize: CGSize
    public var viewportSize: CGSize
    public var zoomScale: CGFloat
    public var translation: CGSize

    public init(
        remoteSize: CGSize,
        viewportSize: CGSize,
        zoomScale: CGFloat = 1,
        translation: CGSize = .zero
    ) {
        self.remoteSize = remoteSize
        self.viewportSize = viewportSize
        self.zoomScale = max(1, zoomScale)
        self.translation = translation
    }

    public func normalized(_ point: CGPoint) -> NormalizedPoint? {
        guard remoteSize.width > 0,
              remoteSize.height > 0,
              viewportSize.width > 0,
              viewportSize.height > 0 else {
            return nil
        }
        let fitScale = min(viewportSize.width / remoteSize.width, viewportSize.height / remoteSize.height)
        let contentSize = CGSize(
            width: remoteSize.width * fitScale * zoomScale,
            height: remoteSize.height * fitScale * zoomScale
        )
        let origin = CGPoint(
            x: (viewportSize.width - contentSize.width) / 2 + translation.width,
            y: (viewportSize.height - contentSize.height) / 2 + translation.height
        )
        guard point.x >= origin.x,
              point.y >= origin.y,
              point.x <= origin.x + contentSize.width,
              point.y <= origin.y + contentSize.height else {
            return nil
        }
        return NormalizedPoint(
            x: min(1, max(0, Double((point.x - origin.x) / contentSize.width))),
            y: min(1, max(0, Double((point.y - origin.y) / contentSize.height)))
        )
    }
}
