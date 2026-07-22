import CoreGraphics
import SwiftUI
import UIKit

public struct RemoteInputOverlay: UIViewRepresentable {
    public typealias EventHandler = (InputEvent) -> Void

    private let sessionID: UUID
    private let displayID: String
    private let remoteSize: CGSize
    @Binding private var zoomScale: CGFloat
    @Binding private var keyboardPresented: Bool
    private let onEvent: EventHandler
    private let onShortcutPalette: () -> Void

    public init(
        sessionID: UUID,
        displayID: String,
        remoteSize: CGSize,
        zoomScale: Binding<CGFloat>,
        keyboardPresented: Binding<Bool>,
        onEvent: @escaping EventHandler,
        onShortcutPalette: @escaping () -> Void
    ) {
        self.sessionID = sessionID
        self.displayID = displayID
        self.remoteSize = remoteSize
        _zoomScale = zoomScale
        _keyboardPresented = keyboardPresented
        self.onEvent = onEvent
        self.onShortcutPalette = onShortcutPalette
    }

    public func makeUIView(context: Context) -> RemoteInputSurfaceView {
        let view = RemoteInputSurfaceView()
        view.configure(
            sessionID: sessionID,
            displayID: displayID,
            remoteSize: remoteSize,
            zoomScale: zoomScale,
            onEvent: onEvent,
            onZoomChanged: { zoomScale = $0 },
            onShortcutPalette: onShortcutPalette
        )
        return view
    }

    public func updateUIView(_ uiView: RemoteInputSurfaceView, context: Context) {
        uiView.configure(
            sessionID: sessionID,
            displayID: displayID,
            remoteSize: remoteSize,
            zoomScale: zoomScale,
            onEvent: onEvent,
            onZoomChanged: { zoomScale = $0 },
            onShortcutPalette: onShortcutPalette
        )
        if keyboardPresented, !uiView.isFirstResponder {
            uiView.becomeFirstResponder()
        } else if !keyboardPresented, uiView.isFirstResponder {
            uiView.releaseAllKeys()
            uiView.resignFirstResponder()
        }
    }
}

public final class RemoteInputSurfaceView: UIView, UIKeyInput, UIGestureRecognizerDelegate {
    private var sessionID = UUID()
    private var displayID = "primary"
    private var remoteSize = CGSize(width: 1, height: 1)
    private var zoomScale: CGFloat = 1
    private var onEvent: ((InputEvent) -> Void)?
    private var onZoomChanged: ((CGFloat) -> Void)?
    private var onShortcutPalette: (() -> Void)?
    private var activeRightClickPoint: NormalizedPoint?
    private var isConfigured = false

    public override var canBecomeFirstResponder: Bool { true }
    public var hasText: Bool { false }

    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        isMultipleTouchEnabled = true
        accessibilityLabel = "远程桌面输入区域"
        installGestures()
    }

    public required init?(coder: NSCoder) {
        super.init(coder: coder)
        backgroundColor = .clear
        isMultipleTouchEnabled = true
        installGestures()
    }

    public func configure(
        sessionID: UUID,
        displayID: String,
        remoteSize: CGSize,
        zoomScale: CGFloat,
        onEvent: @escaping (InputEvent) -> Void,
        onZoomChanged: @escaping (CGFloat) -> Void,
        onShortcutPalette: @escaping () -> Void
    ) {
        self.sessionID = sessionID
        self.displayID = displayID
        self.remoteSize = remoteSize
        self.zoomScale = min(4, max(1, zoomScale))
        self.onEvent = onEvent
        self.onZoomChanged = onZoomChanged
        self.onShortcutPalette = onShortcutPalette
        isConfigured = true
    }

    public override func didMoveToWindow() {
        super.didMoveToWindow()
        if window == nil, isConfigured {
            releaseAllKeys()
        }
    }

    public func releaseAllKeys() {
        activeRightClickPoint = nil
        onEvent?(.releaseAll(sessionID: sessionID, displayID: displayID))
    }

    public func insertText(_ text: String) {
        guard !text.isEmpty else { return }
        onEvent?(.textCommit(sessionID: sessionID, displayID: displayID, text: text))
    }

    public func deleteBackward() {
        emitPhysicalKey(hidUsage: 0x2A, logicalKey: "Backspace", modifiers: [], state: .down, isRepeat: false)
        emitPhysicalKey(hidUsage: 0x2A, logicalKey: "Backspace", modifiers: [], state: .up, isRepeat: false)
    }

    public override func pressesBegan(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        let handled = emitPresses(presses, state: .down)
        if !handled { super.pressesBegan(presses, with: event) }
    }

    public override func pressesChanged(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        let handled = emitPresses(presses, state: .repeat)
        if !handled { super.pressesChanged(presses, with: event) }
    }

    public override func pressesEnded(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        let handled = emitPresses(presses, state: .up)
        if !handled { super.pressesEnded(presses, with: event) }
    }

    public override func pressesCancelled(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        _ = emitPresses(presses, state: .up)
        releaseAllKeys()
        super.pressesCancelled(presses, with: event)
    }

    private func installGestures() {
        let pointerPan = UIPanGestureRecognizer(target: self, action: #selector(handlePointerPan(_:)))
        pointerPan.minimumNumberOfTouches = 1
        pointerPan.maximumNumberOfTouches = 1
        pointerPan.delegate = self

        let singleTap = UITapGestureRecognizer(target: self, action: #selector(handleSingleTap(_:)))
        singleTap.numberOfTapsRequired = 1
        singleTap.numberOfTouchesRequired = 1

        let doubleTap = UITapGestureRecognizer(target: self, action: #selector(handleDoubleTap(_:)))
        doubleTap.numberOfTapsRequired = 2
        doubleTap.numberOfTouchesRequired = 1
        singleTap.require(toFail: doubleTap)

        let rightClick = UILongPressGestureRecognizer(target: self, action: #selector(handleRightClick(_:)))
        rightClick.minimumPressDuration = 0.45
        rightClick.allowableMovement = 20

        let wheelPan = UIPanGestureRecognizer(target: self, action: #selector(handleWheel(_:)))
        wheelPan.minimumNumberOfTouches = 2
        wheelPan.maximumNumberOfTouches = 2
        wheelPan.delegate = self

        let pinch = UIPinchGestureRecognizer(target: self, action: #selector(handlePinch(_:)))
        pinch.delegate = self

        let shortcutTap = UITapGestureRecognizer(target: self, action: #selector(handleShortcutPalette(_:)))
        shortcutTap.numberOfTouchesRequired = 3
        shortcutTap.numberOfTapsRequired = 1

        [pointerPan, singleTap, doubleTap, rightClick, wheelPan, pinch, shortcutTap].forEach(addGestureRecognizer)
    }

    @objc private func handlePointerPan(_ recognizer: UIPanGestureRecognizer) {
        guard recognizer.state == .began || recognizer.state == .changed,
              let point = mappedPoint(recognizer.location(in: self)) else { return }
        onEvent?(.pointer(sessionID: sessionID, displayID: displayID, point: point))
    }

    @objc private func handleSingleTap(_ recognizer: UITapGestureRecognizer) {
        guard let point = mappedPoint(recognizer.location(in: self)) else { return }
        emitClick(point: point, button: .left, count: 1)
    }

    @objc private func handleDoubleTap(_ recognizer: UITapGestureRecognizer) {
        guard let point = mappedPoint(recognizer.location(in: self)) else { return }
        emitClick(point: point, button: .left, count: 2)
    }

    @objc private func handleRightClick(_ recognizer: UILongPressGestureRecognizer) {
        switch recognizer.state {
        case .began:
            guard let point = mappedPoint(recognizer.location(in: self)) else { return }
            activeRightClickPoint = point
            onEvent?(.button(
                sessionID: sessionID,
                displayID: displayID,
                point: point,
                button: .right,
                state: .down
            ))
        case .ended, .cancelled, .failed:
            guard let point = activeRightClickPoint else { return }
            activeRightClickPoint = nil
            onEvent?(.button(
                sessionID: sessionID,
                displayID: displayID,
                point: point,
                button: .right,
                state: .up
            ))
        default:
            break
        }
    }

    @objc private func handleWheel(_ recognizer: UIPanGestureRecognizer) {
        guard recognizer.state == .began || recognizer.state == .changed else { return }
        let delta = recognizer.translation(in: self)
        recognizer.setTranslation(.zero, in: self)
        onEvent?(.wheel(
            sessionID: sessionID,
            displayID: displayID,
            deltaX: Double(-delta.x),
            deltaY: Double(-delta.y)
        ))
    }

    @objc private func handlePinch(_ recognizer: UIPinchGestureRecognizer) {
        guard recognizer.state == .began || recognizer.state == .changed else { return }
        zoomScale = min(4, max(1, zoomScale * recognizer.scale))
        recognizer.scale = 1
        onZoomChanged?(zoomScale)
    }

    @objc private func handleShortcutPalette(_ recognizer: UITapGestureRecognizer) {
        guard recognizer.state == .ended else { return }
        onShortcutPalette?()
    }

    public func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        gestureRecognizer is UIPinchGestureRecognizer || otherGestureRecognizer is UIPinchGestureRecognizer
    }

    private func mappedPoint(_ point: CGPoint) -> NormalizedPoint? {
        RemoteViewportMapper(
            remoteSize: remoteSize,
            viewportSize: bounds.size,
            zoomScale: zoomScale
        ).normalized(point)
    }

    private func emitClick(point: NormalizedPoint, button: MouseButton, count: Int) {
        for _ in 0..<count {
            onEvent?(.button(
                sessionID: sessionID,
                displayID: displayID,
                point: point,
                button: button,
                state: .down
            ))
            onEvent?(.button(
                sessionID: sessionID,
                displayID: displayID,
                point: point,
                button: button,
                state: .up
            ))
        }
    }

    private func emitPresses(_ presses: Set<UIPress>, state: KeyEventKind) -> Bool {
        var handled = false
        for press in presses {
            guard let key = press.key else { continue }
            handled = true
            emitPhysicalKey(
                hidUsage: UInt32(key.keyCode.rawValue),
                logicalKey: key.charactersIgnoringModifiers,
                modifiers: modifierNames(key.modifierFlags),
                state: state,
                isRepeat: key.isRepeat
            )
        }
        return handled
    }

    private func emitPhysicalKey(
        hidUsage: UInt32,
        logicalKey: String,
        modifiers: [String],
        state: KeyEventKind,
        isRepeat: Bool
    ) {
        onEvent?(InputEvent(
            sessionID: sessionID,
            displayID: displayID,
            inputKind: .physicalKey,
            keyEventKind: state,
            physicalCode: hidUsage,
            keyCode: hidUsage,
            logicalKey: logicalKey,
            modifiers: modifiers,
            keyboardLayout: UITextInputMode.currentInputMode?.primaryLanguage,
            isAutoRepeat: isRepeat
        ))
    }

    private func modifierNames(_ flags: UIKeyModifierFlags) -> [String] {
        var values: [String] = []
        if flags.contains(.control) { values.append("ctrl") }
        if flags.contains(.alternate) { values.append("alt") }
        if flags.contains(.shift) { values.append("shift") }
        if flags.contains(.command) { values.append("meta") }
        if flags.contains(.alphaShift) { values.append("caps_lock") }
        return values
    }
}
