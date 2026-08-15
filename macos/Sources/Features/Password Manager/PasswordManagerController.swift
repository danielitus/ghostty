import Cocoa
import SwiftUI

/// Floating panel hosting the password manager, similar to iTerm2's.
///
/// Credentials are typed into the frontmost terminal surface, resolved at
/// send time — never a surface captured earlier. The panel floats across
/// focus changes, so a target remembered at open time could silently go
/// stale and type a password into the wrong terminal.
class PasswordManagerController: NSWindowController, NSWindowDelegate {
    static let shared = PasswordManagerController()

    /// True while we're auto-opened for a password prompt; prevents
    /// re-opening in a loop for the same prompt.
    private var autoOpened = false

    private init() {
        // Locking when the panel closes is the safe default; an explicit
        // user opt-out is still respected.
        UserDefaults.standard.register(defaults: ["PasswordManagerLockOnClose": true])

        let panel = NSPanel(
            contentRect: .zero,
            styleMask: [.titled, .closable, .utilityWindow],
            backing: .buffered,
            defer: true)
        panel.title = "Password Manager"
        panel.isFloatingPanel = true
        panel.becomesKeyOnlyIfNeeded = false
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        panel.delegate = self
        panel.contentView = NSHostingView(rootView: PasswordManagerView(
            onSend: { [weak self] text in self?.send(text) }))
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - Showing

    /// Show the panel. The send target is resolved at send time, not here.
    func show() {
        guard let window else { return }
        if !window.isVisible { window.center() }
        window.makeKeyAndOrderFront(nil)
    }

    /// Called when a password prompt is detected on a surface. Opens the
    /// panel if the user has enabled auto-open.
    func passwordPromptDetected(on surface: Ghostty.SurfaceView, active: Bool) {
        guard UserDefaults.standard.bool(forKey: "PasswordManagerAutoOpen") else { return }

        if active {
            guard !(window?.isVisible ?? false) else { return }
            autoOpened = true
            show()
        } else if autoOpened {
            autoOpened = false
            window?.close()
        }
    }

    func toggle() {
        if window?.isVisible ?? false {
            window?.close()
        } else {
            show()
        }
    }

    // MARK: - Sending

    private func send(_ text: String) {
        // Resolve the target now: the focused surface of the frontmost
        // terminal window. Anything remembered from when the panel opened
        // could point at a terminal the user has since switched away from.
        guard let surface = Self.currentFocusedSurface(),
              surface.window != nil,
              let model = surface.surfaceModel else {
            NSSound.beep()
            return
        }
        model.sendText(text)
        window?.close()
        surface.window?.makeKeyAndOrderFront(nil)
        Ghostty.moveFocus(to: surface)
    }

    /// The focused surface of the frontmost (z-ordered) terminal window.
    private static func currentFocusedSurface() -> Ghostty.SurfaceView? {
        for win in NSApp.orderedWindows {
            if let controller = win.windowController as? BaseTerminalController,
               let surface = controller.focusedSurface {
                return surface
            }
        }
        return nil
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        autoOpened = false
        if UserDefaults.standard.bool(forKey: "PasswordManagerLockOnClose") {
            PasswordVault.shared.lock()
        }
    }

    @objc func cancel(_ sender: Any?) {
        window?.close()
    }
}
