import Cocoa
import SwiftUI

/// Floating panel hosting the password manager, similar to iTerm2's.
///
/// The panel remembers the terminal surface that was focused when it was
/// opened and types the selected credential into it.
class PasswordManagerController: NSWindowController, NSWindowDelegate {
    static let shared = PasswordManagerController()

    /// The surface that credentials will be typed into.
    private weak var targetSurface: Ghostty.SurfaceView?

    /// True while we're auto-opened for a password prompt; prevents
    /// re-opening in a loop for the same prompt.
    private var autoOpened = false

    private init() {
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

    /// Show the panel targeting the currently focused terminal surface.
    func show(for surface: Ghostty.SurfaceView? = nil) {
        targetSurface = surface ?? Self.currentFocusedSurface()
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
            show(for: surface)
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
        guard let surface = targetSurface ?? Self.currentFocusedSurface(),
              let model = surface.surfaceModel else {
            NSSound.beep()
            return
        }
        model.sendText(text)
        window?.close()
        surface.window?.makeKeyAndOrderFront(nil)
        Ghostty.moveFocus(to: surface)
    }

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
