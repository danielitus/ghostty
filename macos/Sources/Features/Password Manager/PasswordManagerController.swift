import Cocoa
import SwiftUI

/// Where the next credential will be typed, for display in the panel.
/// `nil` means there is currently no terminal to send to.
@MainActor
final class PasswordManagerTarget: ObservableObject {
    @Published var title: String?
}

/// Floating panel hosting the password manager, similar to iTerm2's.
///
/// Credentials are typed into the frontmost terminal surface, resolved at
/// send time — never a surface captured earlier. The panel floats across
/// focus changes, so a target remembered at open time could silently go
/// stale and type a password into the wrong terminal. The resolved target
/// is shown in the panel so the user can see where a send will land.
class PasswordManagerController: NSWindowController, NSWindowDelegate {
    static let shared = PasswordManagerController()

    let target = PasswordManagerTarget()

    /// True while the panel is being made key. The Quick Terminal checks
    /// this so it does not auto-hide when it loses key status to us; if
    /// it hid, Send would land in whichever terminal was behind it.
    private(set) var isTakingKeyWindow = false

    /// The surface whose password prompt auto-opened the panel. Only that
    /// surface's prompt ending closes the panel again; another terminal
    /// finishing its own prompt must not close (and lock) ours.
    private weak var autoOpenSurface: Ghostty.SurfaceView?

    private var observers: [NSObjectProtocol] = []

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
            target: target,
            onSend: { [weak self] text, pressEnter in
                self?.send(text, pressEnter: pressEnter)
            }))

        // Keep the displayed target in step with window ordering.
        let center = NotificationCenter.default
        for name in [
            NSWindow.didBecomeKeyNotification,
            NSWindow.didResignKeyNotification,
            NSWindow.didBecomeMainNotification,
            NSWindow.willCloseNotification,
        ] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) {
                [weak self] _ in
                self?.refreshTarget()
            })
        }
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - Showing

    /// Show the panel. The send target is resolved at send time, not here.
    func show() {
        guard let window else { return }
        let wasVisible = window.isVisible
        if !wasVisible { window.center() }

        // Resolve the target before we take key status so the label
        // reflects the terminal the user was just looking at.
        refreshTarget()

        isTakingKeyWindow = true
        window.makeKeyAndOrderFront(nil)
        isTakingKeyWindow = false

        // Opening a locked vault with Touch ID enabled goes straight to the
        // biometric prompt, so a password prompt in the terminal becomes:
        // panel appears, touch the sensor, pick an entry. Only on a fresh
        // open; re-raising an already visible panel shouldn't re-prompt.
        let vault = PasswordVault.shared
        if !wasVisible, vault.state == .locked,
           vault.biometricsEnabled, vault.biometricsAvailable {
            NotificationCenter.default.post(
                name: PasswordVault.biometricUnlockRequested, object: nil)
        }
    }

    /// Called when a password prompt appears (active) or goes away on a
    /// surface. Opens the panel if the user has enabled auto-open; closes
    /// it only when the prompt that opened it ends.
    func passwordPromptDetected(active: Bool, on surface: Ghostty.SurfaceView) {
        guard UserDefaults.standard.bool(forKey: "PasswordManagerAutoOpen") else { return }

        if active {
            guard surface.focused else { return }
            guard !(window?.isVisible ?? false) else { return }
            autoOpenSurface = surface
            show()
        } else if let origin = autoOpenSurface, origin === surface {
            autoOpenSurface = nil
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

    private func send(_ text: String, pressEnter: Bool) {
        // Resolve the target now: the focused surface of the frontmost
        // terminal window. Anything remembered from when the panel opened
        // could point at a terminal the user has since switched away from.
        guard let surface = Self.currentFocusedSurface(),
              let targetWindow = surface.window,
              let model = surface.surfaceModel else {
            NSSound.beep()
            refreshTarget()
            return
        }

        model.sendText(text)
        if pressEnter {
            // A real key event, not "\r" appended to the text: sendText
            // goes through the paste path, and inside a bracketed paste a
            // carriage return is inserted literally instead of submitting.
            model.sendKeyEvent(Ghostty.Input.KeyEvent(key: .enter, action: .press))
            model.sendKeyEvent(Ghostty.Input.KeyEvent(key: .enter, action: .release))
        }

        window?.close()
        targetWindow.makeKeyAndOrderFront(nil)
        Ghostty.moveFocus(to: surface)
    }

    /// The focused surface of the frontmost visible terminal window,
    /// panels included. `NSApp.orderedWindows` leaves panels out and the
    /// Quick Terminal is one, so all visible windows are walked by their
    /// z-order instead.
    static func currentFocusedSurface() -> Ghostty.SurfaceView? {
        let terminals = NSApp.windows
            .filter { $0.isVisible && !$0.isMiniaturized && $0.windowController is BaseTerminalController }
            .sorted { $0.orderedIndex < $1.orderedIndex }
        for win in terminals {
            if let controller = win.windowController as? BaseTerminalController,
               let surface = controller.focusedSurface,
               surface.window === win {
                return surface
            }
        }
        return nil
    }

    private func refreshTarget() {
        guard let surface = Self.currentFocusedSurface() else {
            target.title = nil
            return
        }
        let windowTitle = surface.window?.title ?? ""
        target.title = windowTitle.isEmpty ? surface.title : windowTitle
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        autoOpenSurface = nil
        if UserDefaults.standard.bool(forKey: "PasswordManagerLockOnClose") {
            PasswordVault.shared.lock()
        }
    }

    @objc func cancel(_ sender: Any?) {
        window?.close()
    }
}
