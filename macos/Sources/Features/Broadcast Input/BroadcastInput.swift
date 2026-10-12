import AppKit
import GhosttyKit

/// iTerm2-style broadcast input: keystrokes and pastes typed into the focused
/// terminal are also sent to the other terminals of the current tab, or of
/// every tab in the current window.
///
/// The mode lives on each `BaseTerminalController` (one per native tab).
/// `all_tabs` is effective for the whole tab group when any tab in it has
/// it set, so tabs opened while broadcasting join automatically.
///
/// Only input typed into a terminal is broadcast. Key presses that trigger a
/// keybind are never forwarded (so ⌘W doesn't close every peer), and text
/// sent programmatically (the password manager, AppleScript, services) goes
/// to its own surface only.
@MainActor
enum BroadcastInput {
    enum Mode {
        case off
        case currentTab
        case allTabs

        init(_ c: ghostty_action_broadcast_input_e) {
            switch c {
            case GHOSTTY_BROADCAST_INPUT_CURRENT_TAB: self = .currentTab
            case GHOSTTY_BROADCAST_INPUT_ALL_TABS: self = .allTabs
            default: self = .off
            }
        }
    }

    // MARK: Mode

    /// Toggle `requested` for the window containing `surface`. Requesting
    /// the mode that's already active turns broadcasting off.
    static func toggle(_ requested: Mode, from surface: Ghostty.SurfaceView) {
        guard let controller = controller(of: surface) else { return }
        let group = tabGroupControllers(of: controller)
        let next: Mode = requested == effectiveMode(for: controller) ? .off : requested

        // all_tabs is shared by the group, current_tab belongs to this tab.
        for c in group where c.broadcastInputMode == .allTabs {
            c.broadcastInputMode = .off
        }
        controller.broadcastInputMode = .off

        switch next {
        case .off:
            break
        case .currentTab:
            controller.broadcastInputMode = .currentTab
        case .allTabs:
            group.forEach { $0.broadcastInputMode = .allTabs }
        }

        refreshIndicators(for: controller)
    }

    /// The mode in effect for a tab.
    static func effectiveMode(for controller: BaseTerminalController) -> Mode {
        if tabGroupControllers(of: controller).contains(where: { $0.broadcastInputMode == .allTabs }) {
            return .allTabs
        }
        return controller.broadcastInputMode == .currentTab ? .currentTab : .off
    }

    /// Update the broadcast indicator on every surface in the tab group of
    /// `controller`. Call whenever the mode or the set of surfaces changes.
    static func refreshIndicators(for controller: BaseTerminalController) {
        for c in tabGroupControllers(of: controller) {
            let active = effectiveMode(for: c) != .off
            for surface in c.surfaceTree where surface.broadcastInputActive != active {
                surface.broadcastInputActive = active
            }
        }
    }

    // MARK: Targets

    /// The surfaces that should receive input typed into `surface`, not
    /// including `surface` itself. Empty when broadcasting is off.
    static func peers(of surface: Ghostty.SurfaceView) -> [Ghostty.SurfaceView] {
        guard let controller = controller(of: surface) else { return [] }

        let candidates: [Ghostty.SurfaceView]
        switch effectiveMode(for: controller) {
        case .off:
            return []
        case .currentTab:
            candidates = Array(controller.surfaceTree)
        case .allTabs:
            candidates = tabGroupControllers(of: controller).flatMap { Array($0.surfaceTree) }
        }

        return candidates.filter { $0 !== surface && $0.surface != nil }
    }

    /// Send a key event typed into `source` to its peers. The caller must
    /// already have checked that the event is not a keybind on `source`.
    /// `event.text` only needs to be valid for the duration of this call.
    ///
    /// A peer delivers the key through its own key handling, so a key that
    /// is a binding there (its own config, an active key table, or the
    /// next key of a pending sequence) is skipped for that peer: typing
    /// into one terminal must never run an action in another.
    ///
    /// `recipients` limits delivery to the peers that received the key's
    /// press (for its repeats and release); otherwise all current peers
    /// are targeted. Returns the peers the event was delivered to.
    @discardableResult
    static func broadcastKey(
        _ event: ghostty_input_key_s,
        from source: Ghostty.SurfaceView,
        to recipients: [Ghostty.SurfaceView]? = nil
    ) -> [Ghostty.SurfaceView] {
        var delivered: [Ghostty.SurfaceView] = []
        for peer in recipients ?? peers(of: source) {
            guard peer !== source, let surface = peer.surface else { continue }
            if event.action != GHOSTTY_ACTION_RELEASE,
               ghostty_surface_key_is_binding(surface, event, nil) {
                continue
            }
            _ = ghostty_surface_key(surface, event)
            delivered.append(peer)
        }
        return delivered
    }

    /// A peer that received a broadcast key press, held weakly so a closed
    /// terminal isn't kept alive by a held key.
    struct Recipient {
        weak var view: Ghostty.SurfaceView?
        init(_ view: Ghostty.SurfaceView) { self.view = view }
    }

    /// Send pasted text from `source` to its peers. Each peer applies its own
    /// bracketed paste mode.
    ///
    /// Text sent to a peer bypasses that peer's paste protection, and a
    /// peer at a shell without bracketed paste runs each line as it
    /// arrives, whatever the source terminal accepted. So a paste that
    /// paste protection would flag (several lines, or a bracketed paste
    /// terminator) is only broadcast after the user confirms it for the
    /// other terminals.
    static func broadcastPaste(_ text: String, from source: Ghostty.SurfaceView) {
        guard !text.isEmpty else { return }
        let count = peers(of: source).count
        guard count > 0 else { return }

        let protect = (NSApp.delegate as? AppDelegate)?.ghostty.config.clipboardPasteProtection ?? true
        guard protect, isUnsafePaste(text), let window = source.window else {
            send(text, from: source)
            return
        }

        let lines = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).count
        let alert = NSAlert()
        alert.messageText = "Paste into \(count) other \(count == 1 ? "terminal" : "terminals")?"
        alert.informativeText = "This paste has \(lines) lines. Broadcast input sends it to "
            + "every terminal it targets, where a shell without bracketed paste "
            + "runs each line as a command."
        alert.addButton(withTitle: "Paste in All")
        alert.addButton(withTitle: "Only This Terminal")
        alert.alertStyle = .warning
        alert.beginSheetModal(for: window) { [weak source] response in
            guard response == .alertFirstButtonReturn, let source else { return }
            MainActor.assumeIsolated { send(text, from: source) }
        }
    }

    private static func send(_ text: String, from source: Ghostty.SurfaceView) {
        for peer in peers(of: source) {
            peer.surfaceModel?.sendText(text)
        }
    }

    /// Mirrors the core's paste safety check: newlines can execute
    /// commands, and a bracketed paste end sequence can break out of
    /// bracketed paste.
    static func isUnsafePaste(_ text: String) -> Bool {
        text.contains(where: \.isNewline) || text.contains("\u{1b}[201~")
    }

    // MARK: Helpers

    private static func controller(of surface: Ghostty.SurfaceView) -> BaseTerminalController? {
        surface.window?.windowController as? BaseTerminalController
    }

    /// All controllers in the native tab group of `controller`, including itself.
    private static func tabGroupControllers(of controller: BaseTerminalController) -> [BaseTerminalController] {
        guard let window = controller.window else { return [controller] }
        let windows = window.tabbedWindows ?? [window]
        let controllers = windows.compactMap { $0.windowController as? BaseTerminalController }
        return controllers.isEmpty ? [controller] : controllers
    }
}

extension Array where Element == Ghostty.ClipboardContent {
    /// The `text/plain` representation, if present and valid UTF-8.
    var plainText: String? {
        first(where: { $0.mime == "text/plain" })?.string
    }
}
