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
    static func broadcastKey(_ event: ghostty_input_key_s, from source: Ghostty.SurfaceView) {
        for peer in peers(of: source) {
            guard let surface = peer.surface else { continue }
            _ = ghostty_surface_key(surface, event)
        }
    }

    /// Send pasted text from `source` to its peers. Each peer applies its own
    /// bracketed paste mode.
    static func broadcastPaste(_ text: String, from source: Ghostty.SurfaceView) {
        guard !text.isEmpty else { return }
        for peer in peers(of: source) {
            peer.surfaceModel?.sendText(text)
        }
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
