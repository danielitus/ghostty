import Cocoa
import SwiftUI

/// Window for searching everything the terminals have printed, through the
/// session logs in `session-log-directory`.
class SessionLogSearchController: NSWindowController, NSWindowDelegate {
    static let shared = SessionLogSearchController()

    let model = SessionLogSearchModel()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 520),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: true)
        window.title = "Search Session Logs"
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("SessionLogSearch")
        window.minSize = NSSize(width: 480, height: 300)
        super.init(window: window)
        window.delegate = self
        window.contentView = NSHostingView(rootView: SessionLogSearchView(
            model: model,
            onOpen: { [weak self] hit in self?.open(hit) }))
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    func show(config: Ghostty.Config) {
        model.directory = config.sessionLogDirectory.map {
            URL(fileURLWithPath: $0, isDirectory: true)
        }
        if !(window?.isVisible ?? false) { window?.center() }
        window?.makeKeyAndOrderFront(nil)
        model.focusRequest += 1
        // Logs grow while the window is closed; refresh what's shown.
        model.run(debounce: false)
    }

    /// Open the log at the hit in a new tab of the frontmost terminal
    /// window, paged with `less` so colors render and `q` closes it.
    private func open(_ hit: SessionLogSearch.Hit) {
        guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
        var config = Ghostty.SurfaceConfiguration()
        // -j.3 puts the hit a third of the way down rather than on the
        // top line, so the output leading up to it is visible.
        config.command = "shell:less -R -j.3 +\(hit.line)g -- \(Self.shellQuote(hit.file.path))"
        config.workingDirectory = hit.file.deletingLastPathComponent().path
        let parent = PasswordManagerController.currentFocusedSurface()?.window
        _ = TerminalController.newTab(appDelegate.ghostty, from: parent, withBaseConfig: config)
    }

    nonisolated static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        model.cancel()
    }
}

/// Query and results for the search window. Each query change cancels the
/// running scan and starts a new one after a short pause in typing.
@MainActor
final class SessionLogSearchModel: ObservableObject {
    @Published var query = ""
    @Published private(set) var results: [SessionLogSearch.FileResult] = []
    @Published private(set) var searching = false
    @Published var directory: URL?

    /// Bumped to ask the view to focus the search field.
    @Published var focusRequest = 0

    private var task: Task<Void, Never>?

    var hitCount: Int { results.reduce(0) { $0 + $1.hits.count } }

    func run(debounce: Bool = true) {
        task?.cancel()
        let query = self.query
        guard let directory, !query.isEmpty else {
            results = []
            searching = false
            return
        }

        searching = true
        task = Task { [weak self] in
            if debounce {
                try? await Task.sleep(for: .milliseconds(250))
            }
            guard !Task.isCancelled else { return }
            let found = await SessionLogSearch.search(query, in: directory)
            guard !Task.isCancelled, let self else { return }
            self.results = found
            self.searching = false
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        searching = false
    }
}

struct SessionLogSearchView: View {
    @ObservedObject var model: SessionLogSearchModel
    var onOpen: (SessionLogSearch.Hit) -> Void

    @State private var selection: SessionLogSearch.Hit.ID?
    @FocusState private var fieldFocused: Bool

    private var selectedHit: SessionLogSearch.Hit? {
        guard let selection else { return nil }
        for file in model.results {
            if let hit = file.hits.first(where: { $0.id == selection }) { return hit }
        }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search all terminal output", text: $model.query)
                    .textFieldStyle(.plain)
                    .focused($fieldFocused)
                    .onSubmit {
                        if let hit = selectedHit ?? model.results.first?.hits.first {
                            onOpen(hit)
                        }
                    }
                if model.searching {
                    ProgressView().controlSize(.small)
                }
            }
            .padding(8)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            .padding(10)

            Divider()

            content

            Divider()

            footer
        }
        .frame(minWidth: 480, minHeight: 300)
        .onChange(of: model.query) { _ in model.run() }
        .onChange(of: model.focusRequest) { _ in fieldFocused = true }
        .onAppear { fieldFocused = true }
    }

    @ViewBuilder
    private var content: some View {
        if model.directory == nil {
            placeholder(
                "Session Logging Is Off",
                systemImage: "doc.text.magnifyingglass",
                detail: "Set session-log-directory in your Ghostty config to record terminal output.")
        } else if model.query.isEmpty {
            placeholder(
                "Search Session Logs",
                systemImage: "doc.text.magnifyingglass",
                detail: "Finds text in everything your terminals have printed, newest session first.")
        } else if model.results.isEmpty && !model.searching {
            placeholder("No Results", systemImage: "magnifyingglass", detail: nil)
        } else {
            List(selection: $selection) {
                ForEach(model.results) { file in
                    Section(header: sectionHeader(file)) {
                        ForEach(file.hits) { hit in
                            row(hit)
                                .tag(hit.id)
                                .contentShape(Rectangle())
                                .simultaneousGesture(TapGesture(count: 2).onEnded {
                                    selection = hit.id
                                    onOpen(hit)
                                })
                                .contextMenu {
                                    Button("Open in New Tab") { onOpen(hit) }
                                    Button("Copy Line") { copy(hit.text) }
                                    Divider()
                                    Button("Show in Finder") {
                                        NSWorkspace.shared.activateFileViewerSelecting([hit.file])
                                    }
                                }
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private func row(_ hit: SessionLogSearch.Hit) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(hit.line)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.tertiary)
                .frame(minWidth: 44, alignment: .trailing)
            Text(highlighted(hit.text))
                .font(.system(.body, design: .monospaced))
                .lineLimit(2)
                .truncationMode(.tail)
        }
        .padding(.vertical, 1)
    }

    private func sectionHeader(_ file: SessionLogSearch.FileResult) -> some View {
        HStack {
            if let started = file.started {
                Text(started.formatted(date: .abbreviated, time: .shortened))
            }
            Text(file.file.lastPathComponent)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Text(file.hits.count == 1 ? "1 match" : "\(file.hits.count) matches")
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if !model.query.isEmpty && !model.results.isEmpty {
                let hits = model.hitCount
                let sessions = model.results.count
                let capped = hits >= SessionLogSearch.maxHits ? " (showing the first \(hits))" : ""
                Text("\(hits) \(hits == 1 ? "match" : "matches") in \(sessions) \(sessions == 1 ? "session" : "sessions")\(capped)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if let directory = model.directory {
                Text(directory.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            Button("Show in Finder") {
                if let hit = selectedHit {
                    NSWorkspace.shared.activateFileViewerSelecting([hit.file])
                } else if let directory = model.directory {
                    NSWorkspace.shared.open(directory)
                }
            }
            .disabled(model.directory == nil)
            Button("Open in New Tab") {
                if let hit = selectedHit { onOpen(hit) }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(selectedHit == nil)
        }
        .padding(10)
    }

    private func placeholder(_ title: String, systemImage: String, detail: String?) -> some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.system(size: 28))
                .foregroundStyle(.tertiary)
            Text(title)
                .font(.headline)
                .foregroundStyle(.secondary)
            if let detail {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The line with every occurrence of the query highlighted.
    private func highlighted(_ text: String) -> AttributedString {
        var attributed = AttributedString(text)
        let query = model.query
        guard !query.isEmpty else { return attributed }
        var searchRange = text.startIndex..<text.endIndex
        while let range = text.range(of: query, options: .caseInsensitive, range: searchRange) {
            if let lo = AttributedString.Index(range.lowerBound, within: attributed),
               let hi = AttributedString.Index(range.upperBound, within: attributed) {
                attributed[lo..<hi].backgroundColor = .yellow.opacity(0.35)
                attributed[lo..<hi].inlinePresentationIntent = .stronglyEmphasized
            }
            searchRange = range.upperBound..<text.endIndex
        }
        return attributed
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
