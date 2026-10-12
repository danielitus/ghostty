import Foundation

/// Full-text search over the raw session logs written to
/// `session-log-directory`.
///
/// Logs are raw pty output, so each line is stripped of escape sequences
/// and control characters before matching. Lines are split on `\n` only,
/// and every line is counted, matched or not, so a hit's line number is
/// its line in the raw file and `less +<line>g` lands on it.
enum SessionLogSearch {
    struct Hit: Identifiable, Hashable {
        let id = UUID()
        let file: URL
        /// 1-based line number in the raw log file.
        let line: Int
        /// The line with escape sequences removed.
        let text: String
    }

    struct FileResult: Identifiable, Hashable {
        var id: URL { file }
        let file: URL
        /// When the session started, from the file name.
        let started: Date?
        let hits: [Hit]
    }

    /// Stop after this many hits in total, and per file, so a common word
    /// returns quickly and one noisy session can't crowd out the others.
    static let maxHits = 500
    static let maxHitsPerFile = 100

    /// Display width kept around a match in very long lines.
    static let maxLineLength = 400

    /// Visible text buffered per line before a very long line is searched
    /// and trimmed, so memory stays bounded.
    static let maxSegment = 64 * 1024

    /// Check for cancellation every this many bytes (1 MiB).
    static let cancelCheckMask = (1 << 20) - 1

    /// Longest query searched for, in UTF-8 bytes.
    static let maxQueryLength = 1024

    /// The log files in `directory`, newest first.
    static func logFiles(in directory: URL) -> [URL] {
        let keys: [URLResourceKey] = [.contentModificationDateKey, .isRegularFileKey]
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]
        ) else { return [] }
        let dated: [(URL, Date)] = urls.compactMap { url in
            guard url.pathExtension == "log",
                  let values = try? url.resourceValues(forKeys: Set(keys)),
                  values.isRegularFile == true else { return nil }
            return (url, values.contentModificationDate ?? .distantPast)
        }
        return dated.sorted { $0.1 > $1.1 }.map(\.0)
    }

    /// Search every log in `directory` for `query`, case-insensitively,
    /// newest session first. Checks for cancellation between files and
    /// periodically within one.
    @concurrent static func search(_ query: String, in directory: URL) async -> [FileResult] {
        let needle = Array(query.utf8).map(lowerASCII)
        guard !needle.isEmpty, needle.count <= maxQueryLength else { return [] }

        var results: [FileResult] = []
        var total = 0
        for file in logFiles(in: directory) {
            if Task.isCancelled || total >= maxHits { break }
            let hits = search(needle, in: file, limit: min(maxHitsPerFile, maxHits - total))
            guard !hits.isEmpty else { continue }
            total += hits.count
            results.append(.init(file: file, started: startDate(of: file), hits: hits))
        }
        return results
    }

    private static func search(_ needle: [UInt8], in file: URL, limit: Int) -> [Hit] {
        // Mapped, so a large log isn't copied into memory.
        guard let data = try? Data(contentsOf: file, options: .alwaysMapped) else { return [] }

        var hits: [Hit] = []
        // The current line's visible text. A very long line (full-screen
        // programs can write megabytes without a newline) is searched each
        // time this fills, keeping only enough of its end to complete a
        // match that started there and to show some context before it.
        let capacity = max(maxSegment, needle.count * 2)
        let keep = max(needle.count - 1, maxLineLength / 2)
        var visible: [UInt8] = []
        visible.reserveCapacity(capacity + 1)

        let matcher = Matcher(needle)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var stripper = Stripper()
            var lineNumber = 1
            // A hit found on a long line before its end, and the line
            // length it needs: later backspaces can still erase it, so it
            // only counts if the line still reaches that far at its end.
            var provisional: Hit?
            var provisionalEnd = 0
            // Checked per byte instead of `provisional`, which would copy
            // the hit (URL and all) every time.
            var hasProvisional = false
            // Visible bytes of this line trimmed from the front of the
            // buffer, so `trimmed + visible.count` is the line's length.
            var trimmed = 0

            for i in 0..<bytes.count {
                // Bounded by bytes, not lines, so cancelling is prompt even
                // inside one enormous line. Matching work is bounded by the
                // buffer, so this covers it too.
                if i & cancelCheckMask == 0, i > 0, Task.isCancelled { return }

                let c = bytes[i]
                if c == 0x0A {
                    if let hit = provisional {
                        hits.append(hit)
                    } else if let found = find(matcher, in: visible, file: file, line: lineNumber) {
                        hits.append(found.hit)
                    }
                    if hits.count >= limit { return }
                    visible.removeAll(keepingCapacity: true)
                    stripper = Stripper()
                    provisional = nil
                    hasProvisional = false
                    trimmed = 0
                    lineNumber += 1
                    continue
                }

                stripper.feed(c, into: &visible)
                if stripper.erasedBeforeBuffer > 0 {
                    // Backspaces reaching into the trimmed part of the line.
                    trimmed -= min(trimmed, stripper.erasedBeforeBuffer)
                    stripper.erasedBeforeBuffer = 0
                }
                if hasProvisional && trimmed + visible.count < provisionalEnd {
                    provisional = nil
                    hasProvisional = false
                }

                guard visible.count >= capacity else { continue }
                if !hasProvisional,
                   let found = find(matcher, in: visible, file: file, line: lineNumber) {
                    provisional = found.hit
                    provisionalEnd = trimmed + found.end
                    hasProvisional = true
                }
                // The hit's text is already in `provisional`, so the buffer
                // can be trimmed either way.
                let removed = visible.count - keep
                visible.removeFirst(removed)
                trimmed += removed
            }

            if let hit = provisional {
                hits.append(hit)
            } else if let found = find(matcher, in: visible, file: file, line: lineNumber) {
                hits.append(found.hit)
            }
        }
        return Array(hits.prefix(limit))
    }

    /// A hit for the first match in `visible`, and the index just past it.
    private static func find(
        _ matcher: Matcher,
        in visible: [UInt8],
        file: URL,
        line: Int
    ) -> (hit: Hit, end: Int)? {
        guard let at = matcher.firstIndex(in: visible) else { return nil }
        let hit = Hit(
            file: file,
            line: line,
            text: display(visible, matchAt: at, matchLength: matcher.needle.count))
        return (hit, at + matcher.needle.count)
    }

    // MARK: Escape stripping

    /// Removes escape sequences and control characters from a byte stream,
    /// one byte at a time, so a sequence is recognized however the stream
    /// is chunked. Tabs are kept; backspace removes the previous character,
    /// so command lines echoed by a line editor read normally.
    struct Stripper {
        private enum State {
            case text, escape, csi, string, stringEscape, charset
        }

        private var state: State = .text

        /// Backspaces that found the output empty, since the caller last
        /// reset this.
        var erasedBeforeBuffer = 0

        mutating func feed(_ c: UInt8, into out: inout [UInt8]) {
            switch state {
            case .text:
                switch c {
                case 0x1B: state = .escape
                case 0x08:
                    // Drop one whole UTF-8 character. With nothing left to
                    // drop, the caller may have trimmed earlier text off the
                    // front; count it so it can track the line's length.
                    if out.isEmpty {
                        erasedBeforeBuffer += 1
                    } else {
                        while let last = out.popLast(), last & 0xC0 == 0x80 {}
                    }
                case 0x09: out.append(c)
                case 0x00..<0x20, 0x7F: break
                default: out.append(c)
                }
            case .escape:
                switch c {
                case UInt8(ascii: "["): state = .csi
                // OSC, DCS, APC, PM, SOS: a string until BEL or ST.
                case UInt8(ascii: "]"), UInt8(ascii: "P"), UInt8(ascii: "_"),
                     UInt8(ascii: "^"), UInt8(ascii: "X"): state = .string
                // Charset designation and similar: one more byte.
                case UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"),
                     UInt8(ascii: "+"), UInt8(ascii: "#"), UInt8(ascii: "%"): state = .charset
                default: state = .text
                }
            case .csi:
                if c == 0x1B {
                    state = .escape
                } else if (0x40...0x7E).contains(c) {
                    state = .text
                }
            case .string:
                if c == 0x07 {
                    state = .text
                } else if c == 0x1B {
                    state = .stringEscape
                }
            case .stringEscape:
                state = c == UInt8(ascii: "\\") ? .text : .string
            case .charset:
                state = .text
            }
        }
    }

    /// Strip `bytes[from..<to]` into `out`, replacing its contents.
    static func strip(
        _ bytes: UnsafeBufferPointer<UInt8>,
        from: Int,
        to end: Int,
        into out: inout [UInt8]
    ) {
        out.removeAll(keepingCapacity: true)
        var stripper = Stripper()
        for i in from..<end { stripper.feed(bytes[i], into: &out) }
    }

    // MARK: Matching

    @inline(__always)
    static func lowerASCII(_ c: UInt8) -> UInt8 {
        (0x41...0x5A).contains(c) ? c | 0x20 : c
    }

    /// First index of `needle` (already lowercased) in `haystack`, ignoring
    /// ASCII case.
    static func indexOf(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty else { return nil }
        return Matcher(needle).firstIndex(in: haystack)
    }

    /// Knuth-Morris-Pratt matching of a lowercased needle, ignoring ASCII
    /// case: linear in the text however repetitive it and the query are.
    struct Matcher {
        let needle: [UInt8]
        /// For each prefix length, the length of its longest proper
        /// prefix that is also a suffix.
        private let fallback: [Int]

        init(_ needle: [UInt8]) {
            self.needle = needle
            var fallback = [Int](repeating: 0, count: needle.count)
            var k = 0
            for i in 1..<max(needle.count, 1) {
                while k > 0 && needle[i] != needle[k] { k = fallback[k - 1] }
                if needle[i] == needle[k] { k += 1 }
                fallback[i] = k
            }
            self.fallback = fallback
        }

        func firstIndex(in haystack: [UInt8]) -> Int? {
            var k = 0
            for (i, raw) in haystack.enumerated() {
                let c = SessionLogSearch.lowerASCII(raw)
                while k > 0 && needle[k] != c { k = fallback[k - 1] }
                if needle[k] == c { k += 1 }
                if k == needle.count { return i - k + 1 }
            }
            return nil
        }
    }

    /// The line as text, trimmed around the match when it is very long.
    private static func display(_ line: [UInt8], matchAt at: Int, matchLength: Int) -> String {
        var lo = 0
        var hi = line.count
        if line.count > maxLineLength {
            lo = max(0, at - maxLineLength / 2)
            hi = min(line.count, lo + maxLineLength)
            // Don't start or end in the middle of a UTF-8 character.
            while lo > 0 && line[lo] & 0xC0 == 0x80 { lo -= 1 }
            while hi < line.count && line[hi] & 0xC0 == 0x80 { hi += 1 }
        }
        let text = String(decoding: line[lo..<hi], as: UTF8.self)
            .trimmingCharacters(in: .whitespaces)
        return (lo > 0 ? "…" : "") + text + (hi < line.count ? "…" : "")
    }

    // MARK: File names

    /// Parse the `YYYYMMDD_HHMMSS` prefix of a log file name.
    static func startDate(of file: URL) -> Date? {
        let name = file.lastPathComponent
        guard name.count >= 15 else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        return formatter.date(from: String(name.prefix(15)))
    }
}
