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
        guard !needle.isEmpty else { return [] }

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

        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var stripper = Stripper()
            var lineNumber = 1
            var matched = false

            for i in 0..<bytes.count {
                // Bounded by bytes, not lines, so cancelling is prompt even
                // inside one enormous line.
                if i & cancelCheckMask == 0, i > 0, Task.isCancelled { return }

                let c = bytes[i]
                if c == 0x0A {
                    if !matched {
                        record(needle, in: visible, file: file, line: lineNumber, into: &hits)
                        if hits.count >= limit { return }
                    }
                    visible.removeAll(keepingCapacity: true)
                    stripper = Stripper()
                    matched = false
                    lineNumber += 1
                    continue
                }

                // The rest of a line that already has a hit only matters
                // for finding the next newline.
                if matched { continue }

                stripper.feed(c, into: &visible)
                if visible.count >= capacity {
                    matched = record(needle, in: visible, file: file, line: lineNumber, into: &hits)
                    if hits.count >= limit { return }
                    if !matched { visible.removeFirst(visible.count - keep) }
                }
            }
            if !matched {
                record(needle, in: visible, file: file, line: lineNumber, into: &hits)
            }
        }
        return Array(hits.prefix(limit))
    }

    /// Append a hit if `visible` contains `needle`. Returns whether it did.
    @discardableResult
    private static func record(
        _ needle: [UInt8],
        in visible: [UInt8],
        file: URL,
        line: Int,
        into hits: inout [Hit]
    ) -> Bool {
        guard let at = indexOf(needle, in: visible) else { return false }
        hits.append(.init(
            file: file,
            line: line,
            text: display(visible, matchAt: at, matchLength: needle.count)))
        return true
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

        mutating func feed(_ c: UInt8, into out: inout [UInt8]) {
            switch state {
            case .text:
                switch c {
                case 0x1B: state = .escape
                case 0x08:
                    // Drop one whole UTF-8 character.
                    while let last = out.popLast(), last & 0xC0 == 0x80 {}
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
    private static func lowerASCII(_ c: UInt8) -> UInt8 {
        (0x41...0x5A).contains(c) ? c | 0x20 : c
    }

    /// First index of `needle` (already lowercased) in `haystack`, ignoring
    /// ASCII case.
    static func indexOf(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        let first = needle[0]
        var i = 0
        let last = haystack.count - needle.count
        while i <= last {
            if lowerASCII(haystack[i]) == first {
                var k = 1
                while k < needle.count && lowerASCII(haystack[i + k]) == needle[k] { k += 1 }
                if k == needle.count { return i }
            }
            i += 1
        }
        return nil
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
