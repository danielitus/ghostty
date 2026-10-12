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

    /// Very long lines are searched this many raw bytes at a time, so
    /// memory stays bounded and cancellation is prompt.
    static let maxSegment = 64 * 1024

    /// Overlap between segments: longer than any query plus the escape
    /// sequences that might sit inside a match.
    static let overlap = 4 * 1024

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
        var stripped: [UInt8] = []
        stripped.reserveCapacity(1024)

        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var lineNumber = 0
            var start = 0
            while start <= bytes.count {
                lineNumber += 1
                var end = start
                while end < bytes.count && bytes[end] != 0x0A { end += 1 }

                if lineNumber % 4096 == 0 && Task.isCancelled { return }

                // Full-screen programs can write megabytes without a
                // newline. Search such a line in bounded segments, which
                // overlap so a match across a boundary is still found,
                // checking for cancellation between them. An escape
                // sequence cut by a boundary may show a few stray bytes.
                var segment = start
                while segment < end || segment == start {
                    let segmentEnd = min(end, segment + maxSegment)
                    strip(bytes, from: segment, to: segmentEnd, into: &stripped)
                    if let at = indexOf(needle, in: stripped) {
                        hits.append(.init(
                            file: file,
                            line: lineNumber,
                            text: display(stripped, matchAt: at, matchLength: needle.count)))
                        if hits.count >= limit { return }
                        break
                    }
                    if segmentEnd >= end { break }
                    if Task.isCancelled { return }
                    segment = segmentEnd - min(segmentEnd - segment, overlap)
                }

                if end >= bytes.count { break }
                start = end + 1
            }
        }
        return hits
    }

    // MARK: Escape stripping

    /// Write `bytes[from..<to]` into `out` without escape sequences or
    /// control characters (tabs are kept). Backspace removes the previous
    /// character, so command lines echoed by a line editor read normally.
    static func strip(
        _ bytes: UnsafeBufferPointer<UInt8>,
        from: Int,
        to end: Int,
        into out: inout [UInt8]
    ) {
        out.removeAll(keepingCapacity: true)
        var i = from
        while i < end {
            let c = bytes[i]
            switch c {
            case 0x1B:
                i = skipEscape(bytes, at: i, end: end)
                continue
            case 0x08:
                // Drop one whole UTF-8 character.
                while let last = out.popLast(), last & 0xC0 == 0x80 {}
            case 0x09:
                out.append(c)
            case 0x00..<0x20, 0x7F:
                break
            default:
                out.append(c)
            }
            i += 1
        }
    }

    /// Index just past the escape sequence starting at `i`.
    private static func skipEscape(_ b: UnsafeBufferPointer<UInt8>, at i: Int, end: Int) -> Int {
        var j = i + 1
        guard j < end else { return end }
        switch b[j] {
        case UInt8(ascii: "["):
            // CSI: parameters, then a final byte in 0x40...0x7E.
            j += 1
            while j < end && !(0x40...0x7E).contains(b[j]) { j += 1 }
            return min(j + 1, end)
        case UInt8(ascii: "]"), UInt8(ascii: "P"), UInt8(ascii: "_"),
             UInt8(ascii: "^"), UInt8(ascii: "X"):
            // OSC, DCS, APC, PM, SOS: until BEL or ST (ESC \).
            j += 1
            while j < end {
                if b[j] == 0x07 { return j + 1 }
                if b[j] == 0x1B && j + 1 < end && b[j + 1] == UInt8(ascii: "\\") { return j + 2 }
                j += 1
            }
            return end
        case UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"),
             UInt8(ascii: "+"), UInt8(ascii: "#"), UInt8(ascii: "%"):
            // Charset designation and similar: one more byte.
            return min(j + 2, end)
        default:
            return j + 1
        }
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
