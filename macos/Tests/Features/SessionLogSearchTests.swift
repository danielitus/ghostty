//
//  SessionLogSearchTests.swift
//  GhosttyTests
//
//  Tests for searching raw session logs.
//

import Foundation
import Testing
@testable import Ghostty

struct SessionLogSearchTests {
    private func strip(_ s: String) -> String {
        let bytes = Array(s.utf8)
        var out: [UInt8] = []
        bytes.withUnsafeBufferPointer {
            SessionLogSearch.strip($0, from: 0, to: bytes.count, into: &out)
        }
        return String(decoding: out, as: UTF8.self)
    }

    @Test func stripsEscapeSequences() {
        // SGR colors, an OSC 133 prompt mark (BEL and ST terminated), a
        // charset designation, a CRLF line ending.
        #expect(strip("\u{1b}]133;A\u{07}\u{1b}[1;32mdaniel@mac\u{1b}[0m:~$ ls\r") == "daniel@mac:~$ ls")
        #expect(strip("\u{1b}]0;title\u{1b}\\hello\u{1b}(B") == "hello")
    }

    @Test func backspaceRemovesCharacters() {
        #expect(strip("lss\u{08} -la") == "ls -la")
        #expect(strip("café\u{08}e") == "cafe")
    }

    @Test func caseInsensitiveMatch() {
        let needle = Array("error".utf8)
        #expect(SessionLogSearch.indexOf(needle, in: Array("Build ERROR: x".utf8)) == 6)
        #expect(SessionLogSearch.indexOf(needle, in: Array("all good".utf8)) == nil)
    }

    @Test func startDateFromFileName() {
        let url = URL(fileURLWithPath: "/tmp/20261011_143812.ghostty.123.abcd.log")
        let date = SessionLogSearch.startDate(of: url)
        let parts = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: date!)
        #expect(parts.year == 2026 && parts.month == 10 && parts.day == 11)
        #expect(parts.hour == 14 && parts.minute == 38)
    }

    @Test func searchReportsRawLineNumbersNewestFirst() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostty-log-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let older = dir.appendingPathComponent("20261010_090000.ghostty.1.a.log")
        let newer = dir.appendingPathComponent("20261011_090000.ghostty.2.b.log")
        // The match is split by color codes in the raw bytes, and blank
        // and escape-only lines still count toward the line number.
        try "$ make\r\n\r\n\u{1b}[0m\r\nfatal: \u{1b}[31mDisk\u{1b}[0m full\r\n".write(to: older, atomically: true, encoding: .utf8)
        try "one\ntwo disk full\n".write(to: newer, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSinceNow: -3600)], ofItemAtPath: older.path)
        // Not a log: ignored.
        try "disk full".write(to: dir.appendingPathComponent("notes.txt"), atomically: true, encoding: .utf8)

        let results = await SessionLogSearch.search("DISK FULL", in: dir)
        #expect(results.map(\.file.lastPathComponent) == [newer.lastPathComponent, older.lastPathComponent])
        #expect(results[0].hits.map(\.line) == [2])
        #expect(results[1].hits.map(\.line) == [4])
        #expect(results[1].hits.first?.text == "fatal: Disk full")
    }

    /// A newline-free stream is searched in segments; a match straddling a
    /// segment boundary is still found, on the right line.
    @Test func longLineMatchAcrossSegments() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostty-log-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let filler = String(repeating: "x", count: SessionLogSearch.maxSegment - 3)
        let tail = String(repeating: "y", count: 200_000)
        let file = dir.appendingPathComponent("20261011_090000.ghostty.1.a.log")
        try ("first\n" + filler + "NEEDLE" + tail + "\nlast\n").write(to: file, atomically: true, encoding: .utf8)

        let results = await SessionLogSearch.search("needle", in: dir)
        #expect(results.first?.hits.map(\.line) == [2])
        #expect(results.first?.hits.first?.text.contains("NEEDLE") == true)
        // The excerpt stays bounded.
        #expect((results.first?.hits.first?.text.count ?? 0) <= SessionLogSearch.maxLineLength + 2)
    }

    @Test func shellQuote() {
        #expect(SessionLogSearchController.shellQuote("/a b/it's.log") == "'/a b/it'\\''s.log'")
    }
}
