//! Raw session logging: every byte the pty writes is appended, unmodified,
//! to a per-surface file. This mirrors iTerm2's "automatically log session
//! input/output" in raw mode, so the logs can be replayed with `cat` or
//! stripped of escape sequences with standard tools.
//!
//! The log file is opened lazily on the first output and only ever touched
//! from the thread that processes pty output, so no locking is needed.
//!
//! Without redaction, writes are unbuffered so the log is complete up to
//! the last byte even if the surface is abandoned without being torn down.
//! With redaction (the default), output is held back until a line is
//! complete so that a secret split across two reads is still recognized.
//! The held-back partial line is written when the program's output ends or
//! the surface closes.
const SessionLog = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const global = @import("../global.zig");
const Redact = @import("Redact.zig");

const log = std.log.scoped(.session_log);

/// Directory to create the log in, or null if logging is disabled.
dir: ?[]const u8 = null,

/// The open log file, once the first output has been written.
file: ?std.Io.File = null,

/// Set after an open or write error so we warn once and stop trying.
failed: bool = false,

/// Masks secrets before they reach the file, or null to log raw output.
redact: ?Redact = null,

/// Output not yet logged because its line isn't complete (redaction only).
pending: std.ArrayList(u8) = .empty,

/// Scratch buffer for redacted output, reused across writes.
scratch: std.ArrayList(u8) = .empty,

alloc: ?Allocator = null,

/// Output without a newline is held back so that a secret on a long line
/// is seen whole. Past `max_pending` it is logged up to its last carriage
/// return, which no secret spans. Past `hard_max_pending`, as full-screen
/// programs that only position the cursor produce, it is split at the
/// last point provably outside a secret (see `cutPoint`).
const max_pending = 16 * 1024;
const hard_max_pending = 256 * 1024;

pub fn init(
    alloc: Allocator,
    dir: ?[]const u8,
    redact: bool,
) Allocator.Error!SessionLog {
    const d = dir orelse return .{};
    if (d.len == 0) return .{};
    return .{
        .dir = try alloc.dupe(u8, d),
        .redact = if (redact) .{} else null,
        .alloc = alloc,
    };
}

pub fn deinit(self: *SessionLog, alloc: Allocator) void {
    self.flush();
    if (self.file) |f| f.close(global.io());
    if (self.dir) |d| alloc.free(d);
    if (self.redact) |*r| r.deinit(alloc);
    self.pending.deinit(alloc);
    self.scratch.deinit(alloc);
    self.* = .{};
}

/// Log any output held back waiting for the end of its line, such as the
/// final prompt. Call when no more output will arrive.
pub fn flush(self: *SessionLog) void {
    if (self.pending.items.len == 0) return;
    if (!self.failed) self.logRedacted(self.pending.items);
    self.pending.clearRetainingCapacity();
}

/// Append pty output to the log. Errors disable logging for this session.
pub fn write(self: *SessionLog, bytes: []const u8) void {
    if (self.dir == null or self.failed or bytes.len == 0) return;
    if (self.redact == null) return self.writeFile(bytes);

    const alloc = self.alloc.?;
    self.pending.appendSlice(alloc, bytes) catch return self.fail(error.OutOfMemory);

    const c = cutPoint(self.pending.items, max_pending, hard_max_pending);
    const cut = c.at;
    if (cut == 0) return;
    if (c.mid_run) {
        self.logRedactedCut(self.pending.items[0..cut]);
    } else {
        self.logRedacted(self.pending.items[0..cut]);
    }

    // Keep the remainder for the next write.
    const rest = self.pending.items.len - cut;
    std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[cut..]);
    self.pending.shrinkRetainingCapacity(rest);
}

const Cut = struct {
    /// Bytes to log now; 0 means wait for more output.
    at: usize,
    /// The cut goes through a run of credential characters, so the
    /// redactor must mask the run on both sides (see Redact.redactCut).
    mid_run: bool = false,
};

/// How much of `pending` can be redacted and logged now.
///
/// Everything up to the last newline, or once over `limit`, up to the
/// last carriage return. Over `hard_limit` with neither, the last point
/// no secret can straddle (see `lastSafeCut`). If there is none near the
/// end, the start of the word holding the last `holdback` bytes, along
/// with any `KEY=` or `Bearer` introducing it, so the held-back tail
/// carries every secret it touches. A word too long to hold back is cut
/// where it must be, with the run around the cut masked.
fn cutPoint(pending: []const u8, limit: usize, hard_limit: usize) Cut {
    if (std.mem.lastIndexOfScalar(u8, pending, '\n')) |nl| return .{ .at = nl + 1 };
    if (pending.len < limit) return .{ .at = 0 };
    if (std.mem.lastIndexOfScalar(u8, pending, '\r')) |cr| return .{ .at = cr + 1 };
    if (pending.len < hard_limit) return .{ .at = 0 };

    // A safe cut far from the end would leave nearly a full buffer to be
    // rescanned on every write.
    const max_tail = @max(hard_limit / 2, holdback);
    const safe = lastSafeCut(pending);
    if (pending.len <= holdback) return .{ .at = safe orelse pending.len };
    if (safe) |cut| {
        if (pending.len - cut <= max_tail) return .{ .at = cut };
    }

    // Back to the start of the word around the fallback point (escape
    // sequences count as part of a word, since the redactor matches
    // across them), then of the introducer before it, if any. A cut
    // inside a quoted value is fine: the redactor carries it over.
    var fallback = pending.len - holdback;
    const floor = pending.len - max_tail;
    var w = fallback;
    while (true) {
        while (w > floor and isWordByte(pending[w - 1])) w -= 1;
        if (w <= floor) break;
        const k = lastNonBlank(pending, w) orelse return .{ .at = w };
        if (introducerSafe(pending, k)) return .{ .at = w };
        w = k + 1;
    }

    // One word longer than the tail: cut it, but not inside an escape
    // sequence, and have the redactor mask around the cut.
    var e = fallback -| 64;
    while (std.mem.indexOfScalarPos(u8, pending[0..fallback], e, 0x1b)) |esc| {
        if (Redact.skipEscape(pending, esc) > fallback) {
            fallback = esc;
            break;
        }
        e = esc + 1;
    }
    // Always have the redactor mask around such a cut. It judges the
    // runs on either side on visible text, so a color sequence at the
    // cut can't make a split token look like two harmless pieces, and
    // where there is no run nothing is masked.
    return .{ .at = fallback, .mid_run = true };
}

const holdback = 4 * 1024;

/// Index of the last byte before `end` that isn't a blank, if any.
fn lastNonBlank(s: []const u8, end: usize) ?usize {
    var i = end;
    while (i > 0) {
        i -= 1;
        if (s[i] != ' ' and s[i] != '\t') return i;
    }
    return null;
}

/// Bytes that belong to a word: anything but blanks and control
/// characters, with ESC included so escape sequences stay with the word.
fn isWordByte(c: u8) bool {
    return c == 0x1b or (c > ' ' and c != 0x7f);
}

/// The last index at which `s` can be split without splitting a secret,
/// found in one forward pass: before an escape sequence that doesn't
/// follow a token character (the redactor matches across escapes, so
/// `ghp_ESC[0m…` is one token), or after whitespace, but never inside a
/// quoted assignment value or between a value and the `KEY=`, `KEY:` or
/// `Bearer` introducing it. Quotes follow the redactor's rules: a quote
/// opens a value only right after `=` or `:`, and a backslash escapes the
/// next character inside it.
fn lastSafeCut(s: []const u8) ?usize {
    var best: ?usize = null;
    var quote: u8 = 0;
    // Index of the last visible non-blank byte, for introducer checks.
    var last: ?usize = null;

    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (quote != 0) {
            if (c == '\\') {
                i += 2;
                continue;
            }
            if (c == quote) quote = 0;
            last = i;
            i += 1;
            continue;
        }

        switch (c) {
            0x1b => {
                if (i > 0 and !isTokenChar(s[i - 1]) and introducerSafe(s, last)) best = i;
                i = Redact.skipEscape(s, i);
                continue;
            },
            ' ', '\t' => if (introducerSafe(s, last)) {
                best = i + 1;
            },
            '"', '\'' => {
                if (last) |l| if (s[l] == '=' or s[l] == ':') {
                    quote = c;
                };
                last = i;
            },
            else => last = i,
        }
        i += 1;
    }
    return best;
}

fn isTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

/// Whether a value can't follow: the last visible byte isn't an
/// assignment separator and doesn't end the word "Bearer".
fn introducerSafe(s: []const u8, last: ?usize) bool {
    const l = last orelse return true;
    if (s[l] == '=' or s[l] == ':') return false;
    const word = "bearer";
    if (l + 1 >= word.len and std.ascii.eqlIgnoreCase(s[l + 1 - word.len .. l + 1], word)) return false;
    return true;
}

fn logRedactedCut(self: *SessionLog, bytes: []const u8) void {
    const alloc = self.alloc.?;
    self.scratch.clearRetainingCapacity();
    self.redact.?.redactCut(alloc, &self.scratch, bytes) catch
        return self.fail(error.OutOfMemory);
    self.writeFile(self.scratch.items);
}

fn logRedacted(self: *SessionLog, bytes: []const u8) void {
    const alloc = self.alloc.?;
    self.scratch.clearRetainingCapacity();
    self.redact.?.redact(alloc, &self.scratch, bytes) catch
        return self.fail(error.OutOfMemory);
    self.writeFile(self.scratch.items);
}

fn fail(self: *SessionLog, err: anyerror) void {
    log.warn("session log failed, disabling err={}", .{err});
    if (self.file) |f| f.close(global.io());
    self.file = null;
    self.failed = true;
}

fn writeFile(self: *SessionLog, bytes: []const u8) void {
    if (self.failed or bytes.len == 0) return;

    const file = self.file orelse file: {
        const f = self.open() catch |err| {
            log.warn("failed to open session log in dir={s} err={}", .{ self.dir.?, err });
            self.failed = true;
            return;
        };
        self.file = f;
        break :file f;
    };

    file.writeStreamingAll(global.io(), bytes) catch |err| {
        log.warn("failed to write session log, disabling err={}", .{err});
        file.close(global.io());
        self.file = null;
        self.failed = true;
    };
}

fn open(self: *SessionLog) !std.Io.File {
    const io = global.io();
    const dir_path = self.dir.?;

    try std.Io.Dir.cwd().createDirPath(io, dir_path);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var rand: [4]u8 = undefined;
    io.random(&rand);

    var name_buf: [64]u8 = undefined;
    const name = try filename(
        &name_buf,
        localTime(std.Io.Timestamp.now(io, .real).toSeconds()),
        processId(),
        std.mem.readInt(u32, &rand, .little),
    );

    const file = try dir.createFile(io, name, switch (builtin.target.os.tag) {
        .windows => .{ .exclusive = true },
        // Logs capture everything shown in the terminal, so keep them
        // private to the user.
        else => .{ .exclusive = true, .permissions = .fromMode(0o600) },
    });
    log.info("logging session to {s}/{s}", .{ dir_path, name });
    return file;
}

/// Broken-down calendar time used for the log filename.
pub const Time = struct {
    year: u32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

/// Build the log filename: `YYYYMMDD_HHMMSS.ghostty.<pid>.<random>.log`.
/// The leading timestamp keeps a directory listing in chronological
/// order, matching iTerm2's log naming.
pub fn filename(buf: []u8, t: Time, pid: u64, random: u32) ![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "{d:0>4}{d:0>2}{d:0>2}_{d:0>2}{d:0>2}{d:0>2}.ghostty.{d}.{x:0>8}.log",
        .{ t.year, t.month, t.day, t.hour, t.minute, t.second, pid, random },
    );
}

fn processId() u64 {
    return switch (builtin.target.os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        else => @intCast(std.c.getpid()),
    };
}

/// struct tm. The first nine fields are fixed by C; the trailing two are
/// the BSD/glibc/musl extensions, included so the size is right.
const Tm = extern struct {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: c_long,
    zone: ?[*:0]const u8,
};

extern "c" fn localtime_r(timep: *const c_long, result: *Tm) ?*Tm;

/// Local time for `secs` since the epoch, falling back to UTC where
/// libc's localtime_r isn't available or fails.
fn localTime(secs: i64) Time {
    if (comptime builtin.target.os.tag != .windows and builtin.link_libc) local: {
        const t: c_long = @intCast(secs);
        var tm: Tm = undefined;
        _ = localtime_r(&t, &tm) orelse break :local;
        return .{
            .year = @intCast(tm.year + 1900),
            .month = @intCast(tm.mon + 1),
            .day = @intCast(tm.mday),
            .hour = @intCast(tm.hour),
            .minute = @intCast(tm.min),
            .second = @intCast(tm.sec),
        };
    }

    return utcTime(secs);
}

fn utcTime(secs: i64) Time {
    const epoch = std.time.epoch;
    const es: epoch.EpochSeconds = .{ .secs = @intCast(@max(secs, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = @as(u8, md.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
    };
}

/// `n` filler bytes for tests (Zig 0.17 dropped the `**` operator).
fn xs(comptime n: usize) *const [n]u8 {
    return comptime &@as([n]u8, @splat('x'));
}

test "filename" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "20261004_062426.ghostty.59121.00c0ffee.log",
        try filename(&buf, .{
            .year = 2026,
            .month = 10,
            .day = 4,
            .hour = 6,
            .minute = 24,
            .second = 26,
        }, 59121, 0xc0ffee),
    );
}

test "utcTime" {
    // 2026-10-11T17:04:05Z
    const t = utcTime(1791738245);
    try std.testing.expectEqual(@as(u32, 2026), t.year);
    try std.testing.expectEqual(@as(u8, 10), t.month);
    try std.testing.expectEqual(@as(u8, 11), t.day);
    try std.testing.expectEqual(@as(u8, 17), t.hour);
    try std.testing.expectEqual(@as(u8, 4), t.minute);
    try std.testing.expectEqual(@as(u8, 5), t.second);
}

test "disabled log ignores writes" {
    var s = try SessionLog.init(std.testing.allocator, null, true);
    defer s.deinit(std.testing.allocator);
    s.write("hello");
    try std.testing.expect(s.file == null);
}

test "cutPoint" {
    // Complete lines are logged, the partial line waits.
    try std.testing.expectEqual(@as(usize, 5), cutPoint("ab\nc\nde", 4, 8).at);
    try std.testing.expectEqual(@as(usize, 0), cutPoint("$ ", 4, 8).at);
    // Over the soft limit: after a carriage return, else keep waiting.
    try std.testing.expectEqual(@as(usize, 4), cutPoint("abc\rdef ghi", 4, 64).at);
    try std.testing.expectEqual(@as(usize, 0), cutPoint("abc def ghi", 4, 64).at);
    // Over the hard limit: whitespace or before an escape.
    try std.testing.expectEqual(@as(usize, 8), cutPoint("abc def ghi", 4, 8).at);
    try std.testing.expectEqual(@as(usize, 4), cutPoint("abc \x1b[0mdefghi", 4, 8).at);
    try std.testing.expectEqual(@as(usize, 6), cutPoint("abcdef", 4, 4).at);
}

test "cutPoint never splits a secret" {
    // Not between a value and its introducer.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD= secret123", 4, 8).at);
    try std.testing.expectEqual(@as(usize, 6), cutPoint("x abc Bearer abcdef", 4, 8).at);
    // Not inside a quoted value, escaped quotes included.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD=\"correct horse battery staple", 4, 8).at);
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD=\"abc\\\" tail", 4, 8).at);
    // An apostrophe in prose doesn't open a quote.
    try std.testing.expectEqual(@as(usize, 11), cutPoint("don't stop now", 4, 8).at);
    // Not inside a token broken up by an escape sequence.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x ghp_\x1b[0mabcdef", 4, 8).at);
}

test "cutPoint holds back a tail when no point is safe" {
    const run = xs(3 * holdback);
    const buf = run ++ ":ghp_aBcDeF";
    const c = cutPoint(buf, 4, 8);
    try std.testing.expectEqual(buf.len - holdback, c.at);
    try std.testing.expect(c.mid_run);
    // A color sequence at the cut doesn't make it look safe.
    const colored = (xs(3 * holdback - 20)) ++ ":ghp_aBcDeFgHiJ" ++ "\x1b[0mkLmNoPqRsT" ++ (xs(holdback));
    try std.testing.expect(cutPoint(colored, 4, 8).mid_run);
}

test "cutPoint is linear in the buffer size" {
    // An open quote followed by many spaces: every candidate is inside
    // the quote. A rescan per candidate would take minutes here.
    const alloc = std.testing.allocator;
    const buf = try alloc.alloc(u8, 4 * hard_max_pending);
    defer alloc.free(buf);
    @memset(buf, ' ');
    @memcpy(buf[0..3], "x=\"");
    try std.testing.expectEqual(buf.len - holdback, cutPoint(buf, max_pending, hard_max_pending).at);
}

test "redacted log keeps a long line whole up to the hard limit" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    const filler = xs(max_pending + 10);
    var s = try SessionLog.init(alloc, dir, true);
    s.write(filler ++ " PASSWORD=\"correct horse ");
    s.write("battery staple\" :ghp_aBcDeFgHiJkLmNo");
    s.write("PqRsTuVwXyZ0123456789\n");
    s.deinit(alloc);

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    const contents = try tmp.dir.readFileAlloc(io, entry.name, alloc, .unlimited);
    defer alloc.free(contents);
    try std.testing.expectEqualStrings(
        filler ++ " PASSWORD=\"[REDACTED:secret]\" :[REDACTED:github-token]\n",
        contents,
    );
}

test "redacted log never splits a secret at the hard limit" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    const filler = xs(hard_max_pending);
    var s = try SessionLog.init(alloc, dir, true);
    // A token cut by the read boundary, with no safe point before it.
    s.write(filler ++ ":ghp_aBcDeFgHiJkLmNo");
    s.write("PqRsTuVwXyZ0123456789 PASSWORD=\"abc\\\" tail");
    // A quoted value with an escaped quote, longer than the buffer, so
    // it has to be cut inside.
    s.write(filler);
    s.write(" secret\"\n");
    s.deinit(alloc);

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    const contents = try tmp.dir.readFileAlloc(io, entry.name, alloc, .unlimited);
    defer alloc.free(contents);
    // No part of the token or the value survives.
    for ([_][]const u8{ "ghp_", "aBcDeF", "PqRsTu", "0123456789", "secret\"", "abc" }) |part|
        try std.testing.expect(std.mem.indexOf(u8, contents, part) == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, " PASSWORD=\"[REDACTED:secret]") != null);
    try std.testing.expect(std.mem.endsWith(u8, contents, "[REDACTED:secret]\"\n"));
    // Nothing of the value survives: only the filler before it.
    try std.testing.expect(std.mem.indexOf(u8, contents, "tail") == null);
}

test "redacted log masks a token cut inside one giant word" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    // A complete token straddling `pending.len - holdback`, in a single
    // write with no blank anywhere.
    // Assembled from pieces so secret scanners don't flag the fake token.
    const token = "gh" ++ "p_" ++ "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    const before = xs(hard_max_pending - holdback - 21);
    const after = xs(holdback - token.len - 2 + 21);
    const chunk = before ++ ":" ++ token ++ ":" ++ after;
    try std.testing.expectEqual(hard_max_pending, chunk.len);

    var s = try SessionLog.init(alloc, dir, true);
    s.write(chunk);
    s.write("\n");
    s.deinit(alloc);

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    const contents = try tmp.dir.readFileAlloc(io, entry.name, alloc, .unlimited);
    defer alloc.free(contents);
    try std.testing.expect(std.mem.indexOf(u8, contents, "ghp_") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "PqRsTu") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "0123456789") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "[REDACTED:truncated]") != null);
}

test "redacted log masks a token split at a color sequence by a forced cut" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    // The forced cut lands exactly at the ESC inside the token.
    const head = (xs(hard_max_pending - holdback - 20)) ++ ":ghp_aBcDeFgHiJkLmNo";
    const tail_part = "\x1b[0mPqRsTuVwXyZ0123456789:";
    const chunk = head ++ tail_part ++ (xs(holdback - tail_part.len));
    try std.testing.expectEqual(hard_max_pending, chunk.len);

    var s = try SessionLog.init(alloc, dir, true);
    s.write(chunk);
    s.write("\n");
    s.deinit(alloc);

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    const contents = try tmp.dir.readFileAlloc(io, entry.name, alloc, .unlimited);
    defer alloc.free(contents);
    for ([_][]const u8{ "ghp_", "aBcDeF", "PqRsTu", "0123456789" }) |part|
        try std.testing.expect(std.mem.indexOf(u8, contents, part) == null);
}

test "redacted log holds partial lines until complete" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    var s = try SessionLog.init(alloc, dir, true);
    // The token arrives split across two reads.
    s.write("export GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNo");
    s.write("PqRsTuVwXyZ0123456789\r\n$ ");
    s.deinit(alloc);

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    const contents = try tmp.dir.readFileAlloc(io, entry.name, alloc, .unlimited);
    defer alloc.free(contents);
    try std.testing.expectEqualStrings(
        "export GITHUB_TOKEN=[REDACTED:secret]\r\n$ ",
        contents,
    );
}
