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

    const cut = cutPoint(self.pending.items, max_pending, hard_max_pending);
    if (cut == 0) return;
    self.logRedacted(self.pending.items[0..cut]);

    // Keep the remainder for the next write.
    const rest = self.pending.items.len - cut;
    std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[cut..]);
    self.pending.shrinkRetainingCapacity(rest);
}

/// How much of `pending` can be redacted and logged now. 0 means wait for
/// more output.
///
/// Everything up to the last newline, or once over `limit`, up to the
/// last carriage return. Over `hard_limit` with neither, the last point
/// no secret can straddle (see `lastSafeCut`). If there is none near the
/// end, the final `holdback` bytes are kept for the next write: a
/// prefixed token can't start inside an unbroken run of token
/// characters, so a split earlier than that can't cut one, and the held
/// bytes are seen again with what follows.
fn cutPoint(pending: []const u8, limit: usize, hard_limit: usize) usize {
    if (std.mem.lastIndexOfScalar(u8, pending, '\n')) |nl| return nl + 1;
    if (pending.len < limit) return 0;
    if (std.mem.lastIndexOfScalar(u8, pending, '\r')) |cr| return cr + 1;
    if (pending.len < hard_limit) return 0;

    // A safe cut far from the end would leave nearly a full buffer to be
    // rescanned on every write; hold back a bounded tail instead.
    const safe = lastSafeCut(pending);
    if (pending.len <= holdback) return safe orelse pending.len;
    if (safe) |cut| {
        if (pending.len - cut <= @max(hard_limit / 2, holdback)) return cut;
    }

    // Prefer a blank in the stretch before the held-back tail, where no
    // token can be cut and no value parted from its introducer. A cut
    // inside a quoted value is safe either way: the redactor carries an
    // open quote into the next write.
    const fallback = pending.len - holdback;
    const lower = fallback -| holdback;
    var j = fallback;
    while (j > lower and j > 1) {
        if (pending[j - 1] != ' ' and pending[j - 1] != '\t') {
            j -= 1;
            continue;
        }
        // Every blank in this run follows the same visible byte.
        const k = lastNonBlank(pending, j - 1);
        if (introducerSafe(pending, k)) return j;
        j = k orelse break;
    }
    return fallback;
}

/// Index of the last byte before `end` that isn't a blank, if any.
fn lastNonBlank(s: []const u8, end: usize) ?usize {
    var i = end;
    while (i > 0) {
        i -= 1;
        if (s[i] != ' ' and s[i] != '\t') return i;
    }
    return null;
}

const holdback = 4 * 1024;

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

    const file = try dir.createFile(io, name, switch (builtin.os.tag) {
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
    return switch (builtin.os.tag) {
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
    if (comptime builtin.os.tag != .windows and builtin.link_libc) local: {
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
    try std.testing.expectEqual(@as(usize, 5), cutPoint("ab\nc\nde", 4, 8));
    try std.testing.expectEqual(@as(usize, 0), cutPoint("$ ", 4, 8));
    // Over the soft limit: after a carriage return, else keep waiting.
    try std.testing.expectEqual(@as(usize, 4), cutPoint("abc\rdef ghi", 4, 64));
    try std.testing.expectEqual(@as(usize, 0), cutPoint("abc def ghi", 4, 64));
    // Over the hard limit: whitespace or before an escape.
    try std.testing.expectEqual(@as(usize, 8), cutPoint("abc def ghi", 4, 8));
    try std.testing.expectEqual(@as(usize, 4), cutPoint("abc \x1b[0mdefghi", 4, 8));
    try std.testing.expectEqual(@as(usize, 6), cutPoint("abcdef", 4, 4));
}

test "cutPoint never splits a secret" {
    // Not between a value and its introducer.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD= secret123", 4, 8));
    try std.testing.expectEqual(@as(usize, 6), cutPoint("x abc Bearer abcdef", 4, 8));
    // Not inside a quoted value, escaped quotes included.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD=\"correct horse battery staple", 4, 8));
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x PASSWORD=\"abc\\\" tail", 4, 8));
    // An apostrophe in prose doesn't open a quote.
    try std.testing.expectEqual(@as(usize, 11), cutPoint("don't stop now", 4, 8));
    // Not inside a token broken up by an escape sequence.
    try std.testing.expectEqual(@as(usize, 2), cutPoint("x ghp_\x1b[0mabcdef", 4, 8));
}

test "cutPoint holds back a tail when no point is safe" {
    const run = "x" ** (3 * holdback);
    const buf = run ++ ":ghp_aBcDeF";
    try std.testing.expectEqual(buf.len - holdback, cutPoint(buf, 4, 8));
}

test "cutPoint is linear in the buffer size" {
    // An open quote followed by many spaces: every candidate is inside
    // the quote. A rescan per candidate would take minutes here.
    const alloc = std.testing.allocator;
    const buf = try alloc.alloc(u8, 4 * hard_max_pending);
    defer alloc.free(buf);
    @memset(buf, ' ');
    @memcpy(buf[0..3], "x=\"");
    try std.testing.expectEqual(buf.len - holdback, cutPoint(buf, max_pending, hard_max_pending));
}

test "redacted log keeps a long line whole up to the hard limit" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(dir);

    const filler = "x" ** (max_pending + 10);
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

    const filler = "x" ** hard_max_pending;
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
    try std.testing.expect(std.mem.indexOf(u8, contents, "ghp_") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "secret\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, ":[REDACTED:github-token] PASSWORD=\"[REDACTED:secret]") != null);
    try std.testing.expect(std.mem.endsWith(u8, contents, "[REDACTED:secret]\"\n"));
    // Nothing of the value survives: only the filler before it.
    try std.testing.expect(std.mem.indexOf(u8, contents, "tail") == null);
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
