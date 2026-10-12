//! Masks well-known secrets in session log output so that tokens, keys and
//! passwords printed to a terminal don't accumulate in plain-text logs.
//!
//! Only anchored patterns are matched: token formats with a distinctive
//! prefix (`AKIA…`, `ghp_…`, `sk-ant-…`, JWTs, …), `Bearer` credentials,
//! passwords embedded in URLs, the value of `password=`-style assignments,
//! and PEM private key blocks. Unanchored data such as long hex or base64
//! runs is deliberately left alone: git SHAs, container IDs and encoded
//! blobs are everywhere in a developer's terminal and masking them would
//! make the logs useless.
//!
//! Patterns are matched against the visible text, with escape sequences
//! removed, and the matching raw bytes are masked. A token printed with
//! color codes around or inside it (`ESC[31mghp_ESC[0m…`) is therefore
//! still recognized; the escape sequences inside a masked span are kept
//! after the replacement so the terminal state the log replays is intact.
//!
//! The redactor is fed complete lines (see SessionLog), so a secret is
//! never split across calls. The only state carried between calls is
//! whether a PEM private key block is open.
const Redact = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Lines remaining in an open PEM private key block, or 0 when not in one.
/// Bounded so that a BEGIN line printed without its key (for example by
/// grep) can't mask the rest of the session.
pem_lines_left: u32 = 0,

/// Visible text of the current input and, for each visible byte, its
/// index in the raw input. Reused across calls.
vis: std.ArrayList(u8) = .empty,
map: std.ArrayList(u32) = .empty,

/// The input with secrets in control-string payloads masked, when it has
/// any control strings. Reused across calls.
pre: std.ArrayList(u8) = .empty,

/// The quote character of a quoted secret value that was still open at
/// the end of the last input, or 0. SessionLog only splits a line when it
/// must, and a value longer than its buffer has to be split somewhere, so
/// the next input continues masking until the closing quote.
open_quote: u8 = 0,

/// Whether the last input ended inside that quoted value right after an
/// escaping backslash, so the next input's first byte is escaped.
open_escape: bool = false,

/// Whether the last input was cut in the middle of a run of credential
/// characters (see `redactCut`), so the run's start in this input is
/// masked.
mask_leading_run: bool = false,

/// Upper bound on the lines of a PEM block. A 4096-bit RSA key is about
/// 50 lines; encrypted keys add a few header lines.
const max_pem_lines = 150;

pub fn deinit(self: *Redact, alloc: Allocator) void {
    self.vis.deinit(alloc);
    self.map.deinit(alloc);
    self.pre.deinit(alloc);
}

/// Append `input` to `out` with secrets replaced by `[REDACTED:<kind>]`.
pub fn redact(
    self: *Redact,
    alloc: Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
) Allocator.Error!void {
    return self.redactImpl(alloc, out, input, false);
}

/// Like `redact`, for input that had to be cut in the middle of a run of
/// credential characters because no safe cut point existed. Such a cut
/// can split a token, URL password or value into halves that no pattern
/// recognizes, so the run is masked on both sides of the cut: at the end
/// of this input and at the start of the next.
pub fn redactCut(
    self: *Redact,
    alloc: Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
) Allocator.Error!void {
    return self.redactImpl(alloc, out, input, true);
}

fn redactImpl(
    self: *Redact,
    alloc: Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
    cut_mid_run: bool,
) Allocator.Error!void {
    // Control strings (OSC window titles, OSC 8 hyperlinks, DCS, APC)
    // aren't visible text but are kept in the log, and can carry secrets
    // such as a token in a hyperlink's URL. Mask those first.
    const raw = if (hasControlString(input)) raw: {
        self.pre.clearRetainingCapacity();
        try maskControlStrings(alloc, &self.pre, input);
        break :raw self.pre.items;
    } else input;

    // Strip escape sequences, remembering where each visible byte was.
    self.vis.clearRetainingCapacity();
    self.map.clearRetainingCapacity();
    {
        var r: usize = 0;
        while (r < raw.len) {
            if (raw[r] == 0x1b) {
                r = skipEscape(raw, r);
                continue;
            }
            try self.vis.append(alloc, raw[r]);
            try self.map.append(alloc, @intCast(r));
            r += 1;
        }
    }
    const vis = self.vis.items;
    const map = self.map.items;

    var e: Emitter = .{ .alloc = alloc, .out = out, .raw = raw, .map = map };
    var i: usize = 0;

    // Finish a quoted value continued from the last input.
    if (self.open_quote != 0) {
        const q = quotedEnd(vis, 0, self.open_quote, self.open_escape);
        if (q.end > 0) {
            try out.appendSlice(alloc, "[REDACTED:secret]");
            try e.dropTo(e.rawEnd(q.end));
        }
        // Still open only if it ran to the end of this input too.
        if (q.end < vis.len) {
            self.open_quote = 0;
            self.open_escape = false;
        } else {
            self.open_escape = q.escaped;
        }
        i = q.end;
        self.mask_leading_run = false;
    } else if (self.mask_leading_run) {
        // The rest of a run the last input was cut through.
        self.mask_leading_run = false;
        var end: usize = 0;
        while (end < vis.len and end < max_cut_mask and isCredChar(vis[end])) end += 1;
        if (end > 0) {
            try out.appendSlice(alloc, "[REDACTED:truncated]");
            try e.dropTo(e.rawEnd(end));
        }
        i = end;
    }

    // A forced cut through a run of credential characters: scan only up
    // to the run, which is masked below.
    const stop = if (cut_mid_run) trailingRun(vis) else vis.len;

    while (i < stop) {
        if (self.pem_lines_left > 0) {
            // Mask key lines until the END marker. A line that can't be
            // key material (such as the next prompt) ends the block
            // unmasked.
            const eol = lineEnd(vis, i);
            switch (pemLineKind(vis[i..eol])) {
                .end => {
                    self.pem_lines_left = 0;
                    i = eol;
                    continue;
                },
                .other => {
                    self.pem_lines_left = 0;
                    continue;
                },
                .key => {},
            }

            // Keep only the line's escape sequences and line breaks.
            try e.passTo(e.rawIndex(i));
            try e.dropTo(e.rawEnd(eol));
            i = eol;
            self.pem_lines_left -= 1;
            continue;
        }

        const m = matchAt(vis, i) orelse {
            i += 1;
            continue;
        };

        // Escape sequences just before the secret (its color) stay in
        // front of the replacement. A zero-width match marks a position
        // right after visible text, before any escapes that follow it.
        try e.passTo(if (m.start == m.end) e.rawEnd(m.start) else e.rawIndex(m.start));
        try out.print(alloc, "[REDACTED:{s}]", .{m.kind});
        try e.dropTo(e.rawEnd(m.end));
        i = m.end;
        if (m.open_quote != 0) {
            self.open_quote = m.open_quote;
            self.open_escape = m.open_escape;
        }

        if (m.pem) {
            // Keep the rest of the BEGIN line, then mask what follows.
            const eol = lineEnd(vis, i);
            try e.passTo(e.rawEnd(eol));
            i = eol;
            self.pem_lines_left = max_pem_lines;
        }
    }

    if (cut_mid_run and self.open_quote == 0 and stop < vis.len) {
        // A match may already reach into the run; mask the rest of it,
        // and the run's continuation in the next input.
        if (i < vis.len) {
            try e.passTo(e.rawIndex(i));
            try out.appendSlice(alloc, "[REDACTED:truncated]");
            try e.dropTo(raw.len);
        }
        self.mask_leading_run = true;
    }
    try e.passTo(raw.len);
}

/// Characters that tokens, passwords in URLs and unquoted values are made
/// of. A cut through a run of them may split a secret.
pub fn isCredChar(c: u8) bool {
    return isAlnum(c) or switch (c) {
        '_', '-', '.', '+', '/', '=', '~', '%', '@', ':' => true,
        else => false,
    };
}

/// How far a mask around a forced cut reaches on each side. SessionLog
/// holds back 4 KiB after such a cut, so this covers the held-back bytes
/// plus a secret continuing past them. A secret longer than that, split
/// by such a cut, can still leak its far end.
const max_cut_mask = 8 * 1024;

/// Start of the run of credential characters at the end of `s`, at most
/// `max_cut_mask` back.
fn trailingRun(s: []const u8) usize {
    var i = s.len;
    while (i > 0 and s.len - i < max_cut_mask and isCredChar(s[i - 1])) i -= 1;
    return i;
}

fn isControlStringIntroducer(c: u8) bool {
    return switch (c) {
        ']', 'P', '_', '^', 'X' => true,
        else => false,
    };
}

fn hasControlString(s: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, s, i, 0x1b)) |e| {
        if (e + 1 < s.len and isControlStringIntroducer(s[e + 1])) return true;
        i = e + 1;
    }
    return false;
}

/// Copy `s` to `out`, masking secrets inside each control string's
/// payload. The payload is matched like visible text, without the PEM
/// block state, and the sequence's introducer and terminator are kept.
fn maskControlStrings(
    alloc: Allocator,
    out: *std.ArrayList(u8),
    s: []const u8,
) Allocator.Error!void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, s, i, 0x1b)) |e| {
        if (e + 1 >= s.len or !isControlStringIntroducer(s[e + 1])) {
            try out.appendSlice(alloc, s[i .. e + 1]);
            i = e + 1;
            continue;
        }
        try out.appendSlice(alloc, s[i .. e + 2]);
        const payload_start = e + 2;
        var payload_end = payload_start;
        while (payload_end < s.len) : (payload_end += 1) {
            if (s[payload_end] == 0x07) break;
            if (s[payload_end] == 0x1b and payload_end + 1 < s.len and
                s[payload_end + 1] == '\\') break;
        }
        try maskPlain(alloc, out, s[payload_start..payload_end]);
        i = payload_end;
    }
    try out.appendSlice(alloc, s[i..]);
}

/// Append `text` to `out` with prefixed tokens, assignments, URL
/// passwords and bearer tokens masked.
fn maskPlain(alloc: Allocator, out: *std.ArrayList(u8), text: []const u8) Allocator.Error!void {
    var emitted: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const m = matchAt(text, i) orelse {
            i += 1;
            continue;
        };
        if (m.pem) {
            i += 1;
            continue;
        }
        try out.appendSlice(alloc, text[emitted..m.start]);
        try out.print(alloc, "[REDACTED:{s}]", .{m.kind});
        emitted = m.end;
        i = m.end;
    }
    try out.appendSlice(alloc, text[emitted..]);
}

/// Writes the raw input up to a point, either unchanged or masked.
const Emitter = struct {
    alloc: Allocator,
    out: *std.ArrayList(u8),
    raw: []const u8,
    map: []const u32,
    /// Raw bytes before this index have been handled.
    done: usize = 0,

    /// Raw index of the visible byte at `v`.
    fn rawIndex(self: *const Emitter, v: usize) usize {
        return if (v < self.map.len) self.map[v] else self.raw.len;
    }

    /// Raw index just past the visible byte before `v`: the end of the
    /// raw span for visible text ending at `v`. Escape sequences after
    /// that byte belong to what follows.
    fn rawEnd(self: *const Emitter, v: usize) usize {
        if (v >= self.map.len) return self.raw.len;
        return if (v == 0) 0 else self.map[v - 1] + 1;
    }

    /// Copy raw bytes unchanged up to `end`.
    fn passTo(self: *Emitter, end: usize) Allocator.Error!void {
        if (end <= self.done) return;
        try self.out.appendSlice(self.alloc, self.raw[self.done..end]);
        self.done = end;
    }

    /// Mask raw bytes up to `end`, keeping their escape sequences and
    /// line breaks.
    fn dropTo(self: *Emitter, end: usize) Allocator.Error!void {
        var r = self.done;
        while (r < end) {
            switch (self.raw[r]) {
                0x1b => {
                    const next = @min(skipEscape(self.raw, r), end);
                    try self.out.appendSlice(self.alloc, self.raw[r..next]);
                    r = next;
                    continue;
                },
                '\r', '\n' => try self.out.append(self.alloc, self.raw[r]),
                else => {},
            }
            r += 1;
        }
        self.done = @max(self.done, end);
    }
};

const Match = struct {
    start: usize,
    end: usize,
    kind: []const u8,
    pem: bool = false,
    /// For a quoted value that runs to the end of the input: its quote,
    /// and whether it ended right after an escaping backslash.
    open_quote: u8 = 0,
    open_escape: bool = false,
};

/// Index just past the newline ending the line that contains `i`, or the
/// end of `s`.
fn lineEnd(s: []const u8, i: usize) usize {
    const nl = std.mem.indexOfScalarPos(u8, s, i, '\n') orelse return s.len;
    return nl + 1;
}

/// Index just past the escape sequence starting at `s[i]` (an ESC).
pub fn skipEscape(s: []const u8, i: usize) usize {
    var j = i + 1;
    if (j >= s.len) return s.len;
    switch (s[j]) {
        '[' => {
            j += 1;
            while (j < s.len and !(s[j] >= 0x40 and s[j] <= 0x7e)) j += 1;
            return @min(j + 1, s.len);
        },
        ']', 'P', '_', '^', 'X' => {
            j += 1;
            while (j < s.len) : (j += 1) {
                if (s[j] == 0x07) return j + 1;
                if (s[j] == 0x1b and j + 1 < s.len and s[j + 1] == '\\') return j + 2;
            }
            return s.len;
        },
        else => return j + 1,
    }
}

const PemLine = enum { key, end, other };

/// Classify a line inside a PEM block by its visible text: base64 key
/// data or an RFC 1421 header (`Proc-Type: 4,ENCRYPTED`) is key material,
/// anything else (such as a shell prompt) is not.
fn pemLineKind(line: []const u8) PemLine {
    if (std.mem.indexOf(u8, line, "-----END ") != null) return .end;

    var b64 = true;
    var header = true; // letters and '-' then ':'
    var colon = false;
    var visible: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        const c = line[i];
        if (c == 0x1b) {
            i = skipEscape(line, i);
            continue;
        }
        i += 1;
        if (c == '\r' or c == '\n') continue;
        visible += 1;
        if (!(isAlnum(c) or c == '+' or c == '/' or c == '=')) b64 = false;
        if (!colon) {
            if (c == ':') {
                colon = visible > 1;
                if (!colon) header = false;
            } else if (!(std.ascii.isAlphabetic(c) or c == '-')) header = false;
        }
    }
    if (visible == 0 or b64 or (header and colon)) return .key;
    return .other;
}

fn matchAt(s: []const u8, i: usize) ?Match {
    return switch (s[i]) {
        'A' => awsKey(s, i) orelse googleKey(s, i),
        'g' => githubToken(s, i),
        's', 'r' => stripeKey(s, i) orelse openaiKey(s, i),
        'x' => slackToken(s, i),
        'e' => jwt(s, i),
        'B', 'b' => bearer(s, i),
        '-' => pemBegin(s, i),
        ':' => urlPassword(s, i) orelse assignment(s, i),
        '=' => assignment(s, i),
        else => null,
    };
}

// Character classes

fn isAlnum(c: u8) bool {
    return std.ascii.isAlphanumeric(c);
}

fn isUpperAlnum(c: u8) bool {
    return std.ascii.isUpper(c) or std.ascii.isDigit(c);
}

fn isB64Url(c: u8) bool {
    return isAlnum(c) or c == '_' or c == '-';
}

fn isAlnumUnderscore(c: u8) bool {
    return isAlnum(c) or c == '_';
}

fn isSlackChar(c: u8) bool {
    return isAlnum(c) or c == '-';
}

fn isBearerChar(c: u8) bool {
    return isAlnum(c) or switch (c) {
        '-', '.', '_', '~', '+', '/', '=' => true,
        else => false,
    };
}

/// A token can't start in the middle of a word.
fn atBoundary(s: []const u8, i: usize) bool {
    return i == 0 or !isB64Url(s[i - 1]);
}

/// Length of the run of `class` characters starting at `i`.
fn run(s: []const u8, i: usize, comptime class: fn (u8) bool) usize {
    var j = i;
    while (j < s.len and class(s[j])) j += 1;
    return j - i;
}

/// Real keys mix letters and digits; requiring both keeps prose such as
/// `sk-this-is-a-very-long-identifier` from matching.
fn hasLetterAndDigit(s: []const u8) bool {
    var letter = false;
    var digit = false;
    for (s) |c| {
        if (std.ascii.isAlphabetic(c)) letter = true;
        if (std.ascii.isDigit(c)) digit = true;
    }
    return letter and digit;
}

/// Match `prefix` at `i` followed by at least `min` characters of `class`.
fn prefixed(
    s: []const u8,
    i: usize,
    prefix: []const u8,
    min: usize,
    comptime class: fn (u8) bool,
    kind: []const u8,
) ?Match {
    if (!std.mem.startsWith(u8, s[i..], prefix)) return null;
    if (!atBoundary(s, i)) return null;
    const body = i + prefix.len;
    const n = run(s, body, class);
    if (n < min) return null;
    if (!hasLetterAndDigit(s[body .. body + n])) return null;
    return .{ .start = i, .end = body + n, .kind = kind };
}

// Token formats

fn awsKey(s: []const u8, i: usize) ?Match {
    inline for (.{ "AKIA", "ASIA", "ABIA", "ACCA" }) |p| {
        if (std.mem.startsWith(u8, s[i..], p) and atBoundary(s, i)) {
            const body = i + p.len;
            if (run(s, body, isUpperAlnum) == 16 and
                (body + 16 == s.len or !isAlnum(s[body + 16])))
                return .{ .start = i, .end = body + 16, .kind = "aws-access-key" };
        }
    }
    return null;
}

fn googleKey(s: []const u8, i: usize) ?Match {
    const m = prefixed(s, i, "AIza", 35, isB64Url, "google-api-key") orelse return null;
    return if (m.end - i == 39) m else null;
}

fn githubToken(s: []const u8, i: usize) ?Match {
    inline for (.{ "ghp_", "gho_", "ghu_", "ghs_", "ghr_" }) |p| {
        if (prefixed(s, i, p, 36, isAlnum, "github-token")) |m| return m;
    }
    return prefixed(s, i, "github_pat_", 22, isAlnumUnderscore, "github-token");
}

fn openaiKey(s: []const u8, i: usize) ?Match {
    if (prefixed(s, i, "sk-ant-", 20, isB64Url, "anthropic-key")) |m| return m;
    return prefixed(s, i, "sk-", 20, isB64Url, "api-key");
}

fn stripeKey(s: []const u8, i: usize) ?Match {
    inline for (.{ "sk_live_", "sk_test_", "rk_live_", "rk_test_" }) |p| {
        if (prefixed(s, i, p, 16, isAlnum, "stripe-key")) |m| return m;
    }
    return null;
}

fn slackToken(s: []const u8, i: usize) ?Match {
    inline for (.{ "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-" }) |p| {
        if (prefixed(s, i, p, 10, isSlackChar, "slack-token")) |m| return m;
    }
    return null;
}

fn jwt(s: []const u8, i: usize) ?Match {
    if (!std.mem.startsWith(u8, s[i..], "eyJ") or !atBoundary(s, i)) return null;
    var j = i;
    for (0..3) |part| {
        const n = run(s, j, isB64Url);
        if (n < 8) return null;
        j += n;
        if (part < 2) {
            if (j >= s.len or s[j] != '.') return null;
            j += 1;
        }
    }
    // The payload must be JSON too: header and payload both start "eyJ".
    const payload = std.mem.indexOfScalarPos(u8, s, i, '.').? + 1;
    if (!std.mem.startsWith(u8, s[payload..], "eyJ")) return null;
    return .{ .start = i, .end = j, .kind = "jwt" };
}

fn bearer(s: []const u8, i: usize) ?Match {
    const word = "bearer ";
    if (s.len - i < word.len or !atBoundary(s, i)) return null;
    if (!std.ascii.eqlIgnoreCase(s[i .. i + word.len], word)) return null;
    const tok = i + word.len;
    const n = run(s, tok, isBearerChar);
    if (n < 16) return null;
    return .{ .start = tok, .end = tok + n, .kind = "bearer-token" };
}

fn pemBegin(s: []const u8, i: usize) ?Match {
    const begin = "-----BEGIN ";
    if (!std.mem.startsWith(u8, s[i..], begin)) return null;
    const eol = lineEnd(s, i);
    const line = s[i..eol];
    const tail = "PRIVATE KEY-----";
    const t = std.mem.indexOf(u8, line, tail) orelse return null;
    // Only the key type ("RSA ", "OPENSSH ", "ENCRYPTED ", …) may sit
    // between BEGIN and PRIVATE KEY.
    if (t - begin.len > 24) return null;
    // Mask nothing on the BEGIN line itself; the key follows it.
    const end = i + t + tail.len;
    return .{ .start = end, .end = end, .kind = "private-key", .pem = true };
}

/// `scheme://user:password@host`: mask the password.
fn urlPassword(s: []const u8, i: usize) ?Match {
    if (!std.mem.startsWith(u8, s[i..], "://")) return null;
    var j = i + 3;
    const user = j;
    while (j < s.len and isUrlCredChar(s[j]) and s[j] != ':') j += 1;
    if (j == user or j >= s.len or s[j] != ':') return null;
    j += 1;
    const pass = j;
    while (j < s.len and isUrlCredChar(s[j])) j += 1;
    if (j == pass or j >= s.len or s[j] != '@') return null;
    return .{ .start = pass, .end = j, .kind = "password" };
}

fn isUrlCredChar(c: u8) bool {
    return c > ' ' and c < 0x7f and switch (c) {
        '/', '@', '"', '\'', '<', '>', '`' => false,
        else => true,
    };
}

/// Key names whose value is masked, matched case-insensitively against the
/// end of the name: `DB_PASSWORD=…`, `"api_key": "…"`, `GITHUB_TOKEN=…`.
/// A suffix match keeps counters like `total_tokens: 1200` unmasked.
const secret_keys = [_][]const u8{
    "password",
    "passwd",
    "passphrase",
    "secret",
    "secret_key",
    "secretkey",
    "token",
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
};

/// `name=value` or `name: value` where name ends in a secret key word.
/// `i` is at the `=` or `:`.
fn assignment(s: []const u8, i: usize) ?Match {
    // Find the key name, allowing closing quotes and spaces before the
    // separator as in JSON and YAML.
    var k = i;
    while (k > 0 and (isBlank(s[k - 1]) or s[k - 1] == '"' or s[k - 1] == '\'')) k -= 1;
    const name_end = k;
    while (k > 0 and isNameChar(s[k - 1])) k -= 1;
    const name = s[k..name_end];
    if (name.len == 0) return null;
    if (!endsWithSecretKey(name)) return null;

    // Skip `==` comparisons.
    if (s[i] == '=' and i + 1 < s.len and s[i + 1] == '=') return null;

    var j = i + 1;
    while (j < s.len and isBlank(s[j])) j += 1;

    // A quoted value is masked whole, spaces and punctuation included,
    // up to its closing quote or the end of the line.
    if (j < s.len and (s[j] == '"' or s[j] == '\'')) {
        const quote = s[j];
        const start = j + 1;
        const q = quotedEnd(s, start, quote, false);
        if (q.end == start and !q.escaped) return null;
        if (start < s.len and s[start] == '$') return null;
        return .{
            .start = start,
            .end = q.end,
            .kind = "secret",
            .open_quote = if (q.end == s.len) quote else 0,
            .open_escape = q.escaped,
        };
    }

    // A shell variable reference isn't the secret itself.
    if (j < s.len and s[j] == '$') return null;
    const start = j;
    while (j < s.len and isValueChar(s[j])) j += 1;
    if (j - start < 4) return null;
    return .{ .start = start, .end = j, .kind = "secret" };
}

const QuotedEnd = struct {
    end: usize,
    /// The value ran to the end of `s` right after an escaping backslash.
    escaped: bool = false,
};

/// End of a quoted value starting at `start`: its closing quote (a
/// backslash escapes the next character), the end of the line, or the
/// end of `s`. `escaped` means the first byte is escaped, continuing a
/// value whose previous input ended with a backslash.
fn quotedEnd(s: []const u8, start: usize, quote: u8, escaped: bool) QuotedEnd {
    var e = start;
    if (escaped) {
        if (e >= s.len) return .{ .end = s.len, .escaped = true };
        if (s[e] == '\n' or s[e] == '\r') return .{ .end = e };
        e += 1;
    }
    while (e < s.len and s[e] != quote and s[e] != '\n' and s[e] != '\r') {
        if (s[e] == '\\') {
            if (e + 1 == s.len) return .{ .end = s.len, .escaped = true };
            if (s[e + 1] != '\n') e += 1;
        }
        e += 1;
    }
    return .{ .end = @min(e, s.len) };
}

fn isBlank(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn isNameChar(c: u8) bool {
    return isAlnum(c) or c == '_' or c == '-' or c == '.';
}

fn isValueChar(c: u8) bool {
    return c > ' ' and c < 0x7f and switch (c) {
        '"', '\'', '&', ',', ';', '}', ')', '`' => false,
        else => true,
    };
}

fn endsWithSecretKey(name: []const u8) bool {
    for (secret_keys) |key| {
        if (name.len >= key.len and
            std.ascii.eqlIgnoreCase(name[name.len - key.len ..], key))
            return true;
    }
    return false;
}

// Tests

/// Fake credentials for the tests, assembled from pieces so that no
/// complete key-shaped string appears in the source for secret scanners
/// (such as GitHub's) to flag. None of these is a real credential.
const fake = struct {
    const aws = "AK" ++ "IA" ++ "IOSFODNN7EXAMPLE";
    const github = "gh" ++ "p_" ++ "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    const github_pat = "github" ++ "_pat_" ++ "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz";
    const anthropic = "sk-" ++ "ant-" ++ "api03-AbCdEfGh12345678IjKlMnOp";
    const openai = "sk-" ++ "proj-" ++ "AbCdEfGh12345678IjKlMnOpQr";
    const stripe = "sk_" ++ "live_" ++ "abcdEFGH12345678ijkl";
    const slack = "xo" ++ "xb-" ++ "1234567890-abcdefABCDEF";
    const google = "AI" ++ "za" ++ "SyA1234567890abcdefghijklmnopqrstuv";
    const jwt = "ey" ++ "JhbGciOiJIUzI1NiJ9." ++ "ey" ++ "JzdWIiOiIxMjM0NTY3ODkwIn0." ++
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
};

fn expectRedacted(input: []const u8, expected: []const u8) !void {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    try r.redact(alloc, &out, input);
    try std.testing.expectEqualStrings(expected, out.items);
}

fn expectUnchanged(input: []const u8) !void {
    try expectRedacted(input, input);
}

test "aws access key" {
    try expectRedacted(
        "aws_access_key_id " ++ fake.aws ++ "\r\n",
        "aws_access_key_id [REDACTED:aws-access-key]\r\n",
    );
    // Too long or mid-word is not a key.
    try expectUnchanged(fake.aws ++ "XX\n");
    try expectUnchanged("X" ++ fake.aws ++ "\n");
}

test "github tokens" {
    try expectRedacted(
        "token " ++ fake.github ++ " ok\n",
        "token [REDACTED:github-token] ok\n",
    );
    try expectRedacted(
        fake.github_pat ++ "\n",
        "[REDACTED:github-token]\n",
    );
}

test "anthropic and openai keys" {
    try expectRedacted(
        fake.anthropic ++ "\n",
        "[REDACTED:anthropic-key]\n",
    );
    try expectRedacted(
        "key=" ++ fake.openai ++ "\n",
        "key=[REDACTED:api-key]\n",
    );
    // Prose with the same shape but no digits.
    try expectUnchanged("sk-this-is-a-very-long-identifier-name\n");
}

test "stripe and slack" {
    try expectRedacted(fake.stripe ++ "\n", "[REDACTED:stripe-key]\n");
    try expectRedacted(fake.slack ++ "\n", "[REDACTED:slack-token]\n");
}

test "google api key" {
    try expectRedacted(
        fake.google ++ "\n",
        "[REDACTED:google-api-key]\n",
    );
}

test "jwt" {
    try expectRedacted(
        fake.jwt ++ "\n",
        "[REDACTED:jwt]\n",
    );
    // Header-only base64 isn't a JWT.
    try expectUnchanged("eyJhbGciOiJIUzI1NiJ9.notjsonpayload.signaturepart\n");
}

test "bearer token" {
    try expectRedacted(
        "Authorization: Bearer abcDEF123456ghiJKL789.xyz\r\n",
        "Authorization: Bearer [REDACTED:bearer-token]\r\n",
    );
    try expectUnchanged("the bearer of bad news\n");
}

test "url password" {
    try expectRedacted(
        "postgres://admin:hunter2pass@db.internal:5432/app\n",
        "postgres://admin:[REDACTED:password]@db.internal:5432/app\n",
    );
    try expectUnchanged("https://github.com/ghostty-org/ghostty\n");
    try expectUnchanged("ssh://git@github.com:22/repo\n");
}

test "assignments" {
    try expectRedacted("export DB_PASSWORD=s3cr3tvalue\n", "export DB_PASSWORD=[REDACTED:secret]\n");
    try expectRedacted("GITHUB_TOKEN=abcdef123\n", "GITHUB_TOKEN=[REDACTED:secret]\n");
    try expectRedacted(
        "{\"api_key\": \"abcd1234efgh\", \"name\": \"x\"}\n",
        "{\"api_key\": \"[REDACTED:secret]\", \"name\": \"x\"}\n",
    );
    try expectRedacted(
        "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n",
        "AWS_SECRET_ACCESS_KEY = [REDACTED:secret]\n",
    );
    try expectRedacted("curl 'x?token=abcd1234&page=2'\n", "curl 'x?token=[REDACTED:secret]&page=2'\n");
}

test "quoted and tab-separated assignments" {
    try expectRedacted(
        "PASSWORD=\"correct horse battery staple\"\n",
        "PASSWORD=\"[REDACTED:secret]\"\n",
    );
    try expectRedacted(
        "{\"password\": \"abc,def;ghi\"}\n",
        "{\"password\": \"[REDACTED:secret]\"}\n",
    );
    try expectRedacted("password:\tsecret123\n", "password:\t[REDACTED:secret]\n");
    try expectRedacted(
        "token='a \\' b' rest\n",
        "token='[REDACTED:secret]' rest\n",
    );
    // Unterminated: masked to the end of the line, not beyond.
    try expectRedacted("secret = \"abc def\r\nnext\n", "secret = \"[REDACTED:secret]\r\nnext\n");
    try expectUnchanged("password: \"\"\n");
    try expectUnchanged("password = \"$DB_PASS\"\n");
}

test "tokens in color" {
    try expectRedacted(
        "\x1b[32m" ++ fake.github ++ "\x1b[0m\n",
        "\x1b[32m[REDACTED:github-token]\x1b[0m\n",
    );
    try expectRedacted(
        "\x1b[1;33m" ++ fake.aws ++ "\x1b[m\n",
        "\x1b[1;33m[REDACTED:aws-access-key]\x1b[m\n",
    );
}

test "tokens with escape sequences inside" {
    // Only the prefix highlighted: the reset inside the token is kept
    // after the replacement.
    try expectRedacted(
        "\x1b[31mghp_\x1b[0maBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 ok\n",
        "\x1b[31m[REDACTED:github-token]\x1b[0m ok\n",
    );
    // Formatting in the middle of the body.
    try expectRedacted(
        "AKIAIOSF\x1b[1mODNN7EXAMPLE\x1b[22m\n",
        "[REDACTED:aws-access-key]\x1b[1m\x1b[22m\n",
    );
    // An OSC sequence inside a quoted value.
    try expectRedacted(
        "password=\"abc\x1b]0;t\x07def\"\n",
        "password=\"[REDACTED:secret]\x1b]0;t\x07\"\n",
    );
}

test "secrets in control strings" {
    // An OSC 8 hyperlink whose URL carries a token.
    try expectRedacted(
        "\x1b]8;;https://example.com/?token=secret123\x1b\\link\x1b]8;;\x1b\\\n",
        "\x1b]8;;https://example.com/?token=[REDACTED:secret]\x1b\\link\x1b]8;;\x1b\\\n",
    );
    // A window title.
    try expectRedacted(
        "\x1b]0;deploy " ++ fake.github ++ "\x07$ \n",
        "\x1b]0;deploy [REDACTED:github-token]\x07$ \n",
    );
    // Formatting-only sequences are untouched.
    try expectUnchanged("\x1b]133;A\x07\x1b[1mbold\x1b[0m\n");
}

test "quoted value continues into the next input" {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    try r.redact(alloc, &out, "PASSWORD=\"correct horse");
    try r.redact(alloc, &out, " battery\x1b[0m staple\" after\n");
    try r.redact(alloc, &out, "plain\n");
    try std.testing.expectEqualStrings(
        "PASSWORD=\"[REDACTED:secret][REDACTED:secret]\x1b[0m\" after\nplain\n",
        out.items,
    );
}

test "escaped quote split across inputs" {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    // Cut between the backslash and the quote it escapes.
    try r.redact(alloc, &out, "PASSWORD=\"abc\\");
    try r.redact(alloc, &out, "\"LEAKMARKER\" after\n");
    // Cut after a backslash that is itself escaped: the quote closes.
    try r.redact(alloc, &out, "token=\"ab\\\\");
    try r.redact(alloc, &out, "\" visible\n");
    try std.testing.expect(std.mem.indexOf(u8, out.items, "LEAKMARKER") == null);
    try std.testing.expectEqualStrings(
        "PASSWORD=\"[REDACTED:secret][REDACTED:secret]\" after\n" ++
            "token=\"[REDACTED:secret]\" visible\n",
        out.items,
    );
}

test "cut through a run masks both halves" {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    try r.redactCut(alloc, &out, "keep this, xx:ghp_aBcDeFgHiJkLmNoPqR");
    try r.redact(alloc, &out, "sTuVwXyZ0123456789:xx and the rest\n");
    try std.testing.expect(std.mem.indexOf(u8, out.items, "aBcDeF") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "0123456789") == null);
    try std.testing.expectEqualStrings(
        "keep this, [REDACTED:truncated][REDACTED:truncated] and the rest\n",
        out.items,
    );
}

test "colored pem block stays masked" {
    try expectRedacted(
        "\x1b[33m-----BEGIN RSA PRIVATE KEY-----\x1b[0m\n" ++
            "\x1b[33mMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\x1b[0m\n" ++
            "Proc-Type: 4,ENCRYPTED\n" ++
            "\x1b[33m-----END RSA PRIVATE KEY-----\x1b[0m\n" ++
            "$ \n",
        "\x1b[33m-----BEGIN RSA PRIVATE KEY-----[REDACTED:private-key]\x1b[0m\n" ++
            "\x1b[33m\x1b[0m\n" ++
            "\n" ++
            "\x1b[33m-----END RSA PRIVATE KEY-----\x1b[0m\n" ++
            "$ \n",
    );
}

test "assignments that are not secrets" {
    // Prompts, counters, comparisons, variable references, short values.
    try expectUnchanged("Password: \r\n");
    try expectUnchanged("[sudo] password for daniel: \r\n");
    try expectUnchanged("total_tokens: 1200\n");
    try expectUnchanged("if token == other\n");
    try expectUnchanged("PASSWORD=$DB_PASS\n");
    try expectUnchanged("token: abc\n");
    try expectUnchanged("PWD=/Users/daniel\n");
    try expectUnchanged("author: Jane Doe\n");
}

test "common output is left alone" {
    try expectUnchanged("commit 6b13ed6ff1a2b3c4d5e6f708192a3b4c5d6e7f80\n");
    try expectUnchanged("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n");
    try expectUnchanged("CONTAINER ID   IMAGE\n3f4e5d6c7b8a   nginx:latest\n");
    try expectUnchanged("\x1b[1;32mdaniel@mac\x1b[0m:\x1b[34m~/Projects\x1b[0m$ ls\r\n");
    try expectUnchanged("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgYmxvYg==\n");
}

test "pem private key block" {
    try expectRedacted(
        "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" ++
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\r\n" ++
            "QyNTUxOQAAACDx3HmeJ8pWKqT6aLQ7HqJXtq8Ckf1xNh2l0Zr0pSxWzwAAAJg2zJ7ENsye\r\n" ++
            "-----END OPENSSH PRIVATE KEY-----\r\n" ++
            "after\r\n",
        "-----BEGIN OPENSSH PRIVATE KEY-----[REDACTED:private-key]\r\n" ++
            "\r\n" ++
            "\r\n" ++
            "-----END OPENSSH PRIVATE KEY-----\r\n" ++
            "after\r\n",
    );
    // A public key or certificate is not masked.
    try expectUnchanged("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n");
}

test "pem block spans calls and ends at terminal UI" {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    try r.redact(alloc, &out, "-----BEGIN RSA PRIVATE KEY-----\n");
    try r.redact(alloc, &out, "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n");
    // `head -1 key.pem` prints no END line; the next prompt has escapes
    // and must survive.
    try r.redact(alloc, &out, "\x1b]133;A\x07$ \n");
    try r.redact(alloc, &out, "visible\n");
    try std.testing.expectEqualStrings(
        "-----BEGIN RSA PRIVATE KEY-----[REDACTED:private-key]\n" ++
            "\n" ++
            "\x1b]133;A\x07$ \n" ++
            "visible\n",
        out.items,
    );
}

test "pem block is bounded" {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
    defer r.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    try r.redact(alloc, &out, "-----BEGIN PRIVATE KEY-----\n");
    for (0..max_pem_lines) |_| try r.redact(alloc, &out, "AAAA\n");
    out.clearRetainingCapacity();
    try r.redact(alloc, &out, "plain line\n");
    try std.testing.expectEqualStrings("plain line\n", out.items);
}
