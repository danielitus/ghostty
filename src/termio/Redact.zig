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

/// Upper bound on the lines of a PEM block. A 4096-bit RSA key is about
/// 50 lines; encrypted keys add a few header lines.
const max_pem_lines = 150;

/// Append `input` to `out` with secrets replaced by `[REDACTED:<kind>]`.
pub fn redact(
    self: *Redact,
    alloc: Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
) Allocator.Error!void {
    var emitted: usize = 0;
    var i: usize = 0;

    while (i < input.len) {
        if (self.pem_lines_left > 0) {
            // Mask key lines until the END marker. Lines are judged on
            // their visible text, so colored key output stays masked. A
            // line that can't be key material (such as the next prompt)
            // ends the block unmasked.
            const eol = lineEnd(input, i);
            const line = input[i..eol];
            switch (pemLineKind(line)) {
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

            try out.appendSlice(alloc, input[emitted..i]);
            for (line) |c| if (c == '\r' or c == '\n') try out.append(alloc, c);
            emitted = eol;
            i = eol;
            self.pem_lines_left -= 1;
            continue;
        }

        const m = matchAt(input, i) orelse {
            i += 1;
            continue;
        };

        try out.appendSlice(alloc, input[emitted..m.start]);
        try out.print(alloc, "[REDACTED:{s}]", .{m.kind});
        emitted = m.end;
        i = m.end;

        if (m.pem) {
            // Keep the rest of the BEGIN line, then mask what follows.
            const eol = lineEnd(input, i);
            try out.appendSlice(alloc, input[i..eol]);
            emitted = eol;
            i = eol;
            self.pem_lines_left = max_pem_lines;
        }
    }

    try out.appendSlice(alloc, input[emitted..]);
}

const Match = struct {
    start: usize,
    end: usize,
    kind: []const u8,
    pem: bool = false,
};

/// Index just past the newline ending the line that contains `i`, or the
/// end of `s`.
fn lineEnd(s: []const u8, i: usize) usize {
    const nl = std.mem.indexOfScalarPos(u8, s, i, '\n') orelse return s.len;
    return nl + 1;
}

/// Index just past the escape sequence starting at `s[i]` (an ESC).
fn skipEscape(s: []const u8, i: usize) usize {
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

/// A token can't start in the middle of a word. The end of an escape
/// sequence is a boundary even though its final byte is a letter, as in
/// a token printed in color (`ESC[32mghp_…`).
fn atBoundary(s: []const u8, i: usize) bool {
    return i == 0 or !isB64Url(s[i - 1]) or afterCsi(s, i);
}

/// True if `s[0..i]` ends with a complete CSI sequence (`ESC [ … final`).
fn afterCsi(s: []const u8, i: usize) bool {
    if (i < 3) return false;
    const final = s[i - 1];
    if (final < 0x40 or final > 0x7e) return false;
    var j = i - 1;
    while (j > 0 and s[j - 1] >= 0x20 and s[j - 1] <= 0x3f) j -= 1;
    return j >= 2 and s[j - 1] == '[' and s[j - 2] == 0x1b;
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
        var e = start;
        while (e < s.len and s[e] != quote and s[e] != '\n' and s[e] != '\r') {
            if (s[e] == '\\' and e + 1 < s.len and s[e + 1] != '\n') e += 1;
            e += 1;
        }
        e = @min(e, s.len);
        if (e == start or s[start] == '$') return null;
        return .{ .start = start, .end = e, .kind = "secret" };
    }

    // A shell variable reference isn't the secret itself.
    if (j < s.len and s[j] == '$') return null;
    const start = j;
    while (j < s.len and isValueChar(s[j])) j += 1;
    if (j - start < 4) return null;
    return .{ .start = start, .end = j, .kind = "secret" };
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

fn expectRedacted(input: []const u8, expected: []const u8) !void {
    const alloc = std.testing.allocator;
    var r: Redact = .{};
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
        "aws_access_key_id AKIAIOSFODNN7EXAMPLE\r\n",
        "aws_access_key_id [REDACTED:aws-access-key]\r\n",
    );
    // Too long or mid-word is not a key.
    try expectUnchanged("AKIAIOSFODNN7EXAMPLEXX\n");
    try expectUnchanged("XAKIAIOSFODNN7EXAMPLE\n");
}

test "github tokens" {
    try expectRedacted(
        "token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 ok\n",
        "token [REDACTED:github-token] ok\n",
    );
    try expectRedacted(
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz\n",
        "[REDACTED:github-token]\n",
    );
}

test "anthropic and openai keys" {
    try expectRedacted(
        "sk-ant-api03-AbCdEfGh12345678IjKlMnOp\n",
        "[REDACTED:anthropic-key]\n",
    );
    try expectRedacted(
        "key=sk-proj-AbCdEfGh12345678IjKlMnOpQr\n",
        "key=[REDACTED:api-key]\n",
    );
    // Prose with the same shape but no digits.
    try expectUnchanged("sk-this-is-a-very-long-identifier-name\n");
}

test "stripe and slack" {
    try expectRedacted("sk_live_abcdEFGH12345678ijkl\n", "[REDACTED:stripe-key]\n");
    try expectRedacted("xoxb-1234567890-abcdefABCDEF\n", "[REDACTED:slack-token]\n");
}

test "google api key" {
    try expectRedacted(
        "AIzaSyA1234567890abcdefghijklmnopqrstuv\n",
        "[REDACTED:google-api-key]\n",
    );
}

test "jwt" {
    try expectRedacted(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n",
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
        "\x1b[32mghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\x1b[0m\n",
        "\x1b[32m[REDACTED:github-token]\x1b[0m\n",
    );
    try expectRedacted(
        "\x1b[1;33mAKIAIOSFODNN7EXAMPLE\x1b[m\n",
        "\x1b[1;33m[REDACTED:aws-access-key]\x1b[m\n",
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
            "\n" ++
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
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    try r.redact(alloc, &out, "-----BEGIN PRIVATE KEY-----\n");
    for (0..max_pem_lines) |_| try r.redact(alloc, &out, "AAAA\n");
    out.clearRetainingCapacity();
    try r.redact(alloc, &out, "plain line\n");
    try std.testing.expectEqualStrings("plain line\n", out.items);
}
