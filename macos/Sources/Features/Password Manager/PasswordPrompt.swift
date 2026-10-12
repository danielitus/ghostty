import Foundation

/// A password prompt read from the terminal screen, parsed into the parts
/// that identify which credential it wants: who, where, and what for.
///
/// Used to suggest a vault entry when the password manager opens at a
/// prompt. Parsing is best effort: an unrecognized prompt yields a
/// `.generic` prompt with no user or host, which never produces a
/// suggestion on its own.
struct PasswordPrompt: Equatable {
    enum Kind: Equatable {
        /// `[sudo] password for daniel:`
        case sudo
        /// `daniel@host's password:` or `(daniel@host) Password:`
        case ssh
        /// `Enter passphrase for key '/Users/daniel/.ssh/id_ed25519':`
        case sshKey
        /// `Password for 'https://daniel@github.com':`
        case git
        /// Anything else that asks for a password.
        case generic
    }

    var kind: Kind
    var user: String?
    var host: String?
    /// File name of the SSH key, for `.sshKey`.
    var keyFile: String?
    /// The prompt line as shown, for display.
    var line: String
    /// Name of the terminal's foreground process when the prompt was read
    /// (`sudo`, `ssh`, …), if known. A sudo prompt is only trusted to be
    /// for this Mac when sudo itself is asking.
    var foregroundProcess: String?

    /// Short description for the panel, such as "ssh daniel@prod-db".
    var summary: String {
        switch kind {
        case .sudo:
            return "sudo" + (user.map { " as \($0)" } ?? "")
        case .ssh:
            return "ssh " + [user, host].compactMap { $0 }.joined(separator: "@")
        case .sshKey:
            return "SSH key " + (keyFile ?? "")
        case .git:
            return "git " + (host ?? "")
        case .generic:
            return line
        }
    }

    // MARK: Parsing

    /// Parse the prompt from the text at the bottom of the screen. Only
    /// the last few non-empty lines are considered, and the last one that
    /// mentions a password or passphrase is used.
    static func parse(screen: String) -> PasswordPrompt? {
        let lines = screen
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .suffix(3)
        guard let line = lines.last(where: isPromptLine) else { return nil }
        return parse(line: line)
    }

    static func parse(line: String) -> PasswordPrompt {
        // OpenSSH prefixes keyboard-interactive prompts, whose text comes
        // from the server, with `(user@host)`. Whatever follows is the
        // server's to choose, including `[sudo] password for …`, so the
        // prefix decides: it's a password for that host.
        if let m = line.firstMatch(of: sshParenPattern) {
            return .init(kind: .ssh, user: String(m.1), host: normalize(host: String(m.2)), line: line)
        }
        if let m = line.firstMatch(of: sudoPattern) {
            return .init(kind: .sudo, user: String(m.1), line: line)
        }
        if let m = line.firstMatch(of: sshKeyPattern) {
            let path = String(m.1)
            return .init(
                kind: .sshKey,
                keyFile: (path as NSString).lastPathComponent,
                line: line)
        }
        if let m = line.firstMatch(of: sshPattern) {
            return .init(kind: .ssh, user: String(m.1), host: normalize(host: String(m.2)), line: line)
        }
        if let m = line.firstMatch(of: gitPattern) {
            return .init(
                kind: .git,
                user: m.1.map(String.init),
                host: normalize(host: String(m.2)),
                line: line)
        }
        return .init(kind: .generic, line: line)
    }

    private static func isPromptLine(_ line: String) -> Bool {
        let l = line.lowercased()
        return l.contains("password") || l.contains("passphrase") || l.contains("pass phrase")
    }

    /// Lowercased host without a port.
    private static func normalize(host: String) -> String {
        let h = host.lowercased()
        if let colon = h.lastIndex(of: ":"), !h.hasPrefix("[") {
            return String(h[..<colon])
        }
        return h
    }

    // `[sudo] password for daniel:`
    private static var sudoPattern: Regex<(Substring, Substring)> { try! Regex<(Substring, Substring)>(
        #"\[sudo\] password for ([^\s:]+)"#).ignoresCase() }
    // `Enter passphrase for key '/path/to/key':`
    private static var sshKeyPattern: Regex<(Substring, Substring)> { try! Regex<(Substring, Substring)>(
        #"passphrase for (?:key )?'([^']+)'"#).ignoresCase() }
    // `daniel@host's password:`
    private static var sshPattern: Regex<(Substring, Substring, Substring)> { try! Regex<(Substring, Substring, Substring)>(
        #"([^\s@'()]+)@([^\s@']+)'s password"#).ignoresCase() }
    // `(daniel@host) Password:` (OpenSSH 8.4+ keyboard-interactive),
    // anchored: only the client puts this at the start of the line.
    private static var sshParenPattern: Regex<(Substring, Substring, Substring)> { try! Regex<(Substring, Substring, Substring)>(
        #"^\(([^\s@()]+)@([^\s@()]+)\)"#).ignoresCase() }
    // `Password for 'https://daniel@github.com':`
    private static var gitPattern: Regex<(Substring, Substring?, Substring)> { try! Regex<(Substring, Substring?, Substring)>(
        #"password for '(?:[a-z][a-z0-9+.-]*://)?(?:([^@'/]+)@)?([^/']+)"#).ignoresCase() }

    // MARK: Matching

    /// The entry this prompt most likely wants, or nil when no entry is a
    /// clear winner. A suggestion needs evidence for this prompt (see
    /// `score`) and exactly one entry with the best score, so an ambiguous
    /// prompt preselects nothing rather than the wrong password.
    func bestMatch(in entries: [PasswordEntry], localHost: String = Self.localHostName) -> PasswordEntry? {
        var best: (entry: PasswordEntry, score: Int)?
        var tie = false
        for entry in entries {
            let s = score(entry, localHost: localHost)
            guard s > 0 else { continue }
            if let b = best, s == b.score {
                tie = true
            } else if best == nil || s > best!.score {
                best = (entry, s)
                tie = false
            }
        }
        guard let best, !tie else { return nil }
        return best.entry
    }

    /// How well `entry` fits this prompt; 0 means it must not be suggested.
    ///
    /// Each prompt type needs its own evidence: the exact host for ssh and
    /// git, the key name for a key passphrase, a sudo or login label for a
    /// sudo prompt that sudo itself is showing. A matching username only
    /// adds to that. Typing a password into the wrong prompt hands it to
    /// whoever runs that host, so near misses never count: `dan` is not
    /// `daniel`, and an entry for `github.com` is not one for
    /// `github.attacker.example`.
    func score(_ entry: PasswordEntry, localHost: String) -> Int {
        let label = entry.label.lowercased()
        let username = entry.username.lowercased()
        var evidence = 0

        switch kind {
        case .ssh, .git:
            if let host, !host.isEmpty, Self.hosts(in: entry).contains(host) {
                evidence = 4
            }
        case .sudo:
            guard let process = foregroundProcess,
                  ["sudo", "su", "doas"].contains(process) else { break }
            if label.contains("sudo") {
                evidence = 3
            } else if !localHost.isEmpty, Self.words(in: label).contains(localHost.lowercased()) {
                evidence = 2
            } else if ["login", "local", "mac"].contains(where: Self.words(in: label).contains) {
                evidence = 1
            }
        case .sshKey:
            if let keyFile, Self.words(in: label).contains(keyFile.lowercased()) {
                evidence = 4
            } else if label.contains("ssh"), label.contains("key") || label.contains("passphrase") {
                evidence = 2
            }
        case .generic:
            break
        }
        guard evidence > 0 else { return 0 }

        var score = evidence
        if let user = user?.lowercased(), !user.isEmpty {
            if username == user {
                score += 2
            } else if let at = username.firstIndex(of: "@"), username[..<at] == user {
                // `daniel@example.com` as the username for user daniel.
                score += 1
            }
        }
        return score
    }

    /// The hosts an entry names: each word of its label, and the domain of
    /// an email-style username.
    static func hosts(in entry: PasswordEntry) -> Set<String> {
        var hosts = words(in: entry.label.lowercased())
        let username = entry.username.lowercased()
        if let at = username.lastIndex(of: "@") {
            hosts.insert(String(username[username.index(after: at)...]))
        }
        return hosts
    }

    /// Words of a label, keeping the characters of host names and file
    /// names together: `"Prod DB (db1.example.com)"` has the words `prod`,
    /// `db` and `db1.example.com`.
    static func words(in text: String) -> Set<String> {
        let parts = text.split { c in
            !(c.isLetter || c.isNumber || c == "." || c == "-" || c == "_")
        }
        return Set(parts.map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: ".")) })
    }

    /// This Mac's short host name, for matching sudo prompts. Read with
    /// gethostname: ProcessInfo.hostName can block on a DNS lookup.
    static var localHostName: String {
        var buf = [CChar](repeating: 0, count: 256)
        guard gethostname(&buf, buf.count) == 0 else { return "" }
        let name = String(cString: buf).lowercased()
        return String(name.split(separator: ".").first ?? "")
    }
}
