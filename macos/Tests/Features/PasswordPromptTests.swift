//
//  PasswordPromptTests.swift
//  GhosttyTests
//
//  Tests for parsing terminal password prompts and suggesting vault entries.
//

import Testing
@testable import Ghostty

struct PasswordPromptParseTests {
    @Test func sudo() {
        let p = PasswordPrompt.parse(line: "[sudo] password for daniel:")
        #expect(p.kind == .sudo)
        #expect(p.user == "daniel")
    }

    @Test func sshClassic() {
        let p = PasswordPrompt.parse(line: "daniel@prod-db.example.com's password:")
        #expect(p.kind == .ssh)
        #expect(p.user == "daniel")
        #expect(p.host == "prod-db.example.com")
    }

    @Test func sshKeyboardInteractive() {
        let p = PasswordPrompt.parse(line: "(admin@10.0.0.5) Password:")
        #expect(p.kind == .ssh)
        #expect(p.user == "admin")
        #expect(p.host == "10.0.0.5")
    }

    @Test func sshKeyPassphrase() {
        let p = PasswordPrompt.parse(line: "Enter passphrase for key '/Users/daniel/.ssh/id_ed25519':")
        #expect(p.kind == .sshKey)
        #expect(p.keyFile == "id_ed25519")
    }

    @Test func gitHTTPS() {
        let p = PasswordPrompt.parse(line: "Password for 'https://daniel@github.com':")
        #expect(p.kind == .git)
        #expect(p.user == "daniel")
        #expect(p.host == "github.com")
    }

    @Test func gitHostWithPort() {
        let p = PasswordPrompt.parse(line: "Password for 'https://git.corp.local:8443':")
        #expect(p.kind == .git)
        #expect(p.user == nil)
        #expect(p.host == "git.corp.local")
    }

    /// The server picks the text after `(user@host)`; it must not be able
    /// to pass for a local sudo prompt.
    @Test func sshWrapperWinsOverServerText() {
        let p = PasswordPrompt.parse(line: "(daniel@remote.example) [sudo] password for daniel:")
        #expect(p.kind == .ssh)
        #expect(p.host == "remote.example")
    }

    @Test func generic() {
        #expect(PasswordPrompt.parse(line: "Password:").kind == .generic)
    }

    @Test func screenUsesLastPromptLine() {
        let screen = """
        $ ls
        a b c
        $ sudo -k ls
        [sudo] password for daniel:


        """
        #expect(PasswordPrompt.parse(screen: screen)?.kind == .sudo)
    }

    @Test func screenWithoutPrompt() {
        #expect(PasswordPrompt.parse(screen: "$ ls\na b c\n$ ") == nil)
    }
}

struct PasswordPromptMatchTests {
    private let entries = [
        PasswordEntry(label: "prod-db", username: "daniel", password: "p1"),
        PasswordEntry(label: "github.com", username: "daniel", password: "p2"),
        PasswordEntry(label: "Mac login (sudo)", username: "daniel", password: "p3"),
        PasswordEntry(label: "SSH key id_ed25519", username: "", password: "p4"),
        PasswordEntry(label: "staging web (staging.example.com)", username: "deploy", password: "p5"),
        PasswordEntry(label: "production account", username: "daniel", password: "p6"),
        PasswordEntry(label: "GitHub", username: "daniel", password: "p7"),
    ]

    private func match(_ line: String, process: String? = nil) -> String? {
        var p = PasswordPrompt.parse(line: line)
        p.foregroundProcess = process
        return p.bestMatch(in: entries, localHost: "mbp")?.password
    }

    @Test func sshMatchesExactHost() {
        #expect(match("daniel@prod-db's password:", process: "ssh") == "p1")
        #expect(match("deploy@staging.example.com's password:", process: "ssh") == "p5")
    }

    @Test func sudoMatchesLabelWhenSudoAsks() {
        #expect(match("[sudo] password for daniel:", process: "sudo") == "p3")
    }

    /// The same text shown by anything but sudo (an ssh server's
    /// keyboard-interactive prompt, a script) isn't trusted as local.
    @Test func sudoTextFromAnotherProcessSuggestsNothing() {
        #expect(match("[sudo] password for daniel:", process: "ssh") == nil)
        #expect(match("[sudo] password for daniel:") == nil)
        #expect(match("(daniel@remote.example) [sudo] password for daniel:", process: "ssh") == nil)
    }

    @Test func keyMatchesFileName() {
        #expect(match("Enter passphrase for key '/Users/daniel/.ssh/id_ed25519':") == "p4")
    }

    @Test func gitMatchesExactHost() {
        #expect(match("Password for 'https://daniel@github.com':", process: "git") == "p2")
    }

    /// The username matches several entries, but the host matches none:
    /// offering any of them would type a password into the wrong host.
    @Test func unknownHostSuggestsNothing() {
        #expect(match("daniel@unknown.example.org's password:") == nil)
    }

    /// Near misses are not host evidence.
    @Test func hostNearMissesSuggestNothing() {
        // `dan` is part of the username `daniel`, not a host the entry names.
        #expect(match("daniel@dan's password:") == nil)
        // A shared first label under an unrelated domain.
        #expect(match("Password for 'https://daniel@github.attacker.example':") == nil)
        // A short name doesn't vouch for a longer host that starts with it.
        #expect(match("daniel@prod-db.attacker.example's password:") == nil)
    }

    @Test func genericPromptSuggestsNothing() {
        #expect(match("Password:") == nil)
    }

    @Test func tieSuggestsNothing() {
        let twins = [
            PasswordEntry(label: "prod-db primary", username: "a", password: "x"),
            PasswordEntry(label: "prod-db replica", username: "b", password: "y"),
        ]
        let p = PasswordPrompt.parse(line: "root@prod-db's password:")
        #expect(p.bestMatch(in: twins, localHost: "mbp") == nil)
    }

    @Test func usernameBreaksTie() {
        let twins = [
            PasswordEntry(label: "prod-db", username: "root", password: "x"),
            PasswordEntry(label: "prod-db", username: "daniel", password: "y"),
        ]
        let p = PasswordPrompt.parse(line: "daniel@prod-db's password:")
        #expect(p.bestMatch(in: twins, localHost: "mbp")?.password == "y")
    }
}
