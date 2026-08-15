import AppKit
import Foundation
import CryptoKit
import CommonCrypto

struct PasswordEntry: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var label: String
    var username: String
    var password: String
}

/// An encrypted, file-backed store of password entries.
///
/// File format v2: magic (8 bytes) || version (1 byte) || KDF ID (1 byte) ||
/// KDF iterations (4 bytes, big-endian) || salt (16 bytes) || AES-GCM
/// combined sealed box of the JSON-encoded entries. The key is derived from
/// a user-supplied master password. Version 1 files (no KDF ID/iterations,
/// fixed at 210k PBKDF2 iterations) can still be read; any save rewrites
/// them as v2, and the iteration count itself is only raised on a master
/// password change (raising it requires re-deriving the key).
@MainActor
class PasswordVault: ObservableObject {
    static let shared = PasswordVault()

    enum State {
        case uninitialized  // no vault file exists yet
        case locked
        case unlocked
    }

    enum VaultError: LocalizedError {
        case badPassword
        case corrupted
        case locked
        case weakPassword

        var errorDescription: String? {
            switch self {
            case .badPassword: return "Incorrect master password."
            case .corrupted: return "The vault file is corrupted or unreadable."
            case .locked: return "The vault is locked."
            case .weakPassword:
                return "The master password must be at least " +
                    "\(PasswordVault.minMasterPasswordLength) characters."
            }
        }
    }

    @Published private(set) var state: State
    @Published private(set) var entries: [PasswordEntry] = []

    /// True while an unlock, create, or password change is deriving keys;
    /// the UI should disable submission to prevent overlapping attempts.
    @Published private(set) var busy = false

    private var key: SymmetricKey?
    private var salt: Data?

    /// Incremented by `lock()`. Async operations capture this at entry and
    /// abandon their result if it changed across an await, so locking the
    /// vault mid-operation can never be undone by an in-flight unlock or
    /// password change completing afterwards.
    private var generation: UInt64 = 0

    /// The PBKDF2 iteration count of the currently unlocked vault. New
    /// vaults use `defaultPBKDF2Iterations`; v1 vaults keep their legacy
    /// count until the master password is changed.
    private var iterations: UInt32 = PasswordVault.defaultPBKDF2Iterations

    // nonisolated: read from VaultError.errorDescription, which is not
    // main-actor-isolated; an isolated read there becomes an error once
    // this target moves past Swift 5 mode.
    nonisolated static let minMasterPasswordLength = 8

    private static let magic = Data("GHSTYPWV".utf8)
    private static let version: UInt8 = 2
    private static let kdfPBKDF2HmacSHA256: UInt8 = 1
    private static let saltLength = 16
    private static let defaultPBKDF2Iterations: UInt32 = 600_000
    private static let v1PBKDF2Iterations: UInt32 = 210_000

    nonisolated private static var fileURL: URL {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        )[0].appendingPathComponent("com.mitchellh.ghostty", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("passwords.vault")
    }

    private init() {
        state = FileManager.default.fileExists(atPath: Self.fileURL.path)
            ? .locked : .uninitialized

        // Lock whenever the machine sleeps, the screen locks, or the login
        // session deactivates (fast user switching); an unlocked vault
        // should never outlive the user's physical presence.
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [
            NSWorkspace.willSleepNotification,
            NSWorkspace.sessionDidResignActiveNotification,
        ] {
            _ = workspace.addObserver(forName: name, object: nil, queue: .main) {
                [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        }
        _ = DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.lock() }
        }
    }

    // MARK: - Locking

    func create(masterPassword: String) async throws {
        guard !busy else { return }
        guard masterPassword.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }
        busy = true
        defer { busy = false }
        let generation = self.generation

        var saltBytes = [UInt8](repeating: 0, count: Self.saltLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw VaultError.corrupted }
        let salt = Data(saltBytes)
        let key = try await Self.deriveKey(
            password: masterPassword, salt: salt,
            iterations: Self.defaultPBKDF2Iterations)
        guard generation == self.generation else { throw CancellationError() }

        self.salt = salt
        self.iterations = Self.defaultPBKDF2Iterations
        self.key = key
        self.entries = []
        try save()
        state = .unlocked
    }

    func unlock(masterPassword: String) async throws {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let data = try Data(contentsOf: Self.fileURL)
        guard data.count > Self.magic.count + 1,
              data.prefix(Self.magic.count) == Self.magic
        else { throw VaultError.corrupted }

        var offset = Self.magic.count
        let version = data[offset]
        offset += 1

        let iterations: UInt32
        switch version {
        case 1:
            iterations = Self.v1PBKDF2Iterations
        case 2:
            guard data.count > offset + 5,
                  data[offset] == Self.kdfPBKDF2HmacSHA256
            else { throw VaultError.corrupted }
            offset += 1
            iterations = data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
            offset += 4
            // Reject absurd counts so a tampered header can't stall the app.
            guard (1_000...100_000_000).contains(iterations)
            else { throw VaultError.corrupted }
        default:
            throw VaultError.corrupted
        }

        guard data.count > offset + Self.saltLength else { throw VaultError.corrupted }
        let salt = data.subdata(in: offset..<(offset + Self.saltLength))
        offset += Self.saltLength

        let key = try await Self.deriveKey(
            password: masterPassword, salt: salt, iterations: iterations)
        guard generation == self.generation else { throw CancellationError() }
        let boxData = data.subdata(in: offset..<data.count)

        // A box that can't even be constructed is a truncated/malformed
        // file, not a wrong password; only authentication failure is.
        guard let box = try? AES.GCM.SealedBox(combined: boxData)
        else { throw VaultError.corrupted }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: key)
        } catch {
            throw VaultError.badPassword
        }

        guard let decoded = try? JSONDecoder().decode([PasswordEntry].self, from: plaintext)
        else { throw VaultError.corrupted }

        self.salt = salt
        self.key = key
        self.iterations = iterations
        self.entries = decoded
        state = .unlocked
    }

    /// Re-encrypt the vault under a new master password. Requires the
    /// vault to be unlocked; the current password is verified to prove
    /// the caller knows it, not just that the panel is open.
    func changeMasterPassword(current: String, new: String) async throws {
        guard !busy else { return }
        guard state == .unlocked, let salt, let key else { throw VaultError.locked }
        guard new.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let verifyKey = try await Self.deriveKey(
            password: current, salt: salt, iterations: iterations)
        guard generation == self.generation else { throw CancellationError() }
        guard verifyKey == key else { throw VaultError.badPassword }

        var saltBytes = [UInt8](repeating: 0, count: Self.saltLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw VaultError.corrupted }
        let newSalt = Data(saltBytes)
        let newKey = try await Self.deriveKey(
            password: new, salt: newSalt, iterations: Self.defaultPBKDF2Iterations)
        guard generation == self.generation else { throw CancellationError() }

        // Commit to memory only once the file write succeeds; otherwise a
        // failed save would leave memory and disk expecting different
        // passwords.
        let (oldSalt, oldKey, oldIterations) = (self.salt, self.key, self.iterations)
        self.salt = newSalt
        self.key = newKey
        self.iterations = Self.defaultPBKDF2Iterations
        do {
            try save()
        } catch {
            self.salt = oldSalt
            self.key = oldKey
            self.iterations = oldIterations
            throw error
        }
    }

    func lock() {
        // Bump first so any in-flight unlock/change abandons its result
        // even when we were already locked.
        generation &+= 1
        // Never move an uninitialized vault to .locked (e.g. sleep before
        // any vault file exists); there is nothing to lock.
        guard state != .uninitialized else { return }
        key = nil
        salt = nil
        entries = []
        state = .locked
    }

    // MARK: - CRUD

    func add(_ entry: PasswordEntry) throws {
        entries.append(entry)
        try save()
    }

    func update(_ entry: PasswordEntry) throws {
        guard let idx = entries.firstIndex(where: { $0.id == entry.id }) else { return }
        entries[idx] = entry
        try save()
    }

    func delete(_ entry: PasswordEntry) throws {
        entries.removeAll { $0.id == entry.id }
        try save()
    }

    // MARK: - Persistence

    private func save() throws {
        guard let key, let salt else { throw VaultError.locked }
        let plaintext = try JSONEncoder().encode(entries)
        let box = try AES.GCM.seal(plaintext, using: key)
        guard let combined = box.combined else { throw VaultError.corrupted }

        var data = Data()
        data.append(Self.magic)
        data.append(Self.version)
        data.append(Self.kdfPBKDF2HmacSHA256)
        withUnsafeBytes(of: iterations.bigEndian) { data.append(contentsOf: $0) }
        data.append(salt)
        data.append(combined)

        // Write to a temp file created owner-only up front — never a
        // window where the bytes exist with wider permissions — then swap
        // it into place atomically.
        let fileURL = Self.fileURL
        let tmpURL = fileURL.deletingLastPathComponent()
            .appendingPathComponent(".\(fileURL.lastPathComponent).tmp")
        guard FileManager.default.createFile(
            atPath: tmpURL.path, contents: nil,
            attributes: [.posixPermissions: 0o600])
        else { throw VaultError.corrupted }
        do {
            try data.write(to: tmpURL, options: [.completeFileProtection])
            if FileManager.default.fileExists(atPath: fileURL.path) {
                _ = try FileManager.default.replaceItemAt(fileURL, withItemAt: tmpURL)
            } else {
                try FileManager.default.moveItem(at: tmpURL, to: fileURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: tmpURL)
            throw error
        }
    }

    /// Runs on the global concurrent executor, keeping the expensive PBKDF2
    /// work off the main thread. @concurrent (not just nonisolated async)
    /// so this holds even if the target adopts NonisolatedNonsendingByDefault
    /// (ApproachableConcurrency) or Swift 6 mode, where a plain nonisolated
    /// async function would silently run on the caller's actor instead.
    @concurrent nonisolated private static func deriveKey(
        password: String,
        salt: Data,
        iterations: UInt32
    ) async throws -> SymmetricKey {
        let passwordData = Data(password.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        let status = passwordData.withUnsafeBytes { pwBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwBytes.bindMemory(to: Int8.self).baseAddress, passwordData.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derived, derived.count)
            }
        }
        // Never proceed with an all-zero key if derivation failed.
        guard status == kCCSuccess else { throw VaultError.corrupted }
        return SymmetricKey(data: Data(derived))
    }
}
