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

    private var key: SymmetricKey?
    private var salt: Data?

    /// The PBKDF2 iteration count of the currently unlocked vault. New
    /// vaults use `defaultPBKDF2Iterations`; v1 vaults keep their legacy
    /// count until the master password is changed.
    private var iterations: UInt32 = PasswordVault.defaultPBKDF2Iterations

    static let minMasterPasswordLength = 8

    private static let magic = Data("GHSTYPWV".utf8)
    private static let version: UInt8 = 2
    private static let kdfPBKDF2HmacSHA256: UInt8 = 1
    private static let saltLength = 16
    private static let defaultPBKDF2Iterations: UInt32 = 600_000
    private static let v1PBKDF2Iterations: UInt32 = 210_000

    private static var fileURL: URL {
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

        // Lock whenever the machine sleeps or the screen locks; an unlocked
        // vault should never outlive the user's physical presence.
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(lockFromNotification),
            name: NSWorkspace.willSleepNotification, object: nil)
        DistributedNotificationCenter.default().addObserver(
            self, selector: #selector(lockFromNotification),
            name: NSNotification.Name("com.apple.screenIsLocked"), object: nil)
    }

    @objc private func lockFromNotification(_ notification: Notification) {
        lock()
    }

    // MARK: - Locking

    func create(masterPassword: String) throws {
        guard masterPassword.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }

        var saltBytes = [UInt8](repeating: 0, count: Self.saltLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw VaultError.corrupted }
        self.salt = Data(saltBytes)
        self.iterations = Self.defaultPBKDF2Iterations
        self.key = try Self.deriveKey(
            password: masterPassword, salt: self.salt!, iterations: self.iterations)
        self.entries = []
        try save()
        state = .unlocked
    }

    func unlock(masterPassword: String) throws {
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

        let key = try Self.deriveKey(
            password: masterPassword, salt: salt, iterations: iterations)
        let boxData = data.subdata(in: offset..<data.count)

        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: boxData)
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
    func changeMasterPassword(current: String, new: String) throws {
        guard state == .unlocked, let salt, let key else { throw VaultError.locked }
        guard try Self.deriveKey(
            password: current, salt: salt, iterations: iterations) == key
        else { throw VaultError.badPassword }
        guard new.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }

        var saltBytes = [UInt8](repeating: 0, count: Self.saltLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw VaultError.corrupted }
        let newSalt = Data(saltBytes)
        let newKey = try Self.deriveKey(
            password: new, salt: newSalt, iterations: Self.defaultPBKDF2Iterations)

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
        try data.write(to: Self.fileURL, options: [.atomic, .completeFileProtection])

        // Owner read/write only.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: Self.fileURL.path)
    }

    private static func deriveKey(
        password: String,
        salt: Data,
        iterations: UInt32
    ) throws -> SymmetricKey {
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
