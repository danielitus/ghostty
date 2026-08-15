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
/// File format: magic (8 bytes) || version (1 byte) || salt (16 bytes) ||
/// AES-GCM combined sealed box of the JSON-encoded entries. The key is
/// derived from a user-supplied master password via PBKDF2-HMAC-SHA256.
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

        var errorDescription: String? {
            switch self {
            case .badPassword: return "Incorrect master password."
            case .corrupted: return "The vault file is corrupted or unreadable."
            }
        }
    }

    @Published private(set) var state: State
    @Published private(set) var entries: [PasswordEntry] = []

    private var key: SymmetricKey?
    private var salt: Data?

    private static let magic = Data("GHSTYPWV".utf8)
    private static let version: UInt8 = 1
    private static let saltLength = 16
    private static let pbkdf2Iterations: UInt32 = 210_000

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
    }

    // MARK: - Locking

    func create(masterPassword: String) throws {
        var saltBytes = [UInt8](repeating: 0, count: Self.saltLength)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw VaultError.corrupted }
        self.salt = Data(saltBytes)
        self.key = Self.deriveKey(password: masterPassword, salt: self.salt!)
        self.entries = []
        try save()
        state = .unlocked
    }

    func unlock(masterPassword: String) throws {
        let data = try Data(contentsOf: Self.fileURL)
        let headerLen = Self.magic.count + 1 + Self.saltLength
        guard data.count > headerLen,
              data.prefix(Self.magic.count) == Self.magic,
              data[Self.magic.count] == Self.version
        else { throw VaultError.corrupted }

        let salt = data.subdata(in: (Self.magic.count + 1)..<headerLen)
        let key = Self.deriveKey(password: masterPassword, salt: salt)
        let boxData = data.subdata(in: headerLen..<data.count)

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
        self.entries = decoded
        state = .unlocked
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
        guard let key, let salt else { return }
        let plaintext = try JSONEncoder().encode(entries)
        let box = try AES.GCM.seal(plaintext, using: key)
        guard let combined = box.combined else { throw VaultError.corrupted }

        var data = Data()
        data.append(Self.magic)
        data.append(Self.version)
        data.append(salt)
        data.append(combined)
        try data.write(to: Self.fileURL, options: [.atomic, .completeFileProtection])

        // Owner read/write only.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: Self.fileURL.path)
    }

    private static func deriveKey(password: String, salt: Data) -> SymmetricKey {
        let passwordData = Data(password.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        passwordData.withUnsafeBytes { pwBytes in
            salt.withUnsafeBytes { saltBytes in
                _ = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwBytes.bindMemory(to: Int8.self).baseAddress, passwordData.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    pbkdf2Iterations,
                    &derived, derived.count)
            }
        }
        return SymmetricKey(data: Data(derived))
    }
}
