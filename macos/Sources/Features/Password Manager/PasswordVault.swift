import AppKit
import Foundation
import CryptoKit
import CommonCrypto
import LocalAuthentication
import Security

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
        case biometricsUnavailable
        case biometricsCanceled
        case keychain(OSStatus)

        var errorDescription: String? {
            switch self {
            case .badPassword: return "Incorrect master password."
            case .corrupted: return "The vault file is corrupted or unreadable."
            case .locked: return "The vault is locked."
            case .weakPassword:
                return "The master password must be at least " +
                    "\(PasswordVault.minMasterPasswordLength) characters."
            case .biometricsUnavailable:
                return "Touch ID is no longer available for this vault. " +
                    "Unlock with your master password and enable it again."
            case .biometricsCanceled:
                return "Touch ID was canceled."
            case .keychain(let status):
                let msg = SecCopyErrorMessageString(status, nil) as String?
                return "Keychain error: \(msg ?? String(status))"
            }
        }
    }

    @Published private(set) var state: State
    @Published private(set) var entries: [PasswordEntry] = []

    /// True while an unlock, create, or password change is deriving keys;
    /// the UI should disable submission to prevent overlapping attempts.
    @Published private(set) var busy = false

    /// Whether the derived vault key is stored in the Keychain behind a
    /// biometric (Touch ID / Watch) access control, so the vault can be
    /// opened without typing the master password. Mirrors a UserDefaults
    /// flag; the Keychain item itself is the source of truth and the flag
    /// is cleared whenever the item turns out to be gone or invalidated.
    @Published private(set) var biometricsEnabled: Bool

    /// True when this Mac can evaluate a biometric policy right now.
    var biometricsAvailable: Bool {
        LAContext().canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

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

    /// Posted by the panel controller when the panel is shown while locked
    /// and Touch ID is enabled; the unlock view responds by prompting.
    nonisolated static let biometricUnlockRequested =
        Notification.Name("PasswordVaultBiometricUnlockRequested")

    private static let magic = Data("GHSTYPWV".utf8)
    private static let version: UInt8 = 2
    private static let kdfPBKDF2HmacSHA256: UInt8 = 1
    private static let saltLength = 16
    private static let defaultPBKDF2Iterations: UInt32 = 600_000
    private static let v1PBKDF2Iterations: UInt32 = 210_000

    private static let biometricsDefaultsKey = "PasswordManagerTouchID"
    private static let keychainService = "com.mitchellh.ghostty.password-manager"
    private static let keychainAccount = "vault-key"

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
        biometricsEnabled = UserDefaults.standard.bool(forKey: Self.biometricsDefaultsKey)

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

        let file = try Self.readVaultFile()
        let key = try await Self.deriveKey(
            password: masterPassword, salt: file.salt, iterations: file.iterations)
        guard generation == self.generation else { throw CancellationError() }

        let decoded = try Self.open(file.box, using: key)

        self.salt = file.salt
        self.key = key
        self.iterations = file.iterations
        self.entries = decoded
        state = .unlocked
    }

    /// Unlock using the vault key stored in the Keychain behind Touch ID.
    /// The system shows the biometric prompt; on cancel this throws
    /// `VaultError.biometricsCanceled`. If the Keychain item is missing or
    /// has been invalidated (biometric enrollment changed, app signature
    /// changed), Touch ID is disabled and `biometricsUnavailable` thrown so
    /// the UI falls back to the master password.
    func unlockWithBiometrics() async throws {
        guard !busy, state == .locked else { return }
        guard biometricsEnabled else { throw VaultError.biometricsUnavailable }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let file = try Self.readVaultFile()
        let key: SymmetricKey
        do {
            key = try await Self.readKeyFromKeychain()
        } catch VaultError.biometricsUnavailable {
            disableBiometrics()
            throw VaultError.biometricsUnavailable
        }
        guard generation == self.generation else { throw CancellationError() }

        let decoded: [PasswordEntry]
        do {
            decoded = try Self.open(file.box, using: key)
        } catch VaultError.badPassword {
            // The stored key no longer matches the file (e.g. the vault
            // was replaced on disk). Drop it rather than keep failing.
            disableBiometrics()
            throw VaultError.biometricsUnavailable
        }

        self.salt = file.salt
        self.key = key
        self.iterations = file.iterations
        self.entries = decoded
        state = .unlocked
    }

    /// Store the current vault key in the Keychain protected by the
    /// currently enrolled biometrics. Requires an unlocked vault, which
    /// proves the caller knew the master password.
    func enableBiometrics() throws {
        guard state == .unlocked, let key else { throw VaultError.locked }
        guard biometricsAvailable else { throw VaultError.biometricsUnavailable }
        try Self.storeKeyInKeychain(key)
        UserDefaults.standard.set(true, forKey: Self.biometricsDefaultsKey)
        biometricsEnabled = true
    }

    func disableBiometrics() {
        Self.deleteKeyFromKeychain()
        UserDefaults.standard.set(false, forKey: Self.biometricsDefaultsKey)
        biometricsEnabled = false
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

        // Keep Touch ID working across the change: the stored key is the
        // derived key, which just changed. Writing needs no biometric
        // prompt. If the write fails, fall back to disabled rather than
        // leaving a stale key that can never open the vault.
        if biometricsEnabled {
            do {
                try Self.storeKeyInKeychain(newKey)
            } catch {
                disableBiometrics()
            }
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

    // MARK: - File parsing

    private struct VaultFile {
        let iterations: UInt32
        let salt: Data
        let box: AES.GCM.SealedBox
    }

    nonisolated private static func readVaultFile() throws -> VaultFile {
        let data = try Data(contentsOf: fileURL)
        guard data.count > magic.count + 1,
              data.prefix(magic.count) == magic
        else { throw VaultError.corrupted }

        var offset = magic.count
        let version = data[offset]
        offset += 1

        let iterations: UInt32
        switch version {
        case 1:
            iterations = v1PBKDF2Iterations
        case 2:
            guard data.count > offset + 5,
                  data[offset] == kdfPBKDF2HmacSHA256
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

        guard data.count > offset + saltLength else { throw VaultError.corrupted }
        let salt = data.subdata(in: offset..<(offset + saltLength))
        offset += saltLength

        // A box that can't even be constructed is a truncated/malformed
        // file, not a wrong password; only authentication failure is.
        guard let box = try? AES.GCM.SealedBox(combined: data.subdata(in: offset..<data.count))
        else { throw VaultError.corrupted }
        return VaultFile(iterations: iterations, salt: salt, box: box)
    }

    nonisolated private static func open(
        _ box: AES.GCM.SealedBox, using key: SymmetricKey
    ) throws -> [PasswordEntry] {
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: key)
        } catch {
            throw VaultError.badPassword
        }
        guard let decoded = try? JSONDecoder().decode([PasswordEntry].self, from: plaintext)
        else { throw VaultError.corrupted }
        return decoded
    }

    // MARK: - Keychain (Touch ID)

    nonisolated private static var keychainBaseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
    }

    /// Writes the key as a generic-password item readable only after the
    /// user passes biometric authentication with the *current* enrollment;
    /// adding or removing a fingerprint invalidates the item. Adding the
    /// item itself never prompts.
    nonisolated private static func storeKeyInKeychain(_ key: SymmetricKey) throws {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &cfError)
        else { throw VaultError.keychain(errSecParam) }

        let keyData = key.withUnsafeBytes { Data($0) }
        deleteKeyFromKeychain()
        var query = keychainBaseQuery
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = keyData
        query[kSecAttrLabel as String] = "Ghostty Password Vault"
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
    }

    nonisolated private static func deleteKeyFromKeychain() {
        SecItemDelete(keychainBaseQuery as CFDictionary)
    }

    /// Reads the key back; the system presents the Touch ID sheet. Runs
    /// off the main actor since the call blocks until the user responds.
    @concurrent nonisolated private static func readKeyFromKeychain() async throws -> SymmetricKey {
        let context = LAContext()
        context.localizedReason = "unlock the password vault"
        // No "Enter Password" fallback: the item is biometric-only, and the
        // master password field is the fallback in our own UI.
        context.localizedFallbackTitle = ""

        var query = keychainBaseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 32
            else { throw VaultError.biometricsUnavailable }
            return SymmetricKey(data: data)
        case errSecUserCanceled, errSecAuthFailed:
            // errSecAuthFailed is also what a "too many attempts" lockout
            // surfaces as; treat both as "didn't authenticate this time"
            // rather than tearing down the Touch ID setup.
            throw VaultError.biometricsCanceled
        case errSecItemNotFound, errSecInteractionNotAllowed:
            throw VaultError.biometricsUnavailable
        default:
            throw VaultError.keychain(status)
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
