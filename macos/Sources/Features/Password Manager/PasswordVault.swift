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
                return "Touch ID setup failed: \(msg ?? String(status))"
            }
        }
    }

    @Published private(set) var state: State
    @Published private(set) var entries: [PasswordEntry] = []

    /// True while an unlock, create, or password change is deriving keys;
    /// the UI should disable submission to prevent overlapping attempts.
    @Published private(set) var busy = false

    /// Whether the derived vault key is wrapped by a Secure Enclave key
    /// that requires Touch ID to use, so the vault can be opened without
    /// typing the master password. Mirrors a UserDefaults flag; the
    /// wrapped-key file is the source of truth and the flag is cleared
    /// whenever it turns out to be gone or invalidated.
    @Published private(set) var biometricsEnabled: Bool

    /// True when this Mac can evaluate a biometric policy right now and
    /// has a Secure Enclave to hold the wrapping key.
    var biometricsAvailable: Bool {
        SecureEnclave.isAvailable && LAContext().canEvaluatePolicy(
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

    /// Unlock using the Secure Enclave-wrapped vault key behind Touch ID.
    /// The system shows the biometric prompt; on cancel this throws
    /// `VaultError.biometricsCanceled`. If the wrapped key is missing or
    /// has been invalidated (biometric enrollment changed), Touch ID is
    /// disabled and `biometricsUnavailable` thrown so the UI falls back to
    /// the master password.
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

    /// Wrap the current vault key with a Secure Enclave key protected by
    /// the currently enrolled biometrics. Requires an unlocked vault, which
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

        // Keep Touch ID working across the change: the wrapped key is the
        // derived key, which just changed. Re-wrapping needs no biometric
        // prompt. If it fails, fall back to disabled rather than leaving a
        // stale key that can never open the vault.
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

    // MARK: - Touch ID key wrapping

    /// Touch ID is implemented with the Secure Enclave rather than the
    /// Keychain: biometric-gated Keychain items need the data protection
    /// keychain, which refuses ad-hoc signed builds (-34018). The Secure
    /// Enclave itself has no such requirement.
    ///
    /// Enabling creates an SE P-256 key whose *use* requires the current
    /// biometric enrollment, then wraps the vault key: an ephemeral P-256
    /// key does ECDH with the SE public key, HKDF derives a wrapping key,
    /// and AES-GCM seals the vault key. The SE key blob, ephemeral public
    /// key, salt, and sealed box go into `passwords.touchid` (0600) beside
    /// the vault. Unlocking reverses this; the ECDH on the SE side is what
    /// triggers the Touch ID sheet. Enrollment changes invalidate the SE
    /// key, which surfaces as a failure and disables the feature.
    private static let touchIDMagic = Data("GHSTYTID".utf8)
    private static let touchIDVersion: UInt8 = 1
    private static let touchIDInfo = Data("ghostty-password-vault-touchid".utf8)

    nonisolated private static var touchIDFileURL: URL {
        fileURL.deletingLastPathComponent().appendingPathComponent("passwords.touchid")
    }

    nonisolated private static func storeKeyInKeychain(_ key: SymmetricKey) throws {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &cfError)
        else { throw VaultError.keychain(errSecParam) }

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        } catch {
            throw VaultError.keychain(OSStatus((error as NSError).code))
        }

        var saltBytes = [UInt8](repeating: 0, count: saltLength)
        guard SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes) == errSecSuccess
        else { throw VaultError.corrupted }
        let salt = Data(saltBytes)

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: touchIDInfo, outputByteCount: 32)
        let vaultKeyData = key.withUnsafeBytes { Data($0) }
        guard let sealed = try AES.GCM.seal(vaultKeyData, using: wrapKey).combined
        else { throw VaultError.corrupted }

        let seBlob = seKey.dataRepresentation
        let ephPub = ephemeral.publicKey.rawRepresentation
        var data = Data()
        data.append(touchIDMagic)
        data.append(touchIDVersion)
        withUnsafeBytes(of: UInt16(seBlob.count).bigEndian) { data.append(contentsOf: $0) }
        data.append(seBlob)
        withUnsafeBytes(of: UInt16(ephPub.count).bigEndian) { data.append(contentsOf: $0) }
        data.append(ephPub)
        data.append(salt)
        data.append(sealed)

        let url = touchIDFileURL
        deleteKeyFromKeychain()
        guard FileManager.default.createFile(
            atPath: url.path, contents: nil,
            attributes: [.posixPermissions: 0o600])
        else { throw VaultError.corrupted }
        try data.write(to: url, options: [.completeFileProtection])
    }

    nonisolated private static func deleteKeyFromKeychain() {
        try? FileManager.default.removeItem(at: touchIDFileURL)
    }

    /// Unwraps the vault key; the Secure Enclave operation presents the
    /// Touch ID sheet. Runs off the main actor since it blocks until the
    /// user responds.
    @concurrent nonisolated private static func readKeyFromKeychain() async throws -> SymmetricKey {
        guard let data = try? Data(contentsOf: touchIDFileURL)
        else { throw VaultError.biometricsUnavailable }

        // Parse; any malformation means the file is useless, not transient.
        var offset = 0
        func take(_ n: Int) throws -> Data {
            guard n >= 0, data.count >= offset + n else { throw VaultError.biometricsUnavailable }
            defer { offset += n }
            return data.subdata(in: offset..<(offset + n))
        }
        func takeU16() throws -> Int {
            let b = try take(2)
            return Int(b[b.startIndex]) << 8 | Int(b[b.startIndex + 1])
        }
        guard try take(touchIDMagic.count) == touchIDMagic,
              try take(1).first == touchIDVersion
        else { throw VaultError.biometricsUnavailable }
        let seBlob = try take(try takeU16())
        let ephPub = try take(try takeU16())
        let salt = try take(saltLength)
        let sealedData = data.subdata(in: offset..<data.count)

        let context = LAContext()
        context.localizedReason = "unlock the password vault"
        // No "Enter Password" fallback: the master password field in our
        // own UI is the fallback.
        context.localizedFallbackTitle = ""

        do {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seBlob, authenticationContext: context)
            let pub = try P256.KeyAgreement.PublicKey(rawRepresentation: ephPub)
            let shared = try seKey.sharedSecretFromKeyAgreement(with: pub)
            let wrapKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: salt, sharedInfo: touchIDInfo, outputByteCount: 32)
            let box = try AES.GCM.SealedBox(combined: sealedData)
            let vaultKeyData = try AES.GCM.open(box, using: wrapKey)
            guard vaultKeyData.count == 32 else { throw VaultError.biometricsUnavailable }
            return SymmetricKey(data: vaultKeyData)
        } catch let error as NSError where error.domain == LAErrorDomain {
            switch LAError.Code(rawValue: error.code) {
            case .biometryNotEnrolled, .biometryNotAvailable:
                throw VaultError.biometricsUnavailable
            default:
                // Cancel, failed match, lockout, fallback: the user simply
                // didn't authenticate this time. Keep the setup.
                throw VaultError.biometricsCanceled
            }
        } catch let error as VaultError {
            throw error
        } catch {
            // Anything else (SE key invalidated by an enrollment change,
            // corrupt blob, ...) means this wrapped key can't be used.
            throw VaultError.biometricsUnavailable
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
