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
/// File format v3: magic (8 bytes) || version (1 byte) || KDF ID (1 byte) ||
/// KDF iterations (4 bytes, big-endian) || salt (16 bytes) || AES-GCM
/// combined sealed box of the JSON-encoded entries, with everything before
/// the box (the header) bound as GCM associated data so a tampered salt or
/// iteration count is rejected instead of adopted. The key is derived from
/// a user-supplied master password. Version 2 files have the same layout
/// without the header authenticated; version 1 files have no KDF ID or
/// iteration count (fixed at 210k). Both can still be read; any save
/// rewrites them as v3. The iteration count itself is only raised on a
/// master password change since raising it requires re-deriving the key.
///
/// The vault file is shared by every Ghostty instance on the machine
/// (an installed app and a development build, say). Writes are serialized
/// with a lock file and refuse to replace a file that changed since this
/// instance last read or wrote it, so one instance can never silently
/// discard another's entries or revert its master password change.
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
        case staleVault
        /// Another operation (unlock, create, password change) is still
        /// running; the caller must not treat the call as done.
        case busy
        /// Another Ghostty instance holds the vault file lock and did not
        /// release it within the (short) bounded wait.
        case fileBusy
        /// The vault (or Touch ID wrapper) predates the authenticated
        /// header format; a master-password unlock upgrades it.
        case legacyNeedsPassword
        /// Touch ID setup is confirmed dead (no fingerprints enrolled, or
        /// the wrapped key file is missing or corrupt). Setup is torn down.
        case biometricsUnavailable
        /// The user or system dismissed the prompt; nothing is changed.
        case biometricsCanceled
        /// The wrapped key opens fine but does not decrypt this vault
        /// (the vault was replaced, or its header was tampered with).
        case biometricsMismatch
        /// Anything else, including transient failures. Setup is kept.
        case biometricsFailed(String)
        case biometricsSetupFailed(String)

        var errorDescription: String? {
            switch self {
            case .badPassword: return "Incorrect master password."
            case .corrupted: return "The vault file is corrupted or unreadable."
            case .locked: return "The vault is locked."
            case .weakPassword:
                return "The master password must be at least " +
                    "\(PasswordVault.minMasterPasswordLength) characters."
            case .staleVault:
                return "The vault file was changed by another Ghostty instance. " +
                    "Reload it before making changes."
            case .busy:
                return "Another vault operation is still in progress."
            case .fileBusy:
                return "Another Ghostty instance is using the vault file. Try again in a moment."
            case .legacyNeedsPassword:
                return "This vault uses an older file format. Unlock with your master " +
                    "password once to upgrade it; Touch ID will work after that."
            case .biometricsUnavailable:
                return "Touch ID is no longer available for this vault. " +
                    "Unlock with your master password and enable it again."
            case .biometricsCanceled:
                return "Touch ID was canceled."
            case .biometricsMismatch:
                return "The saved Touch ID key does not match this vault. " +
                    "Unlock with your master password and turn Touch ID on again."
            case .biometricsFailed(let reason):
                return "Touch ID failed: \(reason) Unlock with your master password. " +
                    "If this keeps happening, turn Touch ID off and on again in the options menu."
            case .biometricsSetupFailed(let reason):
                return "Touch ID could not be enabled: \(reason)"
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
    /// wrapped-key file is the source of truth.
    @Published private(set) var biometricsEnabled: Bool

    /// Incremented by every `lock()` call, including when the vault was
    /// already locked or has no file yet. Views key their credential-
    /// holding state on it so every lock discards typed master passwords,
    /// entry drafts, and open sheets, even when `state` did not change.
    @Published private(set) var lockEpoch: UInt64 = 0

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
    /// vaults use `defaultPBKDF2Iterations`; older vaults keep their
    /// count until the master password is changed.
    private var iterations: UInt32 = PasswordVault.defaultPBKDF2Iterations

    /// SHA-256 of the vault file as this instance last read or wrote it.
    /// A save refuses to replace a file with a different digest: another
    /// instance wrote it in the meantime.
    private var diskDigest: Data?

    /// The context behind an in-flight Touch ID prompt, so `lock()` can
    /// dismiss the prompt instead of leaving it up over a locked vault.
    private var activeAuthContext: LAContext?

    // nonisolated: read from VaultError.errorDescription, which is not
    // main-actor-isolated; an isolated read there becomes an error once
    // this target moves past Swift 5 mode.
    nonisolated static let minMasterPasswordLength = 8

    /// Posted by the panel controller when the panel is shown while locked
    /// and Touch ID is enabled; the unlock view responds by prompting.
    nonisolated static let biometricUnlockRequested =
        Notification.Name("PasswordVaultBiometricUnlockRequested")

    private static let magic = Data("GHSTYPWV".utf8)
    private static let version: UInt8 = 3
    private static let kdfPBKDF2HmacSHA256: UInt8 = 1
    private static let saltLength = 16
    private static let defaultPBKDF2Iterations: UInt32 = 600_000
    private static let v1PBKDF2Iterations: UInt32 = 210_000

    private static let biometricsDefaultsKey = "PasswordManagerTouchID"

    nonisolated private static var directoryURL: URL {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        )[0].appendingPathComponent("com.mitchellh.ghostty", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    nonisolated private static var fileURL: URL {
        directoryURL.appendingPathComponent("passwords.vault")
    }

    nonisolated private static var lockFileURL: URL {
        directoryURL.appendingPathComponent("passwords.vault.lock")
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
        guard !busy else { throw VaultError.busy }
        guard state == .uninitialized else { throw VaultError.locked }
        guard masterPassword.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let salt = try Self.randomSalt()
        let key = try await Self.deriveKey(
            password: masterPassword, salt: salt,
            iterations: Self.defaultPBKDF2Iterations)
        guard generation == self.generation else { throw CancellationError() }
        try Task.checkCancellation()

        // Write before publishing anything. Creating requires that no
        // file exists; if another instance created one meanwhile, the
        // user needs to unlock that one instead.
        let digest: Data
        do {
            digest = try Self.writeVault(
                entries: [], key: key, salt: salt,
                iterations: Self.defaultPBKDF2Iterations, expectedDigest: nil).digest
        } catch VaultError.staleVault {
            state = .locked
            throw VaultError.staleVault
        }

        self.salt = salt
        self.iterations = Self.defaultPBKDF2Iterations
        self.key = key
        self.entries = []
        self.diskDigest = digest
        state = .unlocked
    }

    func unlock(masterPassword: String) async throws {
        guard !busy else { throw VaultError.busy }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let (file, wrappedKeyData) = try Self.readVaultFiles()
        let key = try await Self.deriveKey(
            password: masterPassword, salt: file.salt, iterations: file.iterations)
        guard generation == self.generation else { throw CancellationError() }
        try Task.checkCancellation()

        let decoded = try Self.open(file, using: key)
        adopt(file: file, key: key, entries: decoded)

        // The derived key opened the box, which proves the salt and
        // iteration count in a pre-v3 header are the real ones. Seal them
        // into a v3 header now, and refresh the Touch ID wrapper so it
        // carries the vault binding, before Touch ID is allowed to bypass
        // the KDF on this vault again. Failure here is not an unlock
        // failure; the next save upgrades the file anyway.
        if file.version < Self.version {
            upgradeLegacyVault()
        } else if biometricsEnabled && !Self.isCurrentWrappedKey(wrappedKeyData) {
            // Touch ID is on but its wrapper is missing or in the old
            // format (a build downgrade, a partial upgrade); a password
            // unlock is the one place a fresh one can be made safely.
            repairWrappedKey()
        }
    }

    private func upgradeLegacyVault() {
        guard state == .unlocked, let key, let salt else { return }
        var wrapped: Data?
        if biometricsEnabled {
            wrapped = try? Self.makeWrappedKeyData(key, vaultSalt: salt)
            if wrapped == nil { disableBiometrics(deleteWrappedKeyMatching: nil) }
        }
        guard let result = try? Self.writeVault(
            entries: entries, key: key, salt: salt, iterations: iterations,
            expectedDigest: diskDigest, wrappedKey: wrapped)
        else { return }
        diskDigest = result.digest
        if wrapped != nil && !result.wrappedKeyInstalled {
            disableBiometrics(deleteWrappedKeyMatching: nil)
        }
    }

    private func repairWrappedKey() {
        guard state == .unlocked, let key, let salt else { return }
        do {
            try Self.storeWrappedKey(key, vaultSalt: salt, expectedDigest: diskDigest)
        } catch {
            disableBiometrics(deleteWrappedKeyMatching: nil)
        }
    }

    /// True if `data` is a wrapped key in the current format. Only the
    /// magic and version are inspected.
    nonisolated private static func isCurrentWrappedKey(_ data: Data?) -> Bool {
        guard let data, data.count > wrappedKeyMagic.count,
              data.prefix(wrappedKeyMagic.count) == wrappedKeyMagic
        else { return false }
        return data[data.startIndex + wrappedKeyMagic.count] == wrappedKeyVersion
    }

    /// Unlock using the Secure Enclave-wrapped vault key behind Touch ID.
    /// The system shows the biometric prompt. Cancelling throws
    /// `biometricsCanceled` and changes nothing. Only a confirmed dead
    /// setup (`biometricsUnavailable`) tears Touch ID down; a wrapped key
    /// that does not fit this vault (`biometricsMismatch`) just stops the
    /// automatic prompts and keeps the file; every other failure is
    /// reported and leaves the setup alone.
    func unlockWithBiometrics() async throws {
        guard state == .locked else { return }
        guard !busy else { throw VaultError.busy }
        guard biometricsEnabled else { throw VaultError.biometricsUnavailable }
        busy = true
        defer { busy = false }
        let generation = self.generation

        // One shared-lock snapshot of both files, so the wrapper we
        // authenticate against belongs to the vault we then open.
        let (file, wrappedKeyData) = try Self.readVaultFiles()

        // A pre-v3 vault has an unauthenticated header. Opening it with a
        // key that bypasses the KDF would let a tampered iteration count
        // or salt be adopted and then sealed into the v3 upgrade, so the
        // upgrade is only ever done after a master-password unlock.
        guard file.version >= Self.version else { throw VaultError.legacyNeedsPassword }

        let context = LAContext()
        context.localizedReason = "unlock the password vault"
        // No "Enter Password" fallback: the master password field in our
        // own UI is the fallback.
        context.localizedFallbackTitle = ""
        activeAuthContext = context
        defer { if activeAuthContext === context { activeAuthContext = nil } }

        let key: SymmetricKey
        do {
            key = try await Self.unwrapKey(
                wrappedKeyData, context: AuthContextBox(context), vaultSalt: file.salt)
        } catch let error as VaultError {
            // Destructive cleanup only for a confirmed dead setup, only if
            // nothing locked (or re-unlocked) the vault meanwhile, and
            // only of the exact wrapper we inspected: another instance
            // may have installed a fresh one since.
            if generation == self.generation {
                switch error {
                case .biometricsUnavailable:
                    disableBiometrics(deleteWrappedKeyMatching: wrappedKeyData)
                case .biometricsMismatch:
                    disableBiometrics(deleteWrappedKeyMatching: nil)
                default:
                    break
                }
            }
            throw error
        }
        guard generation == self.generation else { throw CancellationError() }

        let decoded: [PasswordEntry]
        do {
            decoded = try Self.open(file, using: key)
        } catch VaultError.badPassword {
            // The unwrapped key does not decrypt this vault: the vault was
            // replaced on disk or its header was tampered with. Keep the
            // wrapped key on disk; it is harmless and re-enabling
            // overwrites it.
            if generation == self.generation { disableBiometrics(deleteWrappedKeyMatching: nil) }
            throw VaultError.biometricsMismatch
        }

        adopt(file: file, key: key, entries: decoded)
    }

    private func adopt(file: VaultFile, key: SymmetricKey, entries: [PasswordEntry]) {
        self.salt = file.salt
        self.key = key
        self.iterations = file.iterations
        self.entries = entries
        self.diskDigest = file.digest
        state = .unlocked
        // A vault restored from a backup may have come back world-readable.
        Self.repairPermissions()
    }

    /// Re-read the vault after another instance changed it. Requires the
    /// current key to still open it; if the master password was changed
    /// elsewhere the vault locks so the user can unlock with the new one.
    func reloadFromDisk() throws {
        guard state == .unlocked, let key else { throw VaultError.locked }
        let file = try Self.readVaultFile()
        do {
            let decoded = try Self.open(file, using: key)
            adopt(file: file, key: key, entries: decoded)
        } catch VaultError.badPassword {
            lock()
            throw VaultError.badPassword
        }
    }

    /// Wrap the current vault key with a Secure Enclave key protected by
    /// the currently enrolled biometrics. Requires an unlocked vault, which
    /// proves the caller knew the master password.
    func enableBiometrics() throws {
        guard state == .unlocked, let key, let salt else { throw VaultError.locked }
        guard biometricsAvailable else {
            throw VaultError.biometricsSetupFailed(
                "Touch ID is not available on this Mac right now.")
        }
        // Installed under the vault lock only if the vault on disk is
        // still the one this key opens; otherwise another instance has
        // changed it (and maybe the master password) and this key would
        // overwrite a valid wrapper with a stale one.
        try Self.storeWrappedKey(key, vaultSalt: salt, expectedDigest: diskDigest)
        UserDefaults.standard.set(true, forKey: Self.biometricsDefaultsKey)
        biometricsEnabled = true
    }

    /// Turn Touch ID off. The wrapped key file is deleted only when
    /// `deleteWrappedKeyMatching` is the exact content that was found to be
    /// unusable; passing nil keeps whatever is on disk.
    func disableBiometrics(deleteWrappedKeyMatching stale: Data? = nil) {
        if let stale { Self.deleteWrappedKey(matching: stale) }
        UserDefaults.standard.set(false, forKey: Self.biometricsDefaultsKey)
        biometricsEnabled = false
    }

    /// Turn Touch ID off from the UI, removing the wrapped key.
    func disableBiometricsAndForget() {
        Self.deleteWrappedKey(matching: nil)
        UserDefaults.standard.set(false, forKey: Self.biometricsDefaultsKey)
        biometricsEnabled = false
    }

    /// Re-encrypt the vault under a new master password. Requires the
    /// vault to be unlocked; the current password is verified to prove
    /// the caller knows it, not just that the panel is open. Honors task
    /// cancellation up to the moment the file is written.
    func changeMasterPassword(current: String, new: String) async throws {
        guard !busy else { throw VaultError.busy }
        guard state == .unlocked, let salt, let key else { throw VaultError.locked }
        guard new.count >= Self.minMasterPasswordLength
        else { throw VaultError.weakPassword }
        busy = true
        defer { busy = false }
        let generation = self.generation

        let verifyKey = try await Self.deriveKey(
            password: current, salt: salt, iterations: iterations)
        guard generation == self.generation else { throw CancellationError() }
        try Task.checkCancellation()
        guard verifyKey == key else { throw VaultError.badPassword }

        let newSalt = try Self.randomSalt()
        let newKey = try await Self.deriveKey(
            password: new, salt: newSalt, iterations: Self.defaultPBKDF2Iterations)
        guard generation == self.generation else { throw CancellationError() }
        try Task.checkCancellation()

        // Keep Touch ID working across the change: the wrapped key is the
        // derived key, which just changed. Re-wrapping needs no biometric
        // prompt. If it can't be prepared, fall back to disabled rather
        // than leaving a stale key that can never open the vault.
        var wrapped: Data?
        if biometricsEnabled {
            wrapped = try? Self.makeWrappedKeyData(newKey, vaultSalt: newSalt)
            if wrapped == nil { disableBiometrics(deleteWrappedKeyMatching: nil) }
        }

        // Write first; memory changes only once the files are safely on
        // disk so a failed save never leaves memory and disk expecting
        // different passwords. Vault and wrapper are replaced under one
        // lock so no reader ever sees a new vault with the old wrapper.
        let result = try Self.writeVault(
            entries: entries, key: newKey, salt: newSalt,
            iterations: Self.defaultPBKDF2Iterations, expectedDigest: diskDigest,
            wrappedKey: wrapped)
        self.salt = newSalt
        self.key = newKey
        self.iterations = Self.defaultPBKDF2Iterations
        self.diskDigest = result.digest

        // The vault is committed even if the wrapper could not be
        // installed after it; that only costs Touch ID, never the change.
        if wrapped != nil && !result.wrappedKeyInstalled {
            disableBiometrics(deleteWrappedKeyMatching: nil)
        }
    }

    func lock() {
        // Bump first so any in-flight unlock/change abandons its result
        // even when we were already locked, and so views drop whatever
        // credentials they hold.
        generation &+= 1
        lockEpoch &+= 1
        activeAuthContext?.invalidate()
        activeAuthContext = nil
        // Never move an uninitialized vault to .locked (e.g. sleep before
        // any vault file exists); there is nothing to lock.
        guard state != .uninitialized else { return }
        key = nil
        salt = nil
        entries = []
        diskDigest = nil
        state = .locked
    }

    // MARK: - CRUD

    // Every mutation is written to disk first and published only if the
    // write succeeded, so a failed save can never show an entry that is
    // not actually stored (or hide one that still is).

    func add(_ entry: PasswordEntry) throws {
        var updated = entries
        updated.append(entry)
        try commit(updated)
    }

    func update(_ entry: PasswordEntry) throws {
        var updated = entries
        guard let idx = updated.firstIndex(where: { $0.id == entry.id }) else { return }
        updated[idx] = entry
        try commit(updated)
    }

    func delete(_ entry: PasswordEntry) throws {
        var updated = entries
        updated.removeAll { $0.id == entry.id }
        try commit(updated)
    }

    /// Reorder entries; the order is persisted as part of the vault.
    func move(fromOffsets source: IndexSet, toOffset destination: Int) throws {
        var updated = entries
        updated.move(fromOffsets: source, toOffset: destination)
        try commit(updated)
    }

    /// Move a single entry up (`-1`) or down (`+1`) by one position.
    func move(_ entry: PasswordEntry, by delta: Int) throws {
        var updated = entries
        guard let idx = updated.firstIndex(where: { $0.id == entry.id }) else { return }
        let target = idx + delta
        guard updated.indices.contains(target) else { return }
        updated.swapAt(idx, target)
        try commit(updated)
    }

    private func commit(_ newEntries: [PasswordEntry]) throws {
        guard state == .unlocked, let key, let salt else { throw VaultError.locked }
        diskDigest = try Self.writeVault(
            entries: newEntries, key: key, salt: salt,
            iterations: iterations, expectedDigest: diskDigest).digest
        entries = newEntries
    }

    // MARK: - Persistence

    /// Serialize, encrypt, and atomically write the vault. Holds the
    /// cross-process lock across the staleness check and the replace.
    /// `expectedDigest` is the digest of the file this instance last saw
    /// (`nil` when creating: the file must not exist). When `wrappedKey`
    /// is given it is installed under the same lock, right after the
    /// vault, so the pair is never observed half-updated. Returns the
    /// digest of the vault file just written and whether the wrapper
    /// was installed: once the vault is on disk the write has succeeded,
    /// so a wrapper failure after it is reported, not thrown.
    nonisolated private static func writeVault(
        entries: [PasswordEntry],
        key: SymmetricKey,
        salt: Data,
        iterations: UInt32,
        expectedDigest: Data?,
        wrappedKey: Data? = nil
    ) throws -> (digest: Data, wrappedKeyInstalled: Bool) {
        var plaintext = try JSONEncoder().encode(entries)
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }

        var header = Data()
        header.append(magic)
        header.append(version)
        header.append(kdfPBKDF2HmacSHA256)
        withUnsafeBytes(of: iterations.bigEndian) { header.append(contentsOf: $0) }
        header.append(salt)

        let box = try AES.GCM.seal(plaintext, using: key, authenticating: header)
        guard let combined = box.combined else { throw VaultError.corrupted }
        var data = header
        data.append(combined)

        let lock = try VaultLock.acquire(exclusive: true)
        defer { lock.release() }

        // Refuse to clobber a file that changed under us.
        let onDisk = try readIfExists(fileURL)
        switch (expectedDigest, onDisk) {
        case (nil, nil): break
        case (nil, .some): throw VaultError.staleVault
        case (.some, nil): throw VaultError.staleVault
        case (.some(let expected), .some(let current)):
            guard digest(of: current) == expected else { throw VaultError.staleVault }
        }

        try writeOwnerOnly(data, to: fileURL)
        var wrappedKeyInstalled = false
        if let wrappedKey {
            wrappedKeyInstalled = (try? writeOwnerOnly(wrappedKey, to: wrappedKeyURL)) != nil
        }
        return (digest(of: data), wrappedKeyInstalled)
    }

    nonisolated private static func digest(of data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    nonisolated private static func randomSalt() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: saltLength)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        else { throw VaultError.corrupted }
        return Data(bytes)
    }

    /// Reads a file, returning nil if it does not exist and rethrowing
    /// any other error.
    nonisolated private static func readIfExists(_ url: URL) throws -> Data? {
        do {
            return try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return nil
        } catch let error as NSError
            where error.domain == NSPOSIXErrorDomain && error.code == Int(ENOENT) {
            return nil
        }
    }

    /// Write `data` to `url` so that at no point does a file with wider
    /// than owner-only permissions or partial contents exist at `url`:
    /// exclusive creation of a uniquely named temp file with mode 0600
    /// (fchmod'ed to exactly that, whatever the umask), fsync, then an
    /// atomic replace that keeps the temp file's metadata (the original's
    /// mode is deliberately not preserved). Nothing that can fail runs
    /// after the replace, so a thrown error always means the old file is
    /// still in place.
    nonisolated private static func writeOwnerOnly(_ data: Data, to url: URL) throws {
        let tmpURL = url.deletingLastPathComponent().appendingPathComponent(
            ".\(url.lastPathComponent).\(UUID().uuidString).tmp")

        let fd = Darwin.open(tmpURL.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError() }
        var installed = false
        var closed = false
        defer {
            if !closed { _ = Darwin.close(fd) }
            if !installed { try? FileManager.default.removeItem(at: tmpURL) }
        }
        guard fchmod(fd, 0o600) == 0 else { throw posixError() }

        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            guard let base = buf.baseAddress else { return }
            var offset = 0
            while offset < buf.count {
                let n = Darwin.write(fd, base + offset, buf.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw posixError()
                }
                offset += n
            }
        }
        guard fsync(fd) == 0 else { throw posixError() }
        closed = true
        guard Darwin.close(fd) == 0 else { throw posixError() }

        if FileManager.default.fileExists(atPath: url.path) {
            _ = try FileManager.default.replaceItemAt(
                url, withItemAt: tmpURL, backupItemName: nil,
                options: .usingNewMetadataOnly)
        } else {
            try FileManager.default.moveItem(at: tmpURL, to: url)
        }
        installed = true
    }

    nonisolated private static func posixError() -> Error {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    /// Best-effort: make sure the on-disk files are owner-only, e.g. after
    /// a restore from a backup that widened them.
    nonisolated private static func repairPermissions() {
        for url in [fileURL, wrappedKeyURL] {
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }

    /// Cross-process mutual exclusion for vault and wrapped-key writes,
    /// via flock(2) on a lock file beside the vault. Readers take it
    /// shared so they never observe a half-replaced pair of files.
    ///
    /// Acquisition never blocks indefinitely: most callers run on the
    /// main actor, and a peer instance that is suspended while holding
    /// the lock must not freeze this one. The lock is polled without
    /// blocking for a short bounded time (holders keep it for
    /// milliseconds), then `fileBusy` is thrown for the user to retry.
    private struct VaultLock {
        private let fd: Int32

        private static let acquireTimeout: DispatchTimeInterval = .milliseconds(500)
        private static let pollInterval: useconds_t = 10_000

        nonisolated static func acquire(exclusive: Bool) throws -> VaultLock {
            let fd = Darwin.open(lockFileURL.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw posixError() }
            let operation = (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB
            let deadline = DispatchTime.now() + acquireTimeout
            while true {
                if flock(fd, operation) == 0 { return VaultLock(fd: fd) }
                let code = errno
                if code != EWOULDBLOCK && code != EINTR {
                    _ = Darwin.close(fd)
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
                }
                if DispatchTime.now() >= deadline {
                    _ = Darwin.close(fd)
                    throw VaultError.fileBusy
                }
                usleep(pollInterval)
            }
        }

        nonisolated func release() {
            _ = flock(fd, LOCK_UN)
            _ = Darwin.close(fd)
        }
    }

    // MARK: - File parsing

    private struct VaultFile {
        let version: UInt8
        let iterations: UInt32
        let salt: Data
        /// Everything before the sealed box; GCM associated data for v3.
        let header: Data
        let box: AES.GCM.SealedBox
        let digest: Data
    }

    nonisolated private static func readVaultFile() throws -> VaultFile {
        try readVaultFiles().vault
    }

    /// Read the vault and, if present, the Touch ID wrapper under one
    /// shared lock, so the two always come from the same point in time.
    nonisolated private static func readVaultFiles() throws -> (vault: VaultFile, wrappedKey: Data?) {
        let lock = try VaultLock.acquire(exclusive: false)
        defer { lock.release() }

        let wrappedKey: Data?
        do {
            wrappedKey = try readIfExists(wrappedKeyURL)
        } catch {
            // A wrapper that can't be read right now is treated as absent
            // by the caller; that is never destructive.
            wrappedKey = nil
        }

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
        case 2, 3:
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
        let header = data.subdata(in: 0..<offset)

        // A box that can't even be constructed is a truncated/malformed
        // file, not a wrong password; only authentication failure is.
        guard let box = try? AES.GCM.SealedBox(combined: data.subdata(in: offset..<data.count))
        else { throw VaultError.corrupted }
        return (
            VaultFile(
                version: version, iterations: iterations, salt: salt,
                header: header, box: box, digest: digest(of: data)),
            wrappedKey
        )
    }

    nonisolated private static func open(
        _ file: VaultFile, using key: SymmetricKey
    ) throws -> [PasswordEntry] {
        var plaintext: Data
        do {
            plaintext = file.version >= 3
                ? try AES.GCM.open(file.box, using: key, authenticating: file.header)
                : try AES.GCM.open(file.box, using: key)
        } catch {
            throw VaultError.badPassword
        }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
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
    /// and AES-GCM seals the vault key with the vault's salt as associated
    /// data, binding the wrapper to this vault. The SE key blob, ephemeral
    /// public key, salt, and sealed box go into `passwords.touchid` (0600,
    /// written atomically under the vault lock) beside the vault.
    /// Unlocking reverses this; the ECDH on the SE side is what triggers
    /// the Touch ID sheet.
    private static let wrappedKeyMagic = Data("GHSTYTID".utf8)
    /// v2 binds the vault salt as GCM associated data. v1 (no AAD) is
    /// recognized but never used: any vault old enough to have one is
    /// pre-v3 and is upgraded, wrapper included, by a master-password
    /// unlock first.
    private static let wrappedKeyVersion: UInt8 = 2
    private static let wrappedKeyLegacyVersion: UInt8 = 1
    private static let wrappedKeyInfo = Data("ghostty-password-vault-touchid".utf8)

    nonisolated private static var wrappedKeyURL: URL {
        directoryURL.appendingPathComponent("passwords.touchid")
    }

    /// LAContext is not Sendable; it is only ever used from the one
    /// unwrap operation it was created for, and invalidated from the
    /// main actor, which is thread-safe.
    private struct AuthContextBox: @unchecked Sendable {
        let context: LAContext
        init(_ context: LAContext) { self.context = context }
    }

    /// Install a wrapped key, but only if the vault on disk still has
    /// `expectedDigest`: the key must belong to the vault it sits beside.
    nonisolated private static func storeWrappedKey(
        _ key: SymmetricKey, vaultSalt: Data, expectedDigest: Data?
    ) throws {
        let data = try makeWrappedKeyData(key, vaultSalt: vaultSalt)
        let lock = try VaultLock.acquire(exclusive: true)
        defer { lock.release() }
        guard let onDisk = try readIfExists(fileURL), digest(of: onDisk) == expectedDigest
        else { throw VaultError.staleVault }
        try writeOwnerOnly(data, to: wrappedKeyURL)
    }

    /// Build the wrapped-key file contents for `key`. Creates a fresh
    /// Secure Enclave key; no biometric prompt is involved.
    nonisolated private static func makeWrappedKeyData(_ key: SymmetricKey, vaultSalt: Data) throws -> Data {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &cfError)
        else {
            let reason = (cfError?.takeRetainedValue()).map { String(describing: $0) }
            throw VaultError.biometricsSetupFailed(reason ?? "Could not create access control.")
        }

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        } catch {
            throw VaultError.biometricsSetupFailed(describe(error))
        }

        let salt = try randomSalt()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: wrappedKeyInfo, outputByteCount: 32)
        var vaultKeyData = key.withUnsafeBytes { Data($0) }
        defer { vaultKeyData.resetBytes(in: 0..<vaultKeyData.count) }
        guard let sealed = try AES.GCM.seal(
            vaultKeyData, using: wrapKey, authenticating: vaultSalt).combined
        else { throw VaultError.corrupted }

        let seBlob = seKey.dataRepresentation
        let ephPub = ephemeral.publicKey.rawRepresentation
        var data = Data()
        data.append(wrappedKeyMagic)
        data.append(wrappedKeyVersion)
        withUnsafeBytes(of: UInt16(seBlob.count).bigEndian) { data.append(contentsOf: $0) }
        data.append(seBlob)
        withUnsafeBytes(of: UInt16(ephPub.count).bigEndian) { data.append(contentsOf: $0) }
        data.append(ephPub)
        data.append(salt)
        data.append(sealed)
        return data
    }

    /// Remove the wrapped key file. With `matching` set, only a file whose
    /// contents are exactly those bytes is removed, so a wrapper another
    /// instance installed in the meantime is never deleted by mistake.
    nonisolated private static func deleteWrappedKey(matching stale: Data?) {
        guard let lock = try? VaultLock.acquire(exclusive: true) else { return }
        defer { lock.release() }
        if let stale {
            guard let current = try? readIfExists(wrappedKeyURL), current == stale else { return }
        }
        try? FileManager.default.removeItem(at: wrappedKeyURL)
    }

    /// Unwraps the vault key; the Secure Enclave operation presents the
    /// Touch ID sheet. Runs off the main actor since it blocks until the
    /// user responds. Errors are classified so callers can tell a dead
    /// setup from a transient failure; see `VaultError`.
    @concurrent nonisolated private static func unwrapKey(
        _ wrappedKeyData: Data?,
        context box: AuthContextBox,
        vaultSalt: Data
    ) async throws -> SymmetricKey {
        // Nothing to use: confirmed.
        guard let data = wrappedKeyData else { throw VaultError.biometricsUnavailable }

        // Parse; a malformed file is confirmed unusable, not transient.
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
        guard try take(wrappedKeyMagic.count) == wrappedKeyMagic else {
            throw VaultError.biometricsUnavailable
        }
        switch try take(1).first {
        case wrappedKeyVersion: break
        case wrappedKeyLegacyVersion: throw VaultError.legacyNeedsPassword
        default: throw VaultError.biometricsUnavailable
        }
        let seBlob = try take(try takeU16())
        let ephPub = try take(try takeU16())
        let salt = try take(saltLength)
        let sealedData = data.subdata(in: offset..<data.count)
        guard let sealedBox = try? AES.GCM.SealedBox(combined: sealedData)
        else { throw VaultError.biometricsUnavailable }

        do {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seBlob, authenticationContext: box.context)
            let pub = try P256.KeyAgreement.PublicKey(rawRepresentation: ephPub)
            let shared = try seKey.sharedSecretFromKeyAgreement(with: pub)
            let wrapKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: salt, sharedInfo: wrappedKeyInfo, outputByteCount: 32)
            var vaultKeyData: Data
            do {
                vaultKeyData = try AES.GCM.open(sealedBox, using: wrapKey, authenticating: vaultSalt)
            } catch {
                // Wrong wrapping key or different vault salt: this wrapper
                // does not belong to this vault.
                throw VaultError.biometricsMismatch
            }
            defer { vaultKeyData.resetBytes(in: 0..<vaultKeyData.count) }
            guard vaultKeyData.count == 32 else { throw VaultError.biometricsMismatch }
            return SymmetricKey(data: vaultKeyData)
        } catch let error as VaultError {
            throw error
        } catch let error as NSError where error.domain == LAErrorDomain {
            switch LAError.Code(rawValue: error.code) {
            case .biometryNotEnrolled:
                // No fingerprints at all: the SE key can never be used.
                throw VaultError.biometricsUnavailable
            case .userCancel, .systemCancel, .appCancel, .userFallback,
                 .authenticationFailed, .biometryLockout, .biometryNotAvailable,
                 .notInteractive, .invalidContext:
                // Didn't authenticate this time (cancel, no match, lockout,
                // lid closed, lock() invalidated the prompt). Keep the setup.
                throw VaultError.biometricsCanceled
            default:
                throw VaultError.biometricsFailed(describe(error))
            }
        } catch {
            // Security / CryptoTokenKit / CryptoKit errors. An enrollment
            // change lands here too, but so can transient conditions, and
            // the two can't be told apart reliably, so the setup is kept
            // and the reason surfaced. The user can turn Touch ID off and
            // on again to rebuild it.
            throw VaultError.biometricsFailed(describe(error))
        }
    }

    nonisolated private static func describe(_ error: Error) -> String {
        let ns = error as NSError
        let text = ns.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        let detail = "\(ns.domain) \(ns.code)"
        if text.isEmpty { return "\(detail)." }
        return text.hasSuffix(".") ? "\(text) (\(detail))" : "\(text). (\(detail))"
    }

    /// Runs on the global concurrent executor, keeping the expensive PBKDF2
    /// work off the main thread. @concurrent (not just nonisolated async)
    /// so this holds even if the target adopts NonisolatedNonsendingByDefault
    /// (ApproachableConcurrency) or Swift 6 mode, where a plain nonisolated
    /// async function would silently run on the caller's actor instead.
    ///
    /// The password bytes and the derived key buffer are wiped on exit.
    /// The `String` the caller holds cannot be wiped; SwiftUI text fields
    /// own that copy until the view is discarded on lock.
    @concurrent nonisolated private static func deriveKey(
        password: String,
        salt: Data,
        iterations: UInt32
    ) async throws -> SymmetricKey {
        var passwordData = Data(password.utf8)
        defer { passwordData.resetBytes(in: 0..<passwordData.count) }
        var derived = [UInt8](repeating: 0, count: 32)
        defer {
            derived.withUnsafeMutableBytes { buf in
                _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
            }
        }
        let count = passwordData.count
        let status = passwordData.withUnsafeBytes { pwBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwBytes.bindMemory(to: Int8.self).baseAddress, count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &derived, derived.count)
            }
        }
        // Never proceed with an all-zero key if derivation failed.
        guard status == kCCSuccess else { throw VaultError.corrupted }
        // SymmetricKey copies into storage that is zeroed when released.
        return SymmetricKey(data: derived)
    }
}
