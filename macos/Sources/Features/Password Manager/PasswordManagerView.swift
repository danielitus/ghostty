import SwiftUI

struct PasswordManagerView: View {
    @ObservedObject var vault: PasswordVault = .shared
    @ObservedObject var target: PasswordManagerTarget

    /// Called with the text to type into the target terminal surface and
    /// whether to press Enter afterwards.
    var onSend: (String, Bool) -> Void

    var body: some View {
        Group {
            switch vault.state {
            case .uninitialized:
                PasswordVaultCreateView(vault: vault)
            case .locked:
                PasswordVaultUnlockView(vault: vault)
            case .unlocked:
                PasswordListView(vault: vault, target: target, onSend: onSend)
            }
        }
        // Every lock() bumps the epoch. Keying the whole tree on it throws
        // away typed master passwords, entry drafts, and open sheets on
        // each lock, even when the vault state did not change (locking a
        // vault that was already locked used to keep the typed password).
        .id(vault.lockEpoch)
    }
}

// MARK: - Create

private struct PasswordVaultCreateView: View {
    @ObservedObject var vault: PasswordVault
    @State private var password = ""
    @State private var confirm = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.fill")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text("Create a Password Vault")
                .font(.headline)
            Text("Passwords are stored in an encrypted file protected by a master password. If you forget it, the vault cannot be recovered.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("Master Password", text: $password)
            SecureField("Confirm Password", text: $confirm)
                .onSubmit(create)

            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            Button("Create Vault", action: create)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || vault.busy)
        }
        .padding(20)
        .frame(width: 320)
    }

    private func create() {
        guard password == confirm else {
            error = "Passwords do not match."
            return
        }
        Task {
            do {
                try await vault.create(masterPassword: password)
            } catch is CancellationError {
                // Vault was locked while deriving; nothing to report.
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

// MARK: - Unlock

private struct PasswordVaultUnlockView: View {
    @ObservedObject var vault: PasswordVault
    @State private var password = ""
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.fill")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text("Vault Locked")
                .font(.headline)

            SecureField("Master Password", text: $password)
                .focused($focused)
                .onSubmit(unlock)

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            HStack {
                if vault.biometricsEnabled && vault.biometricsAvailable {
                    Button {
                        unlockWithBiometrics()
                    } label: {
                        Label("Touch ID", systemImage: "touchid")
                    }
                    .disabled(vault.busy)
                    .help("Unlock with Touch ID")
                }
                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || vault.busy)
            }
        }
        .padding(20)
        .frame(width: 320)
        .onAppear { focused = true }
        .onReceive(NotificationCenter.default.publisher(
            for: PasswordVault.biometricUnlockRequested)
        ) { _ in
            unlockWithBiometrics()
        }
    }

    private func unlock() {
        Task {
            do {
                try await vault.unlock(masterPassword: password)
            } catch is CancellationError {
                password = ""
            } catch {
                self.error = error.localizedDescription
                password = ""
            }
        }
    }

    private func unlockWithBiometrics() {
        guard vault.biometricsEnabled, !vault.busy else { return }
        Task {
            do {
                try await vault.unlockWithBiometrics()
            } catch PasswordVault.VaultError.biometricsCanceled {
                // User backed out; the password field is the fallback.
                focused = true
            } catch is CancellationError {
                // Vault was locked mid-prompt; nothing to report.
            } catch {
                self.error = error.localizedDescription
                focused = true
            }
        }
    }
}

// MARK: - Entry list

private struct PasswordListView: View {
    @ObservedObject var vault: PasswordVault
    @ObservedObject var target: PasswordManagerTarget
    var onSend: (String, Bool) -> Void

    @State private var search = ""
    @State private var selection: UUID?
    @State private var editing: PasswordEntry?
    @State private var pressEnter = UserDefaults.standard.bool(
        forKey: "PasswordManagerPressEnter")
    @State private var autoOpen = UserDefaults.standard.bool(
        forKey: "PasswordManagerAutoOpen")
    @State private var lockOnClose = UserDefaults.standard.bool(
        forKey: "PasswordManagerLockOnClose")
    @State private var changingPassword = false
    @State private var alert: AlertInfo?

    private struct AlertInfo: Identifiable {
        let id = UUID()
        let title: String
        let message: String
        /// The vault changed on disk; offer to reload it.
        let stale: Bool
    }

    private var filtered: [PasswordEntry] {
        guard !search.isEmpty else { return vault.entries }
        return vault.entries.filter {
            $0.label.localizedCaseInsensitiveContains(search) ||
            $0.username.localizedCaseInsensitiveContains(search)
        }
    }

    private var selected: PasswordEntry? {
        filtered.first { $0.id == selection }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search", text: $search)
                    .textFieldStyle(.plain)
                if !search.isEmpty {
                    Button {
                        search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }
            .padding(6)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            .padding(10)

            if filtered.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: search.isEmpty ? "key.slash" : "magnifyingglass")
                        .font(.system(size: 28))
                        .foregroundStyle(.tertiary)
                    Text(search.isEmpty ? "No Passwords" : "No Results")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                    if search.isEmpty {
                        Text("Click + below to add your first entry.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $selection) {
                    ForEach(filtered) { entry in
                        HStack(spacing: 8) {
                            Image(systemName: "key.fill")
                                .foregroundStyle(.secondary)
                                .frame(width: 20, height: 20)
                                .background(.quaternary.opacity(0.6), in: Circle())
                            VStack(alignment: .leading, spacing: 1) {
                                Text(entry.label)
                                if !entry.username.isEmpty {
                                    Text(entry.username)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 2)
                        .contentShape(Rectangle())
                        .simultaneousGesture(TapGesture(count: 2).onEnded {
                            selection = entry.id
                            send(entry.password)
                        })
                        .tag(entry.id)
                        .contextMenu {
                            Button("Send Password") { send(entry.password) }
                                .disabled(target.title == nil)
                            Button("Send Username") { send(entry.username) }
                                .disabled(entry.username.isEmpty || target.title == nil)
                            Divider()
                            Button("Move Up") { perform { try vault.move(entry, by: -1) } }
                                .disabled(!search.isEmpty || vault.entries.first?.id == entry.id)
                            Button("Move Down") { perform { try vault.move(entry, by: 1) } }
                                .disabled(!search.isEmpty || vault.entries.last?.id == entry.id)
                            Divider()
                            Button("Edit…") { editing = entry }
                            Button("Delete", role: .destructive) {
                                perform { try vault.delete(entry) }
                            }
                        }
                    }
                    // Drag to reorder. Only meaningful on the unfiltered
                    // list: offsets in a filtered view don't map to the
                    // vault, so reordering is disabled while searching.
                    .onMove { source, destination in
                        guard search.isEmpty else { return }
                        perform { try vault.move(fromOffsets: source, toOffset: destination) }
                    }
                }
                .listStyle(.inset)
            }

            Divider()

            VStack(spacing: 6) {
                HStack(spacing: 8) {
                    Button("Send Username") { send(selected?.username) }
                        .disabled(selected?.username.isEmpty ?? true || target.title == nil)
                    Button("Send Password") { send(selected?.password) }
                        .buttonStyle(.borderedProminent)
                        .disabled(selected == nil || target.title == nil)
                        .keyboardShortcut(.defaultAction)
                }
                .controlSize(.large)

                // Where the credential will be typed, resolved live so it
                // always matches what Send would do right now.
                if let title = target.title {
                    Text("Sends to \u{201C}\(title)\u{201D}")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                } else {
                    Text("No terminal window to send to")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .padding(.horizontal, 10)

            Divider()

            HStack(spacing: 2) {
                Button {
                    editing = PasswordEntry(label: "", username: "", password: "")
                } label: {
                    Image(systemName: "plus")
                        .frame(width: 20, height: 20)
                }
                .help("Add entry")
                Button {
                    if let selected { editing = selected }
                } label: {
                    Image(systemName: "pencil")
                        .frame(width: 20, height: 20)
                }
                .disabled(selected == nil)
                .help("Edit entry")
                Button {
                    if let selected { perform { try vault.delete(selected) } }
                } label: {
                    Image(systemName: "minus")
                        .frame(width: 20, height: 20)
                }
                .disabled(selected == nil)
                .help("Delete entry")

                Spacer()

                Menu {
                    Toggle("Press Enter After Sending", isOn: $pressEnter)
                    Toggle("Open at Password Prompts", isOn: $autoOpen)
                    Toggle("Lock When Window Closes", isOn: $lockOnClose)
                    Divider()
                    Toggle("Unlock with Touch ID", isOn: Binding(
                        get: { vault.biometricsEnabled },
                        set: { on in
                            if on {
                                perform(title: "Couldn't Enable Touch ID") {
                                    try vault.enableBiometrics()
                                }
                            } else {
                                vault.disableBiometrics()
                            }
                        }))
                        .disabled(!vault.biometricsAvailable)
                    Button("Change Master Password…") { changingPassword = true }
                } label: {
                    Image(systemName: "gearshape")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Options")

                Button {
                    vault.lock()
                } label: {
                    Image(systemName: "lock.fill")
                        .frame(width: 20, height: 20)
                }
                .help("Lock vault")
            }
            .buttonStyle(.borderless)
            .padding(8)
            .onChange(of: pressEnter) { v in
                UserDefaults.standard.set(v, forKey: "PasswordManagerPressEnter")
            }
            .onChange(of: autoOpen) { v in
                UserDefaults.standard.set(v, forKey: "PasswordManagerAutoOpen")
            }
            .onChange(of: lockOnClose) { v in
                UserDefaults.standard.set(v, forKey: "PasswordManagerLockOnClose")
            }
        }
        .frame(width: 340, height: 440)
        .onAppear { selectFirstIfNeeded() }
        .onChange(of: search) { _ in selectFirstIfNeeded() }
        // Keep a valid selection across adds, deletes, and reorders too,
        // not just searches: the first entry added to an empty vault is
        // selected, and deleting the selected entry selects a neighbor.
        .onChange(of: filtered.map(\.id)) { _ in selectFirstIfNeeded() }
        .sheet(item: $editing) { entry in
            PasswordEntryEditView(vault: vault, entry: entry)
        }
        .sheet(isPresented: $changingPassword) {
            ChangeMasterPasswordView(vault: vault)
        }
        .alert(item: $alert) { info in
            if info.stale {
                return Alert(
                    title: Text(info.title),
                    message: Text(info.message),
                    primaryButton: .default(Text("Reload")) {
                        perform(title: "Couldn't Reload") { try vault.reloadFromDisk() }
                    },
                    secondaryButton: .cancel())
            }
            return Alert(
                title: Text(info.title),
                message: Text(info.message),
                dismissButton: .default(Text("OK")))
        }
    }

    private func selectFirstIfNeeded() {
        if selected == nil { selection = filtered.first?.id }
    }

    /// Run a vault mutation and surface its failure instead of hiding it;
    /// the vault only publishes changes that were written, so a failure
    /// here means nothing changed.
    private func perform(title: String = "Couldn't Save", _ action: () throws -> Void) {
        do {
            try action()
        } catch {
            let stale: Bool
            if case PasswordVault.VaultError.staleVault? = error as? PasswordVault.VaultError {
                stale = true
            } else {
                stale = false
            }
            alert = AlertInfo(title: title, message: error.localizedDescription, stale: stale)
        }
    }

    private func send(_ text: String?) {
        guard let text, !text.isEmpty else { return }
        // Strip control characters so a stored value can never inject key
        // presses beyond the credential itself. Enter, when enabled, is
        // sent by the controller as a real key event rather than as a
        // carriage return inside the text: the text goes through the paste
        // path, and inside a bracketed paste a "\r" is inserted literally
        // instead of submitting.
        let clean = String(text.unicodeScalars.filter {
            $0.value >= 0x20 && !(0x7F...0x9F).contains($0.value)
        })
        guard !clean.isEmpty else { return }
        onSend(clean, pressEnter)
    }
}

// MARK: - Change master password sheet

private struct ChangeMasterPasswordView: View {
    @ObservedObject var vault: PasswordVault
    @State private var current = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    @State private var error: String?
    @State private var task: Task<Void, Never>?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 12) {
            Text("Change Master Password")
                .font(.headline)

            Form {
                SecureField("Current Password", text: $current)
                SecureField("New Password", text: $newPassword)
                SecureField("Confirm New Password", text: $confirm)
                    .onSubmit(change)
            }

            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") {
                    // Cancelling really cancels: the vault checks for
                    // cancellation before it commits the new password.
                    task?.cancel()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Change", action: change)
                    .keyboardShortcut(.defaultAction)
                    .disabled(current.isEmpty || newPassword.isEmpty || vault.busy)
            }
        }
        .padding(16)
        .frame(width: 320)
        .onDisappear { task?.cancel() }
    }

    private func change() {
        guard newPassword == confirm else {
            error = "New passwords do not match."
            return
        }
        task = Task {
            do {
                try await vault.changeMasterPassword(current: current, new: newPassword)
                dismiss()
            } catch is CancellationError {
                dismiss()
            } catch {
                self.error = error.localizedDescription
                current = ""
            }
        }
    }
}

// MARK: - Edit sheet

private struct PasswordEntryEditView: View {
    @ObservedObject var vault: PasswordVault
    @State var entry: PasswordEntry
    @State private var showPassword = false
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    private var isNew: Bool {
        !vault.entries.contains { $0.id == entry.id }
    }

    var body: some View {
        VStack(spacing: 12) {
            Text(isNew ? "New Entry" : "Edit Entry")
                .font(.headline)

            Form {
                TextField("Label", text: $entry.label)
                TextField("Username", text: $entry.username)
                HStack {
                    if showPassword {
                        TextField("Password", text: $entry.password)
                    } else {
                        SecureField("Password", text: $entry.password)
                    }
                    Button {
                        showPassword.toggle()
                    } label: {
                        Image(systemName: showPassword ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                }
            }

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(entry.label.isEmpty)
            }
        }
        .padding(16)
        .frame(width: 320)
    }

    private func save() {
        do {
            if isNew {
                try vault.add(entry)
            } else {
                try vault.update(entry)
            }
            dismiss()
        } catch {
            // Keep the sheet open so nothing typed is lost.
            self.error = error.localizedDescription
        }
    }
}
