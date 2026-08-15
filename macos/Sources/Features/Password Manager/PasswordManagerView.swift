import SwiftUI

struct PasswordManagerView: View {
    @ObservedObject var vault: PasswordVault = .shared

    /// Called with the text to type into the focused terminal surface.
    var onSend: (String) -> Void

    var body: some View {
        switch vault.state {
        case .uninitialized:
            PasswordVaultCreateView(vault: vault)
        case .locked:
            PasswordVaultUnlockView(vault: vault)
        case .unlocked:
            PasswordListView(vault: vault, onSend: onSend)
        }
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
                .disabled(password.isEmpty)
        }
        .padding(20)
        .frame(width: 320)
    }

    private func create() {
        guard password == confirm else {
            error = "Passwords do not match."
            return
        }
        do {
            try vault.create(masterPassword: password)
        } catch {
            self.error = error.localizedDescription
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
                Text(error).font(.caption).foregroundStyle(.red)
            }

            Button("Unlock", action: unlock)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty)
        }
        .padding(20)
        .frame(width: 320)
        .onAppear { focused = true }
    }

    private func unlock() {
        do {
            try vault.unlock(masterPassword: password)
        } catch {
            self.error = error.localizedDescription
            password = ""
        }
    }
}

// MARK: - Entry list

private struct PasswordListView: View {
    @ObservedObject var vault: PasswordVault
    var onSend: (String) -> Void

    @State private var search = ""
    @State private var selection: UUID?
    @State private var editing: PasswordEntry?
    @State private var pressEnter = UserDefaults.standard.bool(
        forKey: "PasswordManagerPressEnter")
    @State private var autoOpen = UserDefaults.standard.bool(
        forKey: "PasswordManagerAutoOpen")
    @State private var lockOnClose = UserDefaults.standard.bool(
        forKey: "PasswordManagerLockOnClose")

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
                            Button("Send Username") { send(entry.username) }
                                .disabled(entry.username.isEmpty)
                            Divider()
                            Button("Edit…") { editing = entry }
                            Button("Delete", role: .destructive) {
                                try? vault.delete(entry)
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }

            Divider()

            HStack(spacing: 8) {
                Button("Send Username") { send(selected?.username) }
                    .disabled(selected?.username.isEmpty ?? true)
                Button("Send Password") { send(selected?.password) }
                    .buttonStyle(.borderedProminent)
                    .disabled(selected == nil)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)

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
                    if let selected { try? vault.delete(selected) }
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
        .frame(width: 340, height: 420)
        .onAppear { selectFirstIfNeeded() }
        .onChange(of: search) { _ in selectFirstIfNeeded() }
        .sheet(item: $editing) { entry in
            PasswordEntryEditView(vault: vault, entry: entry)
        }
    }

    private func selectFirstIfNeeded() {
        if selected == nil { selection = filtered.first?.id }
    }

    private func send(_ text: String?) {
        guard let text, !text.isEmpty else { return }
        // Strip control characters so a stored value can never inject key
        // presses beyond the credential itself; Enter is appended only via
        // the explicit toggle below.
        let clean = String(text.unicodeScalars.filter {
            $0.value >= 0x20 && !(0x7F...0x9F).contains($0.value)
        })
        guard !clean.isEmpty else { return }
        onSend(pressEnter ? clean + "\r" : clean)
    }
}

// MARK: - Edit sheet

private struct PasswordEntryEditView: View {
    @ObservedObject var vault: PasswordVault
    @State var entry: PasswordEntry
    @State private var showPassword = false
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

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") {
                    if isNew {
                        try? vault.add(entry)
                    } else {
                        try? vault.update(entry)
                    }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(entry.label.isEmpty)
            }
        }
        .padding(16)
        .frame(width: 320)
    }
}
