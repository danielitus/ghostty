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
            TextField("Search", text: $search)
                .textFieldStyle(.roundedBorder)
                .padding(8)

            List(selection: $selection) {
                ForEach(filtered) { entry in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.label)
                        if !entry.username.isEmpty {
                            Text(entry.username)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .tag(entry.id)
                    .contextMenu {
                        Button("Edit…") { editing = entry }
                        Button("Delete", role: .destructive) {
                            try? vault.delete(entry)
                        }
                    }
                }
            }
            .frame(minHeight: 180)

            Divider()

            VStack(spacing: 8) {
                HStack {
                    Button("Send Username") { send(selected?.username) }
                        .disabled(selected?.username.isEmpty ?? true)
                    Button("Send Password") { send(selected?.password) }
                        .disabled(selected == nil)
                        .keyboardShortcut(.defaultAction)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Toggle("Press Enter after sending", isOn: $pressEnter)
                        .onChange(of: pressEnter) { v in
                            UserDefaults.standard.set(v, forKey: "PasswordManagerPressEnter")
                        }
                    Toggle("Open automatically at password prompts", isOn: $autoOpen)
                        .onChange(of: autoOpen) { v in
                            UserDefaults.standard.set(v, forKey: "PasswordManagerAutoOpen")
                        }
                }
                .toggleStyle(.checkbox)
                .font(.caption)
                .frame(maxWidth: .infinity, alignment: .leading)

                HStack {
                    Button {
                        editing = PasswordEntry(label: "", username: "", password: "")
                    } label: {
                        Image(systemName: "plus")
                    }
                    Button {
                        if let selected { editing = selected }
                    } label: {
                        Image(systemName: "pencil")
                    }
                    .disabled(selected == nil)
                    Button {
                        if let selected { try? vault.delete(selected) }
                    } label: {
                        Image(systemName: "minus")
                    }
                    .disabled(selected == nil)

                    Spacer()

                    Button("Lock") { vault.lock() }
                }
            }
            .padding(8)
        }
        .frame(width: 340, height: 400)
        .sheet(item: $editing) { entry in
            PasswordEntryEditView(vault: vault, entry: entry)
        }
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
