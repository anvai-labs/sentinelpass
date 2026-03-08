//
//  AddEntryView.swift
//  SentinelPass
//
//  Add new password entry
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct AddEntryView: View {
    @EnvironmentObject private var vaultState: VaultState
    @Environment(\.dismiss) private var dismiss

    @State private var title: String = ""
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var url: String = ""
    @State private var notes: String = ""
    @State private var showPassword: Bool = false
    @State private var showingGenerator: Bool = false
    @State private var passwordStrength: PasswordAnalysis?
    @State private var isSaving: Bool = false
    @State private var errorMessage: String = ""
    @State private var showingError: Bool = false
    @FocusState private var focusedField: Field?

    enum Field {
        case title, username, password, url, notes
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                        .focused($focusedField, equals: .title)

                    TextField("Username / Email", text: $username)
                        .focused($focusedField, equals: .username)
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                        .autocorrectionDisabled()

                    HStack {
                        Group {
                            if showPassword {
                                TextField("Password", text: $password)
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .focused($focusedField, equals: .password)

                        Button {
                            showPassword.toggle()
                        } label: {
                            Image(systemName: showPassword ? "eye.slash.fill" : "eye.fill")
                                .foregroundStyle(.secondary)
                        }

                        Button {
                            showingGenerator = true
                        } label: {
                            Image(systemName: "dice.fill")
                                .foregroundStyle(.blue)
                        }
                    }

                    // Password strength indicator
                    if !password.isEmpty, let strength = passwordStrength {
                        HStack(spacing: 8) {
                            ForEach(0..<4) { i in
                                Rectangle()
                                    .fill(i < strength.score ? strength.strengthColor : .gray.opacity(0.3))
                                    .frame(height: 4)
                            }
                            Text(strength.strengthDescription)
                                .font(.caption)
                                .foregroundStyle(strength.strengthColor)
                        }
                    }
                } header: {
                    Text("Credentials")
                }

                Section {
                    TextField("Website URL", text: $url)
                        .focused($focusedField, equals: .url)
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        #endif
                } header: {
                    Text("Website")
                }

                Section {
                    TextField("Notes", text: $notes, axis: .vertical)
                        .focused($focusedField, equals: .notes)
                        .lineLimit(3...6)
                } header: {
                    Text("Notes")
                }
            }
            .navigationTitle("Add Entry")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        saveEntry()
                    } label: {
                        if isSaving {
                            ProgressView()
                        } else {
                            Text("Save")
                        }
                    }
                    .disabled(title.isEmpty || username.isEmpty || password.isEmpty || isSaving)
                }
            }
            .onChange(of: password) { _, _ in
                checkPasswordStrength()
            }
            .sheet(isPresented: $showingGenerator) {
                PasswordGeneratorView(generatedPassword: $password)
            }
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(errorMessage)
            }
        }
    }

    private func checkPasswordStrength() {
        Task {
            if !password.isEmpty {
                passwordStrength = await vaultState.checkPasswordStrength(password: password)
            }
        }
    }

    private func saveEntry() {
        focusedField = nil
        isSaving = true

        Task {
            do {
                try await vaultState.addEntry(
                    title: title,
                    username: username,
                    password: password,
                    url: url,
                    notes: notes
                )
                isSaving = false
                dismiss()
            } catch {
                isSaving = false
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    AddEntryView()
        .environmentObject(VaultState.shared)
}
