//
//  PasswordGeneratorView.swift
//  SentinelPass
//
//  Standalone password generator sheet
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct PasswordGeneratorView: View {
    @EnvironmentObject private var vaultState: VaultState
    @Environment(\.dismiss) private var dismiss

    @Binding var generatedPassword: String
    @State private var length: Double = 20
    @State private var includeSymbols: Bool = true
    @State private var passwordStrength: PasswordAnalysis?

    var body: some View {
        NavigationStack {
            Form {
                // Generated Password Display
                Section {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(generatedPassword.isEmpty ? "Tap Generate to create a password" : generatedPassword)
                            .font(.body.monospaced())
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .foregroundStyle(generatedPassword.isEmpty ? .secondary : .primary)

                        HStack {
                            Button {
                                generatePassword()
                            } label: {
                                Label("Generate", systemImage: "dice.fill")
                            }
                            .buttonStyle(.borderedProminent)

                            Spacer()

                            Button {
                                dismiss()
                            } label: {
                                Text("Use Password")
                            }
                            .buttonStyle(.bordered)
                            .disabled(generatedPassword.isEmpty)
                        }
                    }
                    .padding(.vertical, 8)
                }

                // Password Strength
                if let strength = passwordStrength {
                    Section {
                        HStack(spacing: 4) {
                            ForEach(0..<4) { i in
                                Rectangle()
                                    .fill(i < strength.score ? strength.strengthColor : .gray.opacity(0.3))
                                    .frame(height: 8)
                            }
                        }
                        Text(strength.strengthDescription)
                            .font(.caption)
                            .foregroundStyle(strength.strengthColor)
                    } header: {
                        Text("Strength")
                    }
                }

                // Options
                Section {
                    VStack(alignment: .leading) {
                        HStack {
                            Text("Length: \(Int(length))")
                            Spacer()
                        }

                        Slider(value: $length, in: 8...64, step: 1)
                    }
                    .padding(.vertical, 8)

                    Toggle("Include Symbols (!@#$%^&*)", isOn: $includeSymbols)
                } header: {
                    Text("Options")
                }
            }
            .navigationTitle("Generate Password")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
            .onAppear {
                if generatedPassword.isEmpty {
                    generatePassword()
                }
            }
        }
    }

    private func generatePassword() {
        Task {
            if let password = await vaultState.generatePassword(length: Int(length), includeSymbols: includeSymbols) {
                generatedPassword = password
                passwordStrength = await vaultState.checkPasswordStrength(password: password)
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    PasswordGeneratorView(generatedPassword: .constant(""))
        .environmentObject(VaultState.shared)
}
