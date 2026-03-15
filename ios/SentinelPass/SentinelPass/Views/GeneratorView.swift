//
//  GeneratorView.swift
//  SentinelPass
//
//  Password generator screen
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct GeneratorView: View {
    @EnvironmentObject private var vaultState: VaultState
    @State private var generatedPassword: String = ""
    @State private var length: Double = 20
    @State private var includeSymbols: Bool = true
    @State private var includeNumbers: Bool = true
    @State private var includeUppercase: Bool = true
    @State private var includeLowercase: Bool = true
    @State private var passwordStrength: PasswordAnalysis?
    @State private var copied: Bool = false

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

                            if !generatedPassword.isEmpty {
                                Spacer()

                                Button {
                                    copyPassword()
                                } label: {
                                    Label(copied ? "Copied!" : "Copy", systemImage: "doc.on.doc")
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    }
                    .padding(.vertical, 8)
                }

                // Password Strength
                if let strength = passwordStrength {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("Strength")
                                    .font(.headline)
                                Spacer()
                                Text(strength.strengthDescription)
                                    .foregroundStyle(strength.strengthColor)
                            }

                            HStack(spacing: 4) {
                                ForEach(0..<4) { i in
                                    Rectangle()
                                        .fill(i < strength.score ? strength.strengthColor : .gray.opacity(0.3))
                                        .frame(height: 8)
                                }
                            }

                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text("Entropy:")
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Text("\(Int(strength.entropyBits)) bits")
                                        .foregroundStyle(.primary)
                                }

                                HStack {
                                    Text("Length:")
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Text("\(strength.length) characters")
                                        .foregroundStyle(.primary)
                                }

                                HStack {
                                    Text("Crack time:")
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Text(formatCrackTime(strength.crackTimeSeconds))
                                        .foregroundStyle(.primary)
                                }
                            }
                            .font(.caption)
                        }
                    } header: {
                        Text("Analysis")
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

                        Text("Use longer passwords for better security")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 8)

                    Toggle("Include Symbols (!@#$%^&*)", isOn: $includeSymbols)
                    Toggle("Include Numbers (0-9)", isOn: $includeNumbers)
                    Toggle("Include Uppercase (A-Z)", isOn: $includeUppercase)
                    Toggle("Include Lowercase (a-z)", isOn: $includeLowercase)
                } header: {
                    Text("Options")
                }
            }
            .navigationTitle("Generate Password")
            .onChange(of: length) { _, _ in
                if !generatedPassword.isEmpty {
                    generatePassword()
                }
            }
            .onChange(of: includeSymbols) { _, _ in
                if !generatedPassword.isEmpty {
                    generatePassword()
                }
            }
            .onChange(of: includeNumbers) { _, _ in
                if !generatedPassword.isEmpty {
                    generatePassword()
                }
            }
            .onChange(of: includeUppercase) { _, _ in
                if !generatedPassword.isEmpty {
                    generatePassword()
                }
            }
            .onChange(of: includeLowercase) { _, _ in
                if !generatedPassword.isEmpty {
                    generatePassword()
                }
            }
        }
    }

    private func generatePassword() {
        Task {
            // Generate with our bridge
            if let password = await vaultState.generatePassword(length: Int(length), includeSymbols: includeSymbols) {
                generatedPassword = password
                passwordStrength = await vaultState.checkPasswordStrength(password: password)
            }
        }
    }

    private func copyPassword() {
        #if os(iOS)
        UIPasteboard.general.string = generatedPassword
        #endif

        copied = true

        Task {
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }

    private func formatCrackTime(_ seconds: Double) -> String {
        if seconds < 1 {
            return "Instantly"
        } else if seconds < 60 {
            return "\(Int(seconds)) seconds"
        } else if seconds < 3600 {
            return "\(Int(seconds / 60)) minutes"
        } else if seconds < 86400 {
            return "\(Int(seconds / 3600)) hours"
        } else if seconds < 31536000 {
            return "\(Int(seconds / 86400)) days"
        } else if seconds < 31536000 * 100 {
            return "\(Int(seconds / 31536000)) years"
        } else if seconds < 31536000 * 1000000 {
            return "\(Int(seconds / 31536000 / 1000)) centuries"
        } else {
            return "Forever"
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    GeneratorView()
        .environmentObject(VaultState.shared)
}
