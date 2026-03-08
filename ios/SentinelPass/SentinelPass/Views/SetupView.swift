//
//  SetupView.swift
//  SentinelPass
//
//  Initial vault setup screen
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct SetupView: View {
    @EnvironmentObject private var vaultState: VaultState
    @State private var masterPassword: String = ""
    @State private var confirmPassword: String = ""
    @State private var showingError: Bool = false
    @State private var errorMessage: String = ""
    @State private var showPasswordStrength: Bool = false
    @State private var passwordStrength: PasswordAnalysis?
    @FocusState private var focusedField: Field?

    enum Field {
        case masterPassword, confirmPassword
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    Spacer()

                    // Logo
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 80))
                        .foregroundStyle(.linearGradient(
                            colors: [.blue, .purple],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ))

                    Text("Create Your Vault")
                        .font(.title)
                        .fontWeight(.bold)

                    Text("Choose a strong master password to protect your credentials")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)

                    VStack(spacing: 20) {
                        // Master Password Field
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Master Password")
                                .font(.headline)
                                .foregroundStyle(.secondary)

                            SecureField("Enter master password", text: $masterPassword)
                                .focused($focusedField, equals: .masterPassword)
                                .padding()
                                .background(.ultraThinMaterial)
                                .clipShape(.capsule)
                                .autocorrectionDisabled()
                                #if os(iOS)
                                .textInputAutocapitalization(.never)
                                #endif
                                .onChange(of: masterPassword) { _, _ in
                                    checkPasswordStrength()
                                }

                            // Password strength indicator
                            if showPasswordStrength, let strength = passwordStrength {
                                HStack(spacing: 8) {
                                    ForEach(0..<4) { i in
                                        Rectangle()
                                            .fill(i < strength.score ? strength.strengthColor : .gray.opacity(0.3))
                                            .frame(height: 4)
                                            .animation(.easeInOut, value: strength.score)
                                    }
                                    Text(strength.strengthDescription)
                                        .font(.caption)
                                        .foregroundStyle(strength.strengthColor)
                                }
                            }
                        }

                        // Confirm Password Field
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Confirm Password")
                                .font(.headline)
                                .foregroundStyle(.secondary)

                            SecureField("Confirm master password", text: $confirmPassword)
                                .focused($focusedField, equals: .confirmPassword)
                                .padding()
                                .background(.ultraThinMaterial)
                                .clipShape(.capsule)
                                .autocorrectionDisabled()
                                #if os(iOS)
                                .textInputAutocapitalization(.never)
                                #endif
                        }

                        // Password Requirements
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Requirements:")
                                .font(.caption)
                                .foregroundStyle(.secondary)

                            if let strength = passwordStrength {
                                HStack(spacing: 4) {
                                    Image(systemName: strength.length >= 12 ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(strength.length >= 12 ? .green : .gray)
                                    Text("At least 12 characters")
                                        .font(.caption)
                                }

                                HStack(spacing: 4) {
                                    Image(systemName: strength.hasUpper ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(strength.hasUpper ? .green : .gray)
                                    Text("Contains uppercase letter")
                                        .font(.caption)
                                }

                                HStack(spacing: 4) {
                                    Image(systemName: strength.hasLower ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(strength.hasLower ? .green : .gray)
                                    Text("Contains lowercase letter")
                                        .font(.caption)
                                }

                                HStack(spacing: 4) {
                                    Image(systemName: strength.hasDigit ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(strength.hasDigit ? .green : .gray)
                                    Text("Contains number")
                                        .font(.caption)
                                }

                                HStack(spacing: 4) {
                                    Image(systemName: strength.hasSymbol ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(strength.hasSymbol ? .green : .gray)
                                    Text("Contains symbol")
                                        .font(.caption)
                                }
                            }
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal)

                    // Create Button
                    Button {
                        createVault()
                    } label: {
                        if vaultState.isLoading {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .frame(maxWidth: .infinity)
                                .padding()
                                .background(.blue)
                                .foregroundStyle(.white)
                                .clipShape(.capsule)
                        } else {
                            Text("Create Vault")
                                .frame(maxWidth: .infinity)
                                .padding()
                                .background(isValidPassword ? .blue : .gray)
                                .foregroundStyle(.white)
                                .clipShape(.capsule)
                        }
                    }
                    .disabled(!isValidPassword || vaultState.isLoading)
                    .padding(.horizontal)

                    Spacer()
                }
                .padding()
            }
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(errorMessage)
            }
        }
    }

    private var isValidPassword: Bool {
        !masterPassword.isEmpty &&
        masterPassword == confirmPassword &&
        (passwordStrength?.score ?? 0) >= 3
    }

    private func checkPasswordStrength() {
        showPasswordStrength = !masterPassword.isEmpty

        Task {
            if !masterPassword.isEmpty {
                passwordStrength = await vaultState.checkPasswordStrength(password: masterPassword)
            }
        }
    }

    private func createVault() {
        focusedField = nil

        Task {
            do {
                try await vaultState.createVault(masterPassword: masterPassword)
                masterPassword = ""
                confirmPassword = ""
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    SetupView()
        .environmentObject(VaultState.shared)
}
