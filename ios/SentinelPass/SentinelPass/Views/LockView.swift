//
//  LockView.swift
//  SentinelPass
//
//  Vault lock/unlock screen
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct LockView: View {
    @EnvironmentObject private var vaultState: VaultState
    @EnvironmentObject private var biometricAuth: BiometricAuth
    @State private var masterPassword: String = ""
    @State private var showingError: Bool = false
    @State private var errorMessage: String = ""
    @State private var isAuthenticating: Bool = false
    @FocusState private var isPasswordFieldFocused: Bool

    var body: some View {
        NavigationStack {
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

                Text("SentinelPass")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Secure Password Manager")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Spacer()

                // Biometric Button
                if biometricAuth.isAvailable {
                    Button {
                        authenticateWithBiometric()
                    } label: {
                        HStack {
                            Image(systemName: biometricAuth.biometricType == .faceID ? "face.id" : "touchid")
                            Text("Unlock with \(biometricAuth.biometricType == .faceID ? "Face ID" : "Touch ID")")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.ultraThinMaterial)
                        .clipShape(.capsule)
                    }
                    .disabled(isAuthenticating)
                }

                // Password Field
                VStack(alignment: .leading, spacing: 8) {
                    Text("Master Password")
                        .font(.headline)
                        .foregroundStyle(.secondary)

                    SecureField("Enter master password", text: $masterPassword)
                        .focused($isPasswordFieldFocused)
                        .padding()
                        .background(.ultraThinMaterial)
                        .clipShape(.capsule)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                        .onSubmit {
                            unlockVault()
                        }
                }
                .padding(.horizontal)

                // Unlock Button
                Button {
                    unlockVault()
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
                        Text("Unlock Vault")
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(.blue)
                            .foregroundStyle(.white)
                            .clipShape(.capsule)
                    }
                }
                .disabled(masterPassword.isEmpty || vaultState.isLoading)
                .padding(.horizontal)

                Spacer()
            }
            .padding()
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(errorMessage)
            }
            .onAppear {
                checkBiometricAndAttempt()
            }
        }
    }

    private func unlockVault() {
        isPasswordFieldFocused = false
        isAuthenticating = true

        Task {
            do {
                try await vaultState.unlockVault(masterPassword: masterPassword)
                isAuthenticating = false
                masterPassword = ""
            } catch {
                isAuthenticating = false
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }

    private func checkBiometricAndAttempt() {
        Task {
            let hasBiometric = await vaultState.hasBiometricKey()
            if hasBiometric && biometricAuth.isAvailable {
                // Attempt biometric unlock automatically
                authenticateWithBiometric()
            }
        }
    }

    private func authenticateWithBiometric() {
        isAuthenticating = true

        Task {
            let authenticated = await biometricAuth.authenticate()
            if authenticated {
                do {
                    try await vaultState.unlockWithBiometric()
                    isAuthenticating = false
                } catch {
                    isAuthenticating = false
                    errorMessage = "Biometric unlock failed. Please use master password."
                    showingError = true
                }
            } else {
                isAuthenticating = false
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    LockView()
        .environmentObject(VaultState.shared)
        .environmentObject(BiometricAuth())
}
