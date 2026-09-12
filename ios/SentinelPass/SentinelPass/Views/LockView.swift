//
//  LockView.swift
//  SentinelPass
//
//  Vault lock/unlock screen
//
//  WBS-821/823: when a Keychain platform slot is enrolled, unlock goes
//  through KeychainSlot → sp_slot_open_with_dek. The biometric prompt is
//  raised BY the keychain item read (kSecAccessControlBiometryCurrentSet) —
//  the release IS the authorization; this screen only surfaces the result.
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct LockView: View {
    @EnvironmentObject private var vaultState: VaultState
    @State private var masterPassword: String = ""
    @State private var showingError: Bool = false
    @State private var errorMessage: String = ""
    @State private var isAuthenticating: Bool = false
    @State private var keychainSlotAvailable: Bool = false
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

                // Keychain-slot unlock (the OS prompts biometric/passcode
                // for the keychain item read itself).
                if keychainSlotAvailable {
                    Button {
                        unlockWithKeychainSlot()
                    } label: {
                        HStack {
                            Image(systemName: "faceid")
                            Text("Unlock with Keychain")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.ultraThinMaterial)
                        .clipShape(.capsule)
                    }
                    .disabled(isAuthenticating || vaultState.isLoading)
                    .padding(.horizontal)
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
                keychainSlotAvailable = vaultState.hasKeychainSlot()
                checkKeychainSlotAndAttempt()
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

    /// Offer the slot once at screen appearance: if a slot is enrolled,
    /// trigger the OS-gated read right away (matches the previous
    /// auto-attempt biometric behavior). A user refusal fails CLOSED and
    /// is silent — the master password field remains the fallback.
    private func checkKeychainSlotAndAttempt() {
        guard keychainSlotAvailable, !isAuthenticating else { return }
        Task {
            do {
                isAuthenticating = true
                try await vaultState.unlockWithKeychainSlot()
                isAuthenticating = false
            } catch let error as VaultError {
                isAuthenticating = false
                // Refused/cancelled gestures stay silent (fail closed);
                // real failures surface.
                if case .slotUnlockFailed(let message) = error,
                   message == KeychainSlot.slotUnavailableSentinel {
                    return
                }
                errorMessage = error.localizedDescription
                showingError = true
            } catch {
                isAuthenticating = false
            }
        }
    }

    private func unlockWithKeychainSlot() {
        isAuthenticating = true

        Task {
            do {
                try await vaultState.unlockWithKeychainSlot()
                isAuthenticating = false
            } catch {
                isAuthenticating = false
                errorMessage = error.localizedDescription
                showingError = true
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
