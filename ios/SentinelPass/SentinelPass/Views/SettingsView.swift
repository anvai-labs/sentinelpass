//
//  SettingsView.swift
//  SentinelPass
//
//  Settings and preferences
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct SettingsView: View {
    @EnvironmentObject private var vaultState: VaultState
    @EnvironmentObject private var biometricAuth: BiometricAuth
    @State private var showingConfirmDeleteVault = false
    @State private var showingExportOptions = false

    var body: some View {
        NavigationStack {
            List {
                // Security Section
                Section {
                    if biometricAuth.isAvailable {
                        Toggle("Biometric Unlock", isOn: $biometricEnabled)
                            .onChange(of: biometricEnabled) { _, newValue in
                                Task {
                                    if newValue {
                                        try? await vaultState.enableBiometric()
                                    } else {
                                        try? await vaultState.disableBiometric()
                                    }
                                }
                            }
                    }

                    Button {
                        lockVault()
                    } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                    .foregroundStyle(.blue)
                } header: {
                    Text("Security")
                } footer: {
                    Text("Locking the vault requires your master password or biometric authentication to unlock again.")
                }

                // Data Section
                Section {
                    Button {
                        showingExportOptions = true
                    } label: {
                        Label("Export Data", systemImage: "square.and.arrow.up")
                    }

                    Button {
                        // Import functionality
                    } label: {
                        Label("Import Data", systemImage: "square.and.arrow.down")
                    }
                } header: {
                    Text("Data Management")
                }

                // About Section
                Section {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown")
                            .foregroundStyle(.secondary)
                    }

                    Link(destination: URL(string: "https://github.com/anvai-labs/sentinelpass")!) {
                        HStack {
                            Text("GitHub Repository")
                            Spacer()
                            Image(systemName: "link")
                                .foregroundStyle(.secondary)
                        }
                    }

                    Link(destination: URL(string: "https://sentinelpass.io/docs")!) {
                        HStack {
                            Text("Documentation")
                            Spacer()
                            Image(systemName: "book")
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("About")
                }

                // Danger Zone
                Section {
                    Button(role: .destructive) {
                        showingConfirmDeleteVault = true
                    } label: {
                        Label("Delete Vault", systemImage: "trash")
                    }
                } header: {
                    Text("Danger Zone")
                } footer: {
                    Text("Deleting your vault is permanent and cannot be undone. Make sure you have a backup before proceeding.")
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog("Delete Vault", isPresented: $showingConfirmDeleteVault, titleVisibility: .visible) {
                Button("Delete Vault", role: .destructive) {
                    deleteVault()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("Are you sure you want to delete your vault? This action cannot be undone.")
            }
            .sheet(isPresented: $showingExportOptions) {
                ExportOptionsView()
            }
        }
    }

    @State private var biometricEnabled = false

    private func lockVault() {
        vaultState.lockVault()
    }

    private func deleteVault() {
        // Implementation would delete the vault file
        // For now, just lock
        vaultState.lockVault()
    }
}

@available(iOS 17.0, macOS 14.0, *)
struct ExportOptionsView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Button {
                    exportAsJson()
                } label: {
                    Label("Export as JSON", systemImage: "doc.text")
                }

                Button {
                    exportAsCsv()
                } label: {
                    Label("Export as CSV", systemImage: "tablecells")
                }

                Button {
                    exportEncrypted()
                } label: {
                    Label("Export Encrypted Backup", systemImage: "lock.doc")
                }
            }
            .navigationTitle("Export Data")
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
        }
    }

    private func exportAsJson() {
        // TODO: Implement JSON export
        dismiss()
    }

    private func exportAsCsv() {
        // TODO: Implement CSV export
        dismiss()
    }

    private func exportEncrypted() {
        // TODO: Implement encrypted backup
        dismiss()
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    SettingsView()
        .environmentObject(VaultState.shared)
        .environmentObject(BiometricAuth())
}
