//
//  EntryDetailView.swift
//  SentinelPass
//
//  Detailed view of a password entry
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct EntryDetailView: View {
    @EnvironmentObject private var vaultState: VaultState
    @Environment(\.dismiss) private var dismiss

    /// Full bridge detail — in memory only, never persisted Swift-side
    /// (WBS-826 removed the plaintext SwiftData mirror).
    let entry: EntryDetails
    @State private var showPassword: Bool = false
    @State private var copiedField: String?
    @State private var showingEdit: Bool = false

    var body: some View {
        NavigationStack {
            List {
                // Title and Favorite
                Section {
                    HStack {
                        Text("Title")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.title)
                            .foregroundStyle(.primary)
                        if entry.favorite {
                            Image(systemName: "star.fill")
                                .foregroundStyle(.yellow)
                        }
                    }

                    HStack {
                        Text("Username")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.username)
                    }
                } header: {
                    Text("Account")
                }

                // Password
                Section {
                    HStack {
                        Text("Password")
                            .foregroundStyle(.secondary)
                        Spacer()

                        if showPassword {
                            Text(entry.password)
                                .font(.body.monospaced())
                        } else {
                            Text("••••••••")
                                .foregroundStyle(.secondary)
                        }

                        Button {
                            showPassword.toggle()
                        } label: {
                            Image(systemName: showPassword ? "eye.slash.fill" : "eye.fill")
                                .foregroundStyle(.secondary)
                        }

                        Button {
                            copyToClipboard(entry.password, field: "Password")
                        } label: {
                            Image(systemName: "doc.on.doc")
                                .foregroundStyle(.blue)
                        }
                    }
                } header: {
                    Text("Password")
                }

                // URL
                if let url = entry.url, !url.isEmpty {
                    Section {
                        HStack {
                            Text("Website")
                                .foregroundStyle(.secondary)
                            Spacer()
                            if let linkUrl = URL(string: url) {
                                Link(destination: linkUrl) {
                                    Text(url)
                                        .lineLimit(1)
                                }
                            } else {
                                Text(url)
                                    .foregroundStyle(.secondary)
                            }
                            Button {
                                copyToClipboard(url, field: "URL")
                            } label: {
                                Image(systemName: "doc.on.doc")
                                    .foregroundStyle(.blue)
                            }
                        }
                    } header: {
                        Text("Website")
                    }
                }

                // Notes
                if let notes = entry.notes, !notes.isEmpty {
                    Section {
                        Text(notes)
                    } header: {
                        Text("Notes")
                    }
                }

                // Metadata
                Section {
                    HStack {
                        Text("Created")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.createdAt, style: .date)
                    }

                    HStack {
                        Text("Modified")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.modifiedAt, style: .date)
                    }
                } header: {
                    Text("Metadata")
                }

                // Actions
                Section {
                    Button {
                        showingEdit = true
                    } label: {
                        Label("Edit Entry", systemImage: "pencil")
                    }

                    Button(role: .destructive) {
                        deleteEntry()
                    } label: {
                        Label("Delete Entry", systemImage: "trash")
                    }
                }
            }
            .navigationTitle(entry.title)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .overlay(alignment: .top) {
                if let copiedField = copiedField {
                    Text("\(copiedField) copied!")
                        .font(.caption)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(.black)
                        .foregroundStyle(.white)
                        .clipShape(.capsule)
                        .padding(.top, 8)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .sheet(isPresented: $showingEdit) {
                EditEntryView(entry: entry)
            }
        }
    }

    private func copyToClipboard(_ value: String?, field: String) {
        guard let value = value else { return }

        // WBS-824: local expiring paste (30 s) — never a permanent write.
        Pasteboard.copySensitive(value)

        withAnimation {
            self.copiedField = field
        }

        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation {
                self.copiedField = nil
            }
        }
    }

    private func deleteEntry() {
        Task {
            try? await vaultState.deleteEntry(id: entry.id)
            dismiss()
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    EntryDetailView(entry: EntryDetails(
        id: "1",
        title: "Example",
        username: "user@example.com",
        password: "password123",
        url: "https://example.com",
        notes: "Test notes",
        favorite: false,
        createdAt: Date(),
        modifiedAt: Date()
    ))
    .environmentObject(VaultState.shared)
}
