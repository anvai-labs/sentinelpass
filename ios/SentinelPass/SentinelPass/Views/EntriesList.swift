//
//  EntriesList.swift
//  SentinelPass
//
//  List of password entries
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct EntriesList: View {
    @EnvironmentObject private var vaultState: VaultState
    @State private var searchText = ""
    @State private var showingAddEntry = false
    @State private var showingEntryDetail: EntryModel?
    @State private var filteredEntries: [EntryModel] = []

    var body: some View {
        NavigationStack {
            Group {
                if vaultState.entries.isEmpty && searchText.isEmpty {
                    emptyState
                } else {
                    listContent
                }
            }
            .navigationTitle("Passwords")
            .searchable(text: $searchText, prompt: "Search entries...")
            .onChange(of: searchText) { _, newValue in
                filterEntries()
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showingAddEntry = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingAddEntry) {
                AddEntryView()
            }
            .sheet(item: $showingEntryDetail) { entry in
                EntryDetailView(entry: entry)
            }
            .refreshable {
                await vaultState.loadEntries()
                filterEntries()
            }
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Passwords", systemImage: "key")
        } description: {
            Text("Tap the + button to add your first password entry")
        } actions: {
            Button("Add Entry") {
                showingAddEntry = true
            }
        }
    }

    private var listContent: some View {
        List {
            ForEach(sortedEntries) { entry in
                Button {
                    // Load full entry details
                    Task {
                        if let detail = try? await vaultState.getEntry(id: entry.id) {
                            showingEntryDetail = detail
                        }
                    }
                } label: {
                    EntryRow(entry: entry)
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    Button(role: .destructive) {
                        Task {
                            try? await vaultState.deleteEntry(id: entry.id)
                            filterEntries()
                        }
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private var sortedEntries: [EntryModel] {
        (searchText.isEmpty ? vaultState.entries : filteredEntries).sorted { a, b in
            if a.favorite != b.favorite {
                return a.favorite && !b.favorite
            }
            return a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
        }
    }

    private func filterEntries() {
        if searchText.isEmpty {
            filteredEntries = vaultState.entries
        } else {
            Task {
                filteredEntries = await vaultState.searchEntries(query: searchText)
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
struct EntryRow: View {
    let entry: EntryModel

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: iconForTitle(entry.title))
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(width: 40, height: 40)
                .background(.blue.opacity(0.1))
                .clipShape(.circle)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(entry.title)
                        .font(.headline)

                    if entry.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                    }
                }

                Text(entry.username)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }

    private func iconForTitle(_ title: String) -> String {
        let lowercased = title.lowercased()

        if lowercased.contains("google") { return "globe" }
        if lowercased.contains("github") { return "figure.martial.arts" }
        if lowercased.contains("amazon") { return "cart" }
        if lowercased.contains("facebook") { return "person.2.fill" }
        if lowercased.contains("twitter") || lowercased.contains("x.com") { return "bubble" }
        if lowercased.contains("netflix") { return "play.tv.fill" }
        if lowercased.contains("spotify") { return "music.note" }
        if lowercased.contains("bank") || lowercased.contains("finance") { return "building.columns.fill" }
        if lowercased.contains("email") || lowercased.contains("mail") { return "envelope.fill" }

        return "key.fill"
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    NavigationStack {
        EntriesList()
            .environmentObject(VaultState.shared)
    }
}
