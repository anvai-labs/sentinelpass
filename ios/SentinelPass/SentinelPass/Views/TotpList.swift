//
//  TotpList.swift
//  SentinelPass
//
//  TOTP code list with auto-refresh
//

import SwiftUI
import Combine

@available(iOS 17.0, macOS 14.0, *)
struct TotpList: View {
    @EnvironmentObject private var vaultState: VaultState
    @State private var totpCodes: [String: TotpCode] = [:]
    @State private var timer: Timer?
    @State private var currentSecond: Int = 0

    var body: some View {
        NavigationStack {
            Group {
                if totpEntries.isEmpty {
                    emptyState
                } else {
                    listContent
                }
            }
            .navigationTitle("TOTP")
            .onAppear {
                startTimer()
                loadTotpCodes()
            }
            .onDisappear {
                stopTimer()
            }
            .refreshable {
                loadTotpCodes()
            }
        }
    }

    private var totpEntries: [EntryModel] {
        vaultState.entries.filter { entry in
            // Filter entries that likely have TOTP (could add metadata later)
            // For now, we'll load TOTP for all entries and show those that succeed
            totpCodes[entry.id] != nil
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No TOTP Codes", systemImage: "clock")
        } description: {
            Text("Add entries with TOTP secrets to generate verification codes")
        }
    }

    private var listContent: some View {
        List {
            ForEach(vaultState.entries) { entry in
                if let totp = totpCodes[entry.id] {
                    TotpRow(entry: entry, totp: totp, progress: progressForCode(totp))
                        .id(entry.id)
                }
            }
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        #endif
    }

    private func progressForCode(_ totp: TotpCode) -> Double {
        Double(totp.secondsRemaining) / 30.0
    }

    private func startTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            currentSecond = (currentSecond + 1) % 30
            if currentSecond == 0 {
                loadTotpCodes()
            }
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
    }

    private func loadTotpCodes() {
        Task {
            for entry in vaultState.entries {
                if let totp = try? await vaultState.generateTotp(entryId: entry.id) {
                    await MainActor.run {
                        totpCodes[entry.id] = totp
                    }
                }
            }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
struct TotpRow: View {
    let entry: EntryModel
    let totp: TotpCode
    let progress: Double

    @State private var copied: Bool = false

    var body: some View {
        Button {
            copyCode()
        } label: {
            HStack(spacing: 16) {
                Image(systemName: "clock.fill")
                    .font(.title2)
                    .foregroundStyle(.orange)
                    .frame(width: 40, height: 40)
                    .background(.orange.opacity(0.1))
                    .clipShape(.circle)

                VStack(alignment: .leading, spacing: 4) {
                    Text(entry.title)
                        .font(.headline)

                    Text(entry.username)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 4) {
                    Text(codeDisplay)
                        .font(.system(.title2, design: .rounded))
                        .fontWeight(.semibold)
                        .monospacedDigit()

                    ZStack(alignment: .leading) {
                        GeometryReader { geometry in
                            Rectangle()
                                .fill(.gray.opacity(0.2))
                            Rectangle()
                                .fill(colorForSeconds(totp.secondsRemaining))
                                .frame(width: geometry.size.width * progress)
                        }
                        .frame(height: 4)
                        .clipShape(.capsule)
                    }

                    Text("\(totp.secondsRemaining)s")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
            .overlay(alignment: .top) {
                if copied {
                    HStack {
                        Spacer()
                        Text("Copied!")
                            .font(.caption)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(.black)
                            .foregroundStyle(.white)
                            .clipShape(.capsule)
                        Spacer()
                    }
                    .offset(y: -20)
                }
            }
        }
        .buttonStyle(.plain)
    }

    private var codeDisplay: String {
        let code = totp.code
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }

    private func colorForSeconds(_ seconds: UInt32) -> Color {
        switch seconds {
        case 0...5: return .red
        case 6...10: return .orange
        default: return .green
        }
    }

    private func copyCode() {
        #if os(iOS)
        UIPasteboard.general.string = totp.code
        #endif

        copied = true

        Task {
            try? await Task.sleep(for: .seconds(1))
            copied = false
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    NavigationStack {
        TotpList()
            .environmentObject(VaultState.shared)
    }
}
