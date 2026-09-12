//
//  EntryModel.swift
//  SentinelPass
//
//  UI list models for password entries.
//
//  WBS-826: the SwiftData @Model (which carried a PLAINTEXT `password`
//  column and wired a model container nothing wrote through honestly) is
//  REMOVED. The vault IS the Rust SQLite database; the Swift layer keeps
//  only a non-sensitive list MIRROR of what the bridge returns in
//  `SPEntrySummary`. Full entry data (password/url/notes) flows through
//  `EntryDetails` (Services/VaultBridge.swift), in memory only, never
//  persisted by Swift.
//

import Foundation
import SwiftUI

/// Non-sensitive list-row mirror of a bridge `SPEntrySummary`.
@available(iOS 17.0, macOS 14.0, *)
struct EntryModel: Identifiable {
    let id: String
    let title: String
    let username: String
    let favorite: Bool
    let createdAt: Date?
    let modifiedAt: Date?

    init(
        id: String,
        title: String,
        username: String,
        favorite: Bool = false,
        createdAt: Date? = nil,
        modifiedAt: Date? = nil
    ) {
        self.id = id
        self.title = title
        self.username = username
        self.favorite = favorite
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
    }
}

// MARK: - Supporting Types

@available(iOS 17.0, macOS 14.0, *)
struct TotpCode {
    let code: String
    let secondsRemaining: UInt32
}

@available(iOS 17.0, macOS 14.0, *)
struct PasswordAnalysis {
    let score: Int
    let entropyBits: Double
    let crackTimeSeconds: Double
    let length: Int
    let hasLower: Bool
    let hasUpper: Bool
    let hasDigit: Bool
    let hasSymbol: Bool

    var strengthDescription: String {
        switch score {
        case 0...1: return "Very Weak"
        case 2: return "Weak"
        case 3: return "Fair"
        case 4: return "Strong"
        default: return "Very Strong"
        }
    }

    var strengthColor: Color {
        switch score {
        case 0...1: return .red
        case 2: return .orange
        case 3: return .yellow
        case 4: return .green
        default: return .green
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
struct EntrySummary {
    let id: String
    let title: String
    let username: String
    let favorite: Bool
}
