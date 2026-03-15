//
//  EntryModel.swift
//  SentinelPass
//
//  Data models for password entries
//

import Foundation
import SwiftData
import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
@Model
final class EntryModel {
    var id: String
    var title: String
    var username: String
    var password: String?
    var url: String?
    var notes: String?
    var favorite: Bool
    var createdAt: Date?
    var modifiedAt: Date?

    init(
        id: String,
        title: String,
        username: String,
        password: String? = nil,
        url: String? = nil,
        notes: String? = nil,
        favorite: Bool = false,
        createdAt: Date? = nil,
        modifiedAt: Date? = nil
    ) {
        self.id = id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
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
