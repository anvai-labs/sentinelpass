//
//  SentinelPassApp.swift
//  SentinelPass
//
//  iOS Password Manager using SentinelPass Mobile Bridge
//

import SwiftUI
import SwiftData

@available(iOS 17.0, macOS 14.0, *)
@main
struct SentinelPassApp: App {
    @StateObject private var vaultState = VaultState.shared
    @StateObject private var biometricAuth = BiometricAuth()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vaultState)
                .environmentObject(biometricAuth)
                .onAppear {
                    setupAppearance()
                }
        }
        .modelContainer(for: [EntryModel.self])
    }

    private func setupAppearance() {
        #if os(iOS)
        // Configure app appearance
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor.systemBackground

        UINavigationBar.appearance().standardAppearance = appearance
        UINavigationBar.appearance().scrollEdgeAppearance = appearance
        #endif
    }
}
