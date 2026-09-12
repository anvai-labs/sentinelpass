//
//  SentinelPassApp.swift
//  SentinelPass
//
//  iOS Password Manager using SentinelPass Mobile Bridge
//
//  WBS-823: a privacy cover shields the UI whenever the scene is not
//  active, and the auto-lock timer (5 minutes) runs while backgrounded —
//  returning after the deadline locks the vault.
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
@main
struct SentinelPassApp: App {

    /// WBS-823: vault auto-lock deadline while the scene is not active.
    /// Matches the desktop daemon default (5 minutes).
    private static let autoLockInterval: TimeInterval = 5 * 60

    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var vaultState = VaultState.shared
    @StateObject private var biometricAuth = BiometricAuth()
    @State private var backgroundedAt: Date?

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(vaultState)
                    .environmentObject(biometricAuth)
                    .onAppear {
                        setupAppearance()
                    }

                // Privacy cover: hides vault contents in the app switcher
                // snapshot and while inactive.
                if scenePhase != .active {
                    PrivacyCoverView()
                        .transition(.opacity)
                        .zIndex(10)
                }
            }
            .animation(.easeOut(duration: 0.15), value: scenePhase)
            .onChange(of: scenePhase) { _, newPhase in
                handleScenePhase(newPhase)
            }
        }
    }

    private func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .background, .inactive:
            // Start (or restart) the auto-lock window.
            if backgroundedAt == nil {
                backgroundedAt = Date()
            }
        case .active:
            if let backgrounded = backgroundedAt {
                backgroundedAt = nil
                if Date().timeIntervalSince(backgrounded) >= Self.autoLockInterval {
                    vaultState.lockVault()
                }
            }
        @unknown default:
            break
        }
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

/// Full-screen shield shown whenever the scene is not active (WBS-823).
/// The ultra-thin material blurs whatever is beneath so entry lists,
/// passwords and TOTP codes never appear in the app-switcher snapshot.
@available(iOS 17.0, macOS 14.0, *)
struct PrivacyCoverView: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()

            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.linearGradient(
                        colors: [.blue, .purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                Text("SentinelPass")
                    .font(.title2)
                    .fontWeight(.semibold)
            }
        }
    }
}
