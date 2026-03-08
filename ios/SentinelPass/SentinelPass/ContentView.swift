//
//  ContentView.swift
//  SentinelPass
//
//  Main view controller
//

import SwiftUI

@available(iOS 17.0, macOS 14.0, *)
struct ContentView: View {
    @EnvironmentObject private var vaultState: VaultState
    @EnvironmentObject private var biometricAuth: BiometricAuth
    @State private var showingSetup = false

    var body: some View {
        Group {
            if vaultState.isUnlocked {
                MainTabView()
            } else if vaultState.hasVault {
                LockView()
            } else {
                SetupView()
            }
        }
        .sheet(isPresented: $showingSetup) {
            SetupView()
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
struct MainTabView: View {
    @EnvironmentObject private var vaultState: VaultState

    var body: some View {
        TabView {
            EntriesList()
                .tabItem {
                    Label("Passwords", systemImage: "key.fill")
                }

            TotpList()
                .tabItem {
                    Label("TOTP", systemImage: "clock.fill")
                }

            GeneratorView()
                .tabItem {
                    Label("Generate", systemImage: "dice.fill")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape.fill")
                }
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
#Preview {
    ContentView()
        .environmentObject(VaultState.shared)
        .environmentObject(BiometricAuth())
}
