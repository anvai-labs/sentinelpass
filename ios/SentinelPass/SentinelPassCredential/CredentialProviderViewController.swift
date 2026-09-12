//
//  CredentialProviderViewController.swift
//  SentinelPassCredential
//
//  WBS-825: iOS 17 credential-provider extension
//  (NSExtensionPointIdentifier com.apple.authentication-services.credential-provider-ui).
//
//  Minimal REAL flow:
//   - The extension is a separate PROCESS: it cannot see the app's
//     in-memory unlocked vault. It opens the vault itself, through its own
//     VaultBridge, against the SAME database file under the
//     `group.com.sentinelpass` App Group container (Services/VaultFile.swift
//     is compiled into this target for the shared path resolution).
//   - Until the vault is open the UI asks for the master password.
//   - Entries are filtered against the host app's service identifier
//     (URL host or domain) but the full list stays reachable so the user
//     can pick any entry.
//   - Completion hands an ASPasswordCredential back to the host via
//     completeRequest(withSelectedCredential:); cancellation uses
//     cancelRequest(with: ASExtensionError(.userCanceled)).
//
//  Keychain access-group sharing is deliberately NOT required for this
//  minimal version: the extension holds no secrets at rest of its own and
//  reads no keychain items.
//

import UIKit
import SwiftUI
import AuthenticationServices

@available(iOS 17.0, *)
@MainActor
final class CredentialViewModel: ObservableObject {
    @Published var isUnlocked = false
    @Published var isLoading = false
    @Published var masterPassword = ""
    @Published var entries: [EntryModel] = []
    @Published var showingError = false
    @Published var errorMessage: String?

    /// Weak back-reference so the view model can complete the host
    /// request through the principal view controller's extensionContext.
    private weak var provider: ASCredentialProviderViewController?

    private let bridge = VaultBridge()

    func attach(provider: ASCredentialProviderViewController) {
        self.provider = provider
    }

    func unlock() {
        guard !masterPassword.isEmpty else { return }
        isLoading = true
        errorMessage = nil
        Task {
            defer { isLoading = false }
            let path = VaultFile.vaultURL.path
            let password = masterPassword
            let success = await bridge.unlockVault(vaultPath: path, masterPassword: password)
            if success {
                isUnlocked = true
                masterPassword = ""
                loadEntries()
            } else {
                errorMessage = "Invalid master password"
                showingError = true
            }
        }
    }

    func loadEntries() {
        Task {
            let summaries = await bridge.listEntries()
            entries = summaries.map {
                EntryModel(id: $0.id, title: $0.title, username: $0.username, favorite: $0.favorite)
            }
        }
    }

    /// Fetch the full entry and complete the host request with it.
    func complete(entryId: String) {
        Task {
            guard let provider = provider else { return }
            guard let details = await bridge.getEntry(id: entryId) else {
                errorMessage = "Could not read the selected entry"
                showingError = true
                return
            }
            let credential = ASPasswordCredential(user: details.username, password: details.password)
            // The typed extensionContext (non-optional on
            // ASCredentialProviderViewController) completes the host request.
            provider.extensionContext.completeRequest(
                withSelectedCredential: credential,
                completionHandler: nil
            )
        }
    }
}

@available(iOS 17.0, *)
struct CredentialPickerView: View {
    @ObservedObject var model: CredentialViewModel
    let serviceIdentifiers: [ASCredentialServiceIdentifier]
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            Group {
                if model.isUnlocked {
                    entryList
                } else {
                    unlockPrompt
                }
            }
            .navigationTitle(title)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                }
            }
            .alert("Error", isPresented: $model.showingError) {
                Button("OK", role: .cancel) { model.errorMessage = nil }
            } message: {
                Text(model.errorMessage ?? "")
            }
        }
    }

    private var title: String {
        serviceIdentifierHost ?? "SentinelPass"
    }

    private var unlockPrompt: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(.linearGradient(
                    colors: [.blue, .purple],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ))

            Text("Open SentinelPass to unlock")
                .font(.headline)
            Text("The credential provider needs the vault unlocked to offer passwords for \(title).")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("Master password", text: $model.masterPassword)
                .textFieldStyle(.roundedBorder)
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
                .autocorrectionDisabled()
                .onSubmit { model.unlock() }

            if model.isLoading {
                ProgressView()
            } else {
                Button("Unlock") { model.unlock() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.masterPassword.isEmpty)
            }
        }
        .padding()
    }

    private var entryList: some View {
        List {
            if !matchedEntries.isEmpty {
                Section("For \(title)") {
                    ForEach(matchedEntries) { entry in
                        row(entry)
                    }
                }
            }
            Section("All Entries") {
                if model.entries.isEmpty {
                    Text("No entries in the vault")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.entries) { entry in
                        row(entry)
                    }
                }
            }
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        #endif
    }

    private func row(_ entry: EntryModel) -> some View {
        Button {
            model.complete(entryId: entry.id)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title).font(.headline)
                Text(entry.username).font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }

    private var matchedEntries: [EntryModel] {
        guard let host = serviceIdentifierHost else { return [] }
        return model.entries.filter { entry in
            entry.title.localizedCaseInsensitiveContains(host) ||
            host.localizedCaseInsensitiveContains(entry.title)
        }
    }

    /// Host app identity: URL identifiers contribute their host, domain
    /// identifiers the domain itself. Unusable identifiers return nil and
    /// the full list is shown. (if/else instead of switch: the IdentifierType
    /// enum gained a case after our deployment target — no exhaustiveness
    /// fuss across SDK versions.)
    private var serviceIdentifierHost: String? {
        for identifier in serviceIdentifiers {
            if identifier.type == .URL {
                if let url = URL(string: identifier.identifier), let host = url.host, !host.isEmpty {
                    return host
                }
            } else if identifier.type == .domain {
                return identifier.identifier
            }
        }
        return nil
    }
}

@available(iOS 17.0, *)
class CredentialProviderViewController: ASCredentialProviderViewController {

    @MainActor private let model = CredentialViewModel()
    private var hostingController: UIHostingController<CredentialPickerView>?

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        installUI(serviceIdentifiers: serviceIdentifiers)
    }

    /// Shown when the user enables SentinelPass in Settings → Passwords →
    /// Password Options. The extension has nothing to configure; present
    /// the standard picker so the user sees a working surface.
    override func prepareInterfaceForExtensionConfiguration() {
        installUI(serviceIdentifiers: [])
    }

    @MainActor
    private func installUI(serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.attach(provider: self)

        let picker = CredentialPickerView(
            model: model,
            serviceIdentifiers: serviceIdentifiers,
            onCancel: { [weak self] in
                self?.cancel()
            }
        )
        let controller = UIHostingController(rootView: picker)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        addChild(controller)
        view.addSubview(controller.view)
        NSLayoutConstraint.activate([
            controller.view.topAnchor.constraint(equalTo: view.topAnchor),
            controller.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            controller.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        controller.didMove(toParent: self)
        hostingController = controller
    }

    private func cancel() {
        extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
    }
}
