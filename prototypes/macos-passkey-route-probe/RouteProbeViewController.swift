import AuthenticationServices
import Foundation
import OSLog

// Use only as the principal class of an isolated feasibility extension.
// The probe cancels every request and never reads or returns credential data.
@available(macOS 14.0, *)
final class RouteProbeViewController: ASCredentialProviderViewController {
    private let logger = Logger(subsystem: "com.sentinelpass.route-probe", category: "routing")

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        if registrationRequest is ASPasskeyCredentialRequest {
            logger.notice("registration_callback_observed")
        }
        cancel()
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        // Request interactive routing for passkey requests without inspecting
        // the identity or implying that an actual credential can be supplied.
        cancel(credentialRequest is ASPasskeyCredentialRequest ? .userInteractionRequired : .failed)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if credentialRequest is ASPasskeyCredentialRequest {
            logger.notice("assertion_callback_observed")
        }
        cancel()
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        cancel()
    }

    private func cancel(_ code: ASExtensionError.Code = .failed) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }
}
