# macOS passkey registration route probe

`RouteProbeViewController.swift` is the principal class for a disposable macOS Credential Provider Extension. It logs fixed callback markers and cancels each request. It holds no vault state or passkeys.

1. Create a disposable macOS containing app and Credential Provider Extension in Xcode with unique bundle identifiers, and set the deployment target to macOS 14 or later. Replace the extension's template controller with this file. Set `NSExtensionPrincipalClass` to `$(PRODUCT_MODULE_NAME).RouteProbeViewController` for the `com.apple.authentication-services.credential-provider-ui` extension point.
2. Enable Apple's AutoFill Credential Provider capability on both targets. Set `ProvidesPasskeys` to true in the app and extension credential provider capabilities, following Apple's [registration API documentation](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller/prepareinterface%28forpasskeyregistration%3A%29). Check the final signed files for the entitlement and effective plist settings. Use a distinct display name such as SentinelPass Route Probe to keep it separate from the installed product.
3. Enable the disposable provider in macOS settings. From an isolated browser profile and an authorized disposable HTTPS RP, start an explicit registration and select the probe. Look for `registration_callback_observed` in the unified log under subsystem `com.sentinelpass.route-probe` and category `routing`. The provider cancels the ceremony. Repeat in Safari and Chrome and record the results separately. Remove the probe and disable its provider entry afterward.

The controller marks interactive assertion routing if the OS supplies an assertion request. A callback may require a credential identity already registered by a usable provider, which this probe does not create. If that precondition prevents testing, mark assertion as pending and defer it to the custody prototype. A callback marker only proves delivery to the extension. Successful registration, assertion and physical Touch ID qualification require the later workcard's separate checks.

To check the source against the installed macOS SDK without signing or installing it:

```sh
xcrun --sdk macosx swiftc -typecheck -warnings-as-errors \
  -target arm64-apple-macosx14.0 \
  prototypes/macos-passkey-route-probe/RouteProbeViewController.swift
```
