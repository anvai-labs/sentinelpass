# macOS release resource seal

Local inspection of the published 0.13.1 DMG found that its main executable
had a linker-generated ad-hoc signature, but the app had no resource seal.
`codesign --verify --deep --strict` rejected it with “code has no resources
but signature indicates they must be present”. Its download checksum,
bundle identity, version, architecture and bundled helpers were correct.
The cask update and local installation were withheld.

Version 0.13.2 sets Tauri's macOS signing identity to `-`, so the bundler
seals the complete app before creating the DMG. The release workflow mounts
the final image read-only and verifies its version, identity, architecture,
both helpers and strict code signature. Regression checks reject changed
Info.plist data, injected resources, modified or missing helpers, a missing
resource seal and a mismatched release version. The verifier first failed
against the published 0.13.1 artifact before the packaging fix.
The local 0.13.2 Tauri build passes the verifier both before packaging and
inside the read-only mounted DMG; all six negative checks reject their
tampered or mismatched inputs.

The Developer ID path now submits the signed app for notarization before
attempting to staple its ticket. It requires an Accepted result, rebuilds
the DMG from the stapled app, and signs, submits and staples that image.
This authenticated signing path still requires upstream Apple credentials;
ad-hoc signing does not establish publisher identity or satisfy Gatekeeper
notarization. No quarantine or Gatekeeper policy is disabled by this fix.

Checksum generation also excludes the manifest itself and immediately
checks every listed file. A manifest cannot contain a valid checksum of
its own final contents using the previous generation procedure.

References: [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/)
and [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
