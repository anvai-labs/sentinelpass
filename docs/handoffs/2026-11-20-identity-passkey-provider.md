# SentinelPass handoff: usable passkeys and credential-save authorization

Date: 2026-11-20. Requested by the owner during Anvai Identity dev validation.
Status: incoming product/design work; no provider implementation or platform
qualification is claimed. Target SentinelPass integration branch: develop.

## Observed gap

The installed SentinelPass 0.20.0 CLI describes `passkey` as metadata-only
references. SentinelPass `docs/PASSKEY_PRODUCT_DESIGN.md` likewise separates
references from future platform handoff and credential-provider evaluation.
The owner expected to create/store a usable passkey in SentinelPass, then sign
in to Identity and approve an exact reviewed action with the Mac Touch ID sensor.
Current reference storage does not supply that credential or ceremony.

The verified Identity dev password was saved by the owner through `entry add`.
An unlocked daemon still required fresh master-password authorization for this
change. Agent guidance must hand that prompt to the human; repeated import or
IPC attempts are not an alternative authorization mechanism. No secret values,
private browser/profile state, credential identifiers or biometrics are included.

## Requested product outcome

Provide usable passkey enrollment and authentication from supported browser/app
flows, with discoverable account selection, clear provider/custody attribution,
platform user verification, lifecycle management and truthful supported-platform
copy. Merely adding a reference does not meet this request. Full provider support
needs an explicit architecture decision before implementation, as the existing
design requires. Distinguish three capabilities in UI/CLI and documentation:

1. Reference inventory: metadata about a credential held elsewhere.
2. Platform handoff: actual registration/assertion delegated to a supported
   platform authenticator; SentinelPass does not thereby own or back up its key.
3. SentinelPass credential-provider mode: only after its own security design,
   platform feasibility, implementation and independent qualification.

## Delivery sequence and acceptance

- First pin an installed/build/version and supported platform/browser matrix.
  Assess macOS Chrome with Touch ID first for the reported workflow; identify
  required OS entitlements, signing, provider registration, extension/native-host
  boundaries and fallback. Validate official platform contracts during design;
  do not assume extension JavaScript can register a system credential provider.
- Decide key custody, authenticator/provider role, supported algorithms,
  credential/issuer bindings, discoverability, user verification and attestation
  policy. Keep origin/RP-ID/challenge/user binding enforced throughout the
  extension, native host, daemon and platform boundary. Reject hostile iframe,
  cross-origin/suffix confusion, replay and confused-deputy requests. Agents may
  initiate an approved flow but cannot manufacture user presence or verification.
- Implement real create/get journeys and cancellation, timeout, lock/autolock,
  fresh authorization and restart behavior with explicit UI outcomes. A locked
  vault or failed ceremony must fail closed. Treat updating a reference and
  deleting an actual credential as separate operations with separate impact.
- Keep existing reference data compatible and clearly labeled. Do not serialize
  raw passkey private material as generic password/API-key text or route it
  through password autofill/export. Cross-device sync, backup/recovery and any
  standards-based exchange need their own custody/protocol review; declare
  unavailable capabilities instead of implying a recoverable passkey backup.
- Regression-test the password save workflow: vault unlock versus fresh mutation
  authorization, human prompt ownership, interrupted-write reconciliation,
  duplicate avoidance, redacted diagnostics and no secrets in process arguments.
- Qualify with Identity on disposable dev accounts: register a real credential;
  sign out and assert it; prove wrong origin/RP-ID, stale challenge and missing UV
  refusals; approve an exact reviewed harmless action and return to its initiating
  owner workspace. Prove server-side policy/grant results, not only a successful
  browser click. Preserve existing-factor proof or use approved recovery when
  adding factors to an account that already has inaccessible credentials.
- Record real human Touch ID outcomes separately from virtual-authenticator
  automation. Use only sanitized boolean/status/path results and build versions;
  retain no authenticator payload, biometric data, private browser state or
  credentials. Run independent security review and the supported-platform matrix
  before changing `SECURITY_STATUS_MATRIX.md` from planned/partial to supported.

## Integration boundaries

Identity owns server enrollment/assertion verification and reviewed-action
binding. SentinelPass owns its credential/provider/user-consent surfaces.
AgentBrowser CDP attach drives the confirmed authorized Mac profile; it does not
itself provide a passkey. Production Identity promotion remains separately gated.
No live credential reset, provider activation or release is authorized by this
handoff. Implementation work must target SentinelPass develop via reviewed PR.

Canonical follow-up destinations: SentinelPass `docs/PASSKEY_PRODUCT_DESIGN.md`,
`docs/SECURITY_STATUS_MATRIX.md`, roadmap and a new scoped ADR/workcard. The
receiving team should allocate its own task IDs and evidence rather than invent
completion credit from this handoff.

The [macOS feasibility workcard](../workcards/macos-passkey-provider-feasibility.md)
defines the first signing and browser routing probe and the conditions for a real
provider build.

## Windows and Ubuntu qualification

Run these feasibility lanes alongside macOS. Keep baseline WebAuthn
interoperability and SentinelPass-controlled registration and assertion as
separate results. Record the OS build, browser version and package, authenticator
or provider selected, SentinelPass build, and server-side outcome for each run.

| Platform | Baseline interoperability | SentinelPass provider feasibility |
| --- | --- | --- |
| Windows 11 | Exercise Windows Hello and a physical FIDO2 USB security key in Edge and Chrome. Record whether user verification used Hello biometrics, a PIN, or the security key. | Start with Windows 11 25H2, the build specified by Microsoft's sample. Test plugin registration, enablement, browser selection, registration and assertion callbacks, cancellation, and uninstall. Verify the minimum supported Windows build separately. |
| Ubuntu desktop | Start on Ubuntu 24.04 LTS with Chrome and Firefox using a physical FIDO2 USB key. Record the browser packaging and device access result. A separate Chrome test may use Google Password Manager with a disposable test profile. | Evaluate a browser-specific extension and native-host path with approved credential custody. Require a routing probe on each browser before implementing a provider. Publish support per browser and package. Ubuntu-wide provider integration remains unqualified. |

Begin with the [loopback browser probe](../../prototypes/browser-passkey-probe/README.md)
to exercise browser-to-authenticator interaction. Use the same disposable
Identity journey for each claimed combination. Enroll,
sign in with the enrolled credential, approve a harmless reviewed owner action,
and verify return to the initiating workspace. Test cancellation, timeout,
unavailable or locked provider behavior, and origin and RP ID binding. For a
physical FIDO2 key, exercise removal during the ceremony and confirm the
application reports failure cleanly. Use headed sessions with an operator
present for physical user verification. Virtual-authenticator CI covers protocol
regressions and records its results separately from hardware and provider routing.

Microsoft documents the Windows plugin model and provides a reference
implementation. Chrome documents Google Password Manager support on Linux.
The Linux browser's own provider and an external hardware key are useful
interoperability baselines. SentinelPass provider support requires separate
evidence that the browser routed the request to SentinelPass and that its
reviewed custody and consent design handled the ceremony.

- [Microsoft WebAuthn API and plugin support](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)
- [Microsoft Passkey Manager sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/passkeymanager/)
- [Google Chrome passkey support](https://support.google.com/chrome/answer/13168025)
