# KC-03 preparation: scoped independent review

Reviewed preparation files against runtime candidate
`1df027932f08baabf2afebb6a0444bab867fcd12` and the pinned consumer snapshot
`3b5ca0258d8644c797b160678f32e24b1885280c`. Repository and sibling source were
read-only during review. This is preparation review, not acceptance of a runtime
integration, code-owner approval, merge authorization or production activation.

## Outcome

Scoped acceptance: no remaining blocker found in these preparation files.

The initial low-severity checker defect is resolved. The previous POSIX-only
`../` test accepted Windows relative parent paths such as `..\outside\source`.
The new `isWithinRoot` uses the first separator-independent path component and
also rejects absolute relative results, including cross-drive targets. Reviewed
the preserved failing regression in `containment-red.log`; the regression now
passes for both Windows and POSIX path semantics. This does not claim Windows
host execution or protection against concurrent hostile filesystem mutation.

The workcard and handback correctly distinguish existing native Rust mail
recovery from the Settings/Worker integration, metadata ABI validation from
secret transport, mail-only proof from two-purpose integration, and same-process
proof from macOS inter-application admission. The native recovery function and
toolchain/import-feature statements were checked against the pinned consumer
source. Native storage, canonical binding vectors, independent current authority,
recovered-key lifecycle, admission bounds, trusted UI and authenticated
application identity remain explicit entry gates.

The candidate handback identifies the unmerged producer, separate code-owner
approval, and CI status as of preparation. It does not turn source matching into
exact-head CI or capability enablement. Readiness remains false. The manifest is
explicitly a scoped source inventory, not complete dependency provenance or an
authenticated manifest obtained from an untrusted source.

## Checks run

- `node --test scripts/check-custody-handoff.test.mjs`: **5 passed, 0 failed**.
- Recomputed the report with `checkSources` against the local producer and pinned
  Sandesha checkout: **61 matching files**; JSON serialization plus final newline
  was byte-identical to `source-check.json`.
- `integrationReady` and `productionReady`: both **false**.

## Reviewed SHA-256 values

| File | SHA-256 |
| --- | --- |
| `docs/CUSTODY_KC03_WORKCARD.md` | `b6dd91aa72378c748f12796533f677485640e9dbc805a610f5cff6f5d6322b5f` |
| `scripts/check-custody-handoff.mjs` | `bffc72e941a83456c5af76cfc21b2194fab183f64a7cc2d93baf11f5e23ed4b5` |
| `scripts/check-custody-handoff.test.mjs` | `d92248f17bfa7248f06cb25dec9791b9d87471ca2554063f72e4eb74d75d2e0a` |
| `docs/evidence/custody-kc03-preflight/inputs.json` | `3099936dedff3ce48cbd025b01368b89abbd1867ab562029aa731944dc216c04` |
| `docs/evidence/custody-kc03-preflight/source-check.json` | `31bf42f8bb9a31d923ff0c71ca53e42f5ede9fc29dcf09a8635192927a1f9a9d` |
| `docs/evidence/custody-kc03-preflight/README.md` | `2f22d6f805d3fc463685df85f4799e53a6fe743f39f2464b616c4908263c08b8` |
| `docs/SANDESHA_USER_KEY_CUSTODY_HANDBACK_2026-10-17.md` | `790ffd625cb2979ea1f45c9a08d8e28b550aed7182ec2bda14d5a3ed9690bc04` |

No native crypto execution, platform/device qualification, complete dependency
review, real-key enrollment or transport implementation was performed here.
