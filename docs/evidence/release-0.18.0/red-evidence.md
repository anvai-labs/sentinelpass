# Promotion review red evidence

Base: origin/main `b7b9f5c3c886cdb0532fe5e60dec39e1d07ce061`.
Reviewed release-preparation working tree on `732b0d883eeddfa414a0957b87906e0d088a69fa`.
These are retained observations from the independent review before corrective edits.

## Detached fuzz lock

Command (after compiler-cache permission errors, cache disabled for this read):

```sh
RUSTC_WRAPPER= cargo metadata --manifest-path fuzz/Cargo.toml --locked --offline --format-version 1 > /private/tmp/custody-018-fuzz-metadata.json
```

Observed exit 101:

```text
error: cannot update the lock file /Users/vijaysingh/code/sentinelpass/fuzz/Cargo.lock because --locked was passed to prevent this
help: to generate the lock file without accessing the network, remove the --locked flag and use --offline instead.
```

The root manifests had advanced to 0.18.0; detached lock still listed sentinelpass-core, sentinelpass-protocol and sentinelpass-relay at 0.17.0.

## Protocol package fixture omission

Command:

```sh
RUSTC_WRAPPER= cargo package -p sentinelpass-protocol --list --allow-dirty --locked --offline > /private/tmp/custody-018-protocol-package-list.txt
```

Exit 0. The retained package file list contains `tests/custody_contract.rs`, but no custody golden or positional-array vectors. Those tests include five files at `../../bindings/custody/...`, outside the package root. The newer Sandesha fixture is correctly inside `tests/fixtures`; this does not supply the missing custody fixtures. This is a package-completeness defect, independently of whether Cargo's default package verification builds integration tests.

## Existing publication ordering gap

`.github/workflows/release.yml:687` had:

```yaml
needs: [setup, security-audit, npm-audit-root, npm-audit-e2e]
```

for `crates-publish`, while the GitHub `release` job waits for bundle smoke, installer smoke and feature matrix as well. A tag could therefore publish sentinelpass-protocol while those checks were pending or failing. This is inherited from main, not introduced by the custody diff, but it conflicts with the intended all-publishing-gates release condition. No tag or publication was performed by this reviewer.
