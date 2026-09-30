# ADR-012: shared private-file custody

Date: 2026-09-30. Status: implemented for Linux allowlist storage; review pending.

Extract the bounded Linux file-custody contract into the Apache-2.0
`anvai-secure-io` workspace crate. It owns handle-relative traversal, owner/mode
and regular-file checks, bounded zeroizing reads, atomic durable publication
and advisory locks. It has no vault, crypto, database, UI or networking dependency.
Other Anvai applications consume a pinned Git revision without depending on core.

The first SentinelPass consumer is `ExternalSecretAllowlist` on Linux. JSON and
legacy/enforced/revoked token semantics do not change. Atomic publication fixes
the prior save path that configured 0600 `OpenOptions` but called `fs::write`.
The new reader bounds files to 1 MiB, rejects dangling links and fails closed on
unsafe metadata. It no longer repairs loose permissions implicitly. Operators
must check actual owned paths and set the configuration directory to 0700 and
allowlist to 0600 before upgrading. See the crate README for limits and recovery.

Non-Linux platforms retain their platform path; the save function now uses the
configured options. No Windows ACL or macOS handle/durability guarantee is added.
Shared crate calls return Unsupported outside Linux. Existing vault platform
helpers, SQLite paths, cryptographic policy and token authorization stay separate.

A universal common crate or direct core dependency would conflate unrelated
trust boundaries. Copying helpers would leave patches divergent. This small
crate allows two independent products to use one tested file contract. Security
fixes need coordinated version updates; no public package depends on private code.

Linux tests cover file/directory links, permissions, bounded reads, directory
replacement, concurrent writes, lock exclusion and process crashes around
publication. MSRV 1.89 is exercised separately. Process-crash evidence is not a
power-loss certification. User-namespace ownership remapping, Windows ACLs,
other filesystems and transactional read-modify-write remain explicit limits.
A locked update must hold the same lock across read, mutation and save; atomic
save alone does not prevent lost updates. Tokenless legacy grants remain outside
this refactor and must be rejected by any new token-required integration profile.
