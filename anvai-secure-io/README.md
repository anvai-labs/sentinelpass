# anvai-secure-io

Apache-2.0, Rust 2021, MSRV 1.89. A small native file-custody crate extracted for
Anvai applications. No database, cryptography, async runtime, UI or networking.
Not published to crates.io; consumers pin the reviewed Git revision.

```rust,no_run
use anvai_secure_io::{PrivateDir, Publish};
use std::path::Path;

let directory = PrivateDir::open_or_create(Path::new("/trusted/private/state"))?;
let _lock = directory.lock(Path::new("update.lock"))?;
directory.write(Path::new("record"), b"application bytes", Publish::CreateNew)?;
let bytes = directory.read(Path::new("record"), 4096)?;
# Ok::<(), anvai_secure_io::Error>(())
```

## Supported contract

Linux local filesystems: walk every directory component using `openat` and
`O_NOFOLLOW`; retain directory handles through all file operations. Ancestors
must be root/current-user owned and not group/other writable, except root-owned
sticky traversal directories such as `/tmp`. The final directory must belong to
the current effective UID and have no group/other or special permission bits.
New directories start at 0700; new files at 0600, subject to a restrictive umask.
Do not chmod arbitrary existing directories or repair loose files implicitly.

Regular files must belong to the effective UID, have one hard link, no
group/other permissions and no special mode bits. Reads are bounded both before
allocation and while reading, return zero-on-drop bytes, and never block opening
a FIFO. A requested bound is 1 byte through 16 MiB. Writes also cap at 16 MiB.
Names inside a retained directory are single components. Parent traversal in
the initial directory path is resolved by handles, never by removing a prior
component lexically. Symlinked homes/ancestors are intentionally refused; use
the actual trusted path.

Writes use a privately created exclusive temporary file, file `fsync`, atomic
rename (`RENAME_NOREPLACE` for create-only) and directory `fsync`. No link/unlink
publication window. Unsupported filesystem operations fail; there is no unsafe
fallback. A failure before rename preserves the old file. `CommitUncertain`
means rename succeeded but durability could not be confirmed: inspect state
before retrying. A killed process may leave a private `.anvai-pending-*` file;
these are never auto-adopted or globally swept. An operator may remove orphans
after all writers stop. Locks are advisory and held by the returned `File`;
never unlink a lock name. Atomic whole-file replacement is not a transactional
read-modify-write: hold one lock across the complete application update.

The owner account and root are trusted. This does not defend against a process
already executing as that UID, root, writable mounts or hostile filesystem
servers. It does not certify NFS, container UID mappings, Windows ACLs, macOS
durability or encrypted-at-rest storage. Non-Linux calls return `Unsupported`.
SentinelPass retains its prior platform implementation outside Linux. Identity
currently targets native Linux; browser WASM is not a filesystem-custody backend.

## Consumers and compatibility

SentinelPass uses this for Linux external-secret allowlist load/save. JSON and
token authorization semantics remain unchanged. Anvai Identity uses it for
database-secret reads and bootstrap file custody. Neither depends on the other's
vault, credential authority or database. Both can release independently with a
pinned crate revision. Public code has no dependency on private Identity code.

For pre-existing SentinelPass installations, check ownership and modes of the
configuration directory (0700) and allowlist (0600) before upgrading. The old
Linux reader repaired loose modes; this profile refuses them. Fix only verified
owned paths explicitly, after checking for symlinks/hard links. A malformed,
unsafe or oversized file is an error, never treated as an empty allowlist.
Only a genuinely missing file/directory yields the existing empty default.

Run `cargo test -p anvai-secure-io`, core allowlist tests, and each consumer's
regressions. Tests cover links/types, private modes, bounds, directory swaps,
concurrent creation/replacement, process locks, and killed writers before/after
publication. Process-crash tests are not power-loss/storage-hardware evidence.
Windows ACL support and broader filesystem fault injection remain separate work.
