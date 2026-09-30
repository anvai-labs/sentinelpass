//! Private file custody, independent of vaults, servers and cryptography.
//!
//! Linux implementation uses directory-relative handles, rejects symlinks in
//! every path component and validates ownership before reading or publishing.
//! Other platforms explicitly return Unsupported; they do not pretend Unix
//! modes enforce Windows ACLs. See README for the local-filesystem trust model.
#![forbid(unsafe_code)]

use std::{fs::File, path::Path};
use zeroize::Zeroizing;

/// Fixed, redacted errors: no paths, payloads, parser input or OS debug context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    AlreadyExists,
    UnsafePath,
    NotPrivate,
    TooLarge,
    Busy,
    Io,
    /// Publication happened but directory synchronization failed. Inspect before retrying.
    CommitUncertain,
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "private file or directory is missing",
            Self::AlreadyExists => "private file already exists",
            Self::UnsafePath => "symlink or unsafe path component refused",
            Self::NotPrivate => "owner-private regular file or directory required",
            Self::TooLarge => "private file exceeds the configured bound",
            Self::Busy => "private file lock is busy",
            Self::Io => "private file operation failed",
            Self::CommitUncertain => {
                "file published but durability is uncertain; inspect before retrying"
            }
            Self::Unsupported => "secure file operations are unsupported on this platform",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publish {
    CreateNew,
    ReplaceExisting,
    Upsert,
}

/// Retains an open directory handle. Directory renames never retarget operations.
#[derive(Debug)]
pub struct PrivateDir {
    #[cfg(target_os = "linux")]
    file: File,
}

/// Bound applies before allocation and during reading. Returned bytes zero on drop.
pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(Error::UnsafePath)?;
    PrivateDir::open(parent)?.read(Path::new(name), limit)
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(not(target_os = "linux"))]
impl PrivateDir {
    pub fn open(_: &Path) -> Result<Self> {
        Err(Error::Unsupported)
    }
    pub fn open_or_create(_: &Path) -> Result<Self> {
        Err(Error::Unsupported)
    }
    pub fn read(&self, _: &Path, _: usize) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unsupported)
    }
    pub fn write(&self, _: &Path, _: &[u8], _: Publish) -> Result<()> {
        Err(Error::Unsupported)
    }
    pub fn lock(&self, _: &Path) -> Result<File> {
        Err(Error::Unsupported)
    }
}
