use crate::{Error, PrivateDir, Publish, Result};
use rustix::{
    fs::{self, AtFlags, Mode, OFlags, RenameFlags},
    io::Errno,
    process::geteuid,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn errno(error: Errno) -> Error {
    match error {
        Errno::NOENT => Error::Missing,
        Errno::EXIST => Error::AlreadyExists,
        Errno::LOOP | Errno::NOTDIR => Error::UnsafePath,
        _ => Error::Io,
    }
}

fn leaf(name: &Path) -> Result<()> {
    let mut parts = name.components();
    if matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none() {
        Ok(())
    } else {
        Err(Error::UnsafePath)
    }
}

fn check_file(file: &File, allow_unlinked: bool) -> Result<()> {
    let meta = file.metadata().map_err(|_| Error::Io)?;
    if !meta.is_file()
        || meta.uid() != geteuid().as_raw()
        || meta.mode() & 0o7077 != 0
        || (meta.nlink() != 1 && !(allow_unlinked && meta.nlink() == 0))
    {
        return Err(Error::NotPrivate);
    }
    Ok(())
}

fn check_dir(file: &File, private: bool) -> Result<()> {
    let meta = file.metadata().map_err(|_| Error::Io)?;
    let uid = geteuid().as_raw();
    if !meta.is_dir() {
        return Err(Error::UnsafePath);
    }
    if private {
        if meta.uid() != uid || meta.mode() & 0o7077 != 0 {
            return Err(Error::NotPrivate);
        }
    } else {
        // Root-owned sticky directories (e.g. /tmp) may be traversed; each
        // child is opened without following links and independently checked.
        let trusted_sticky = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if (meta.uid() != uid && meta.uid() != 0) || (meta.mode() & 0o022 != 0 && !trusted_sticky) {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}

impl PrivateDir {
    pub fn open(path: &Path) -> Result<Self> {
        Self::walk(path, false)
    }
    pub fn open_or_create(path: &Path) -> Result<Self> {
        Self::walk(path, true)
    }

    fn walk(path: &Path, create: bool) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().map_err(|_| Error::Io)?.join(path)
        };
        let mut current = File::from(fs::open("/", DIR_FLAGS, Mode::empty()).map_err(errno)?);
        check_dir(&current, false)?;
        for component in absolute.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => Path::new(name),
                // Resolve .. using a directory handle, never lexical removal:
                // a preceding symlink is still rejected before this step.
                Component::ParentDir => Path::new(".."),
                _ => return Err(Error::UnsafePath),
            };
            let fd = match fs::openat(&current, name, DIR_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if create && name != Path::new("..") => {
                    match fs::mkdirat(&current, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) => fs::fsync(&current).map_err(errno)?,
                        Err(Errno::EXIST) => {}
                        Err(error) => return Err(errno(error)),
                    }
                    fs::openat(&current, name, DIR_FLAGS, Mode::empty()).map_err(errno)?
                }
                Err(error) => return Err(errno(error)),
            };
            current = File::from(fd);
            check_dir(&current, false)?;
        }
        check_dir(&current, true)?;
        Ok(Self { file: current })
    }

    fn open_file(&self, name: &Path) -> Result<File> {
        leaf(name)?;
        check_dir(&self.file, true)?;
        let file =
            File::from(fs::openat(&self.file, name, FILE_FLAGS, Mode::empty()).map_err(errno)?);
        check_file(&file, true)?;
        Ok(file)
    }

    pub fn read(&self, name: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
        if limit == 0 || limit > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let file = self.open_file(name)?;
        if file.metadata().map_err(|_| Error::Io)?.len() > limit as u64 {
            return Err(Error::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        if bytes.len() > limit {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    pub fn write(&self, name: &Path, bytes: &[u8], publish: Publish) -> Result<()> {
        leaf(name)?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        check_dir(&self.file, true)?;
        if publish != Publish::CreateNew {
            match self.open_file(name) {
                Ok(_) => {}
                Err(Error::Missing) if publish == Publish::Upsert => {}
                Err(error) => return Err(error),
            }
        }
        // Predictability is harmless: the directory is private and O_EXCL
        // prevents following/clobbering an existing temporary file.
        let mut temporary = None;
        for _ in 0..128 {
            let name = format!(
                ".anvai-pending-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            );
            match fs::openat(
                &self.file,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    temporary = Some((name, File::from(fd)));
                    break;
                }
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(errno(error)),
            }
        }
        let (temporary, mut file) = temporary.ok_or(Error::Busy)?;
        let result = (|| {
            check_file(&file, false)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| Error::Io)?;
            #[cfg(test)]
            crate::tests::checkpoint("before-publication");
            if publish == Publish::CreateNew {
                fs::renameat_with(
                    &self.file,
                    temporary.as_str(),
                    &self.file,
                    name,
                    RenameFlags::NOREPLACE,
                )
                .map_err(errno)?;
            } else {
                fs::renameat(&self.file, temporary.as_str(), &self.file, name).map_err(errno)?;
            }
            #[cfg(test)]
            crate::tests::checkpoint("after-publication");
            fs::fsync(&self.file).map_err(|_| Error::CommitUncertain)
        })();
        if result.is_err() {
            // Only this operation's temp name is removed. No sweeping stale
            // files: a concurrent writer may still own one.
            let _ = fs::unlinkat(&self.file, temporary.as_str(), AtFlags::empty());
        }
        result
    }

    /// Advisory process lock; keep the returned handle alive. Never unlink its name.
    pub fn lock(&self, name: &Path) -> Result<File> {
        leaf(name)?;
        check_dir(&self.file, true)?;
        let file = File::from(
            fs::openat(
                &self.file,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(errno)?,
        );
        check_file(&file, false)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => Error::Busy,
            std::fs::TryLockError::Error(_) => Error::Io,
        })?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn already_open_replaced_inode_is_readable_but_not_a_valid_lock() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = PrivateDir::open(tmp.path()).unwrap();
        directory
            .write(Path::new("file"), b"old", Publish::CreateNew)
            .unwrap();
        let mut opened = directory.open_file(Path::new("file")).unwrap();
        directory
            .write(Path::new("file"), b"new", Publish::ReplaceExisting)
            .unwrap();
        assert_eq!(opened.metadata().unwrap().nlink(), 0);
        check_file(&opened, true).unwrap();
        assert_eq!(check_file(&opened, false), Err(Error::NotPrivate));
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"old");
        assert_eq!(&*directory.read(Path::new("file"), 3).unwrap(), b"new");
    }
}
