//! Native-host registration files shared with the user's browsers.

use std::io::Write;
use std::path::Path;

pub(super) fn write_manifest(dir: &Path, filename: &str, contents: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create dir {}: {}", dir.display(), e))?;
    let path = dir.join(filename);
    // Replace the directory entry instead of following legacy installer links.
    // A private, exclusively created file in the same directory also prevents
    // browsers from seeing partial JSON and leaves linked targets untouched.
    let mut staged = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("Failed to stage manifest {}: {}", path.display(), e))?;
    staged
        .write_all(contents.as_bytes())
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    staged
        .persist(&path)
        .map_err(|e| format!("Failed to replace manifest {}: {}", path.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const NAME: &str = "com.passwordmanager.host.json";

    #[test]
    fn creates_missing_directories_and_replaces_existing_manifest() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("browser/NativeMessagingHosts");
        write_manifest(&dir, NAME, "first").unwrap();
        write_manifest(&dir, NAME, "replacement").unwrap();
        assert_eq!(fs::read_to_string(dir.join(NAME)).unwrap(), "replacement");
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn replaces_dangling_legacy_symlink_without_recreating_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("removed-installation/host.json");
        let path = root.path().join(NAME);
        std::os::unix::fs::symlink(&target, &path).unwrap();
        write_manifest(root.path(), NAME, "replacement").unwrap();
        assert!(!fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(path).unwrap(), "replacement");
        assert!(!target.parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn replaces_live_symlink_without_modifying_its_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("shared.json");
        fs::write(&target, "preserve shared file").unwrap();
        let path = root.path().join(NAME);
        std::os::unix::fs::symlink(&target, &path).unwrap();
        write_manifest(root.path(), NAME, "replacement").unwrap();
        assert_eq!(fs::read_to_string(target).unwrap(), "preserve shared file");
        assert!(!fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(path).unwrap(), "replacement");
    }

    #[test]
    fn replaces_hard_link_without_modifying_other_name() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("shared.json");
        fs::write(&target, "preserve shared file").unwrap();
        fs::hard_link(&target, root.path().join(NAME)).unwrap();
        write_manifest(root.path(), NAME, "replacement").unwrap();
        assert_eq!(fs::read_to_string(target).unwrap(), "preserve shared file");
        assert_eq!(
            fs::read_to_string(root.path().join(NAME)).unwrap(),
            "replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_is_private_even_when_old_manifest_is_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(NAME);
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        write_manifest(root.path(), NAME, "replacement").unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn failure_preserves_destination_and_removes_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(NAME);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), "unchanged").unwrap();
        assert!(write_manifest(root.path(), NAME, "replacement").is_err());
        assert_eq!(fs::read_to_string(path.join("keep")).unwrap(), "unchanged");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
