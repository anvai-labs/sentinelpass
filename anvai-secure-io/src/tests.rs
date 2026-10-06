use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    process::Command,
    sync::{Arc, Barrier, Mutex},
};
use tempfile::TempDir;

fn dir() -> (TempDir, PrivateDir) {
    let tmp = private_tempdir();
    let dir = PrivateDir::open(tmp.path()).unwrap();
    (tmp, dir)
}

/// tempfile >= 3.27 creates its directory through the process umask, so on
/// hosts with a permissive shared-group umask (002) the tempdir is born
/// group-writable and the crate correctly refuses it. Tests that need a
/// traversable base must normalize it explicitly instead of depending on
/// the ambient umask or the tempfile version (found on the dataserver3
/// Linux smoke host; CI runners' 022 umask masked it).
fn private_tempdir() -> TempDir {
    let tmp = TempDir::new().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    tmp
}

#[test]
fn private_creation_bounds_and_no_clobber() {
    let (tmp, dir) = dir();
    let path = Path::new("file");
    dir.write(path, b"first", Publish::CreateNew).unwrap();
    assert_eq!(
        fs::metadata(tmp.path().join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        dir.write(path, b"second", Publish::CreateNew),
        Err(Error::AlreadyExists)
    );
    assert_eq!(dir.read(path, 4), Err(Error::TooLarge));
    assert_eq!(&*dir.read(path, 5).unwrap(), b"first");
    dir.write(path, b"second", Publish::ReplaceExisting)
        .unwrap();
    assert_eq!(
        &*read_private(&tmp.path().join(path), 6).unwrap(),
        b"second"
    );
    assert_eq!(
        dir.write(Path::new("missing"), b"x", Publish::ReplaceExisting),
        Err(Error::Missing)
    );
    assert_eq!(dir.read(path, usize::MAX), Err(Error::TooLarge));
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
}

#[test]
fn missing_nested_directories_are_private_from_creation() {
    let tmp = private_tempdir();
    let nested = tmp.path().join("a/b");
    PrivateDir::open_or_create(&nested).unwrap();
    for path in [tmp.path().join("a"), nested] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn leaf_symlinks_hardlinks_and_nonregular_files_are_rejected() {
    let (tmp, dir) = dir();
    dir.write(Path::new("target"), b"unchanged", Publish::CreateNew)
        .unwrap();
    symlink("target", tmp.path().join("link")).unwrap();
    assert_eq!(dir.read(Path::new("link"), 100), Err(Error::UnsafePath));
    assert_eq!(
        dir.write(Path::new("link"), b"changed", Publish::Upsert),
        Err(Error::UnsafePath)
    );
    symlink("absent", tmp.path().join("dangling")).unwrap();
    assert_eq!(dir.read(Path::new("dangling"), 100), Err(Error::UnsafePath));
    fs::hard_link(tmp.path().join("target"), tmp.path().join("hard")).unwrap();
    assert_eq!(dir.read(Path::new("target"), 100), Err(Error::NotPrivate));
    assert_eq!(
        dir.write(Path::new("hard"), b"bad", Publish::Upsert),
        Err(Error::NotPrivate)
    );
    fs::create_dir(tmp.path().join("directory")).unwrap();
    assert_eq!(
        dir.read(Path::new("directory"), 100),
        Err(Error::NotPrivate)
    );
    assert_eq!(fs::read(tmp.path().join("target")).unwrap(), b"unchanged");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        tmp.path().join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(dir.read(Path::new("fifo"), 100), Err(Error::NotPrivate));
}

#[test]
fn directory_links_and_traversal_names_are_rejected() {
    let (tmp, dir) = dir();
    fs::create_dir(tmp.path().join("real")).unwrap();
    symlink("real", tmp.path().join("link")).unwrap();
    assert_eq!(
        PrivateDir::open_or_create(&tmp.path().join("link/new")).unwrap_err(),
        Error::UnsafePath
    );
    assert_eq!(
        PrivateDir::open(&tmp.path().join("link/..")).unwrap_err(),
        Error::UnsafePath
    );
    for name in ["../escape", "/absolute", "a/b", ".", "..", ""] {
        assert_eq!(
            dir.write(Path::new(name), b"x", Publish::Upsert),
            Err(Error::UnsafePath)
        );
    }
}

#[test]
fn loose_files_and_directories_fail_without_chmod() {
    let (tmp, dir) = dir();
    dir.write(Path::new("file"), b"x", Publish::CreateNew)
        .unwrap();
    fs::set_permissions(tmp.path().join("file"), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(dir.read(Path::new("file"), 1), Err(Error::NotPrivate));
    assert_eq!(
        dir.write(Path::new("file"), b"y", Publish::Upsert),
        Err(Error::NotPrivate)
    );
    assert_eq!(
        fs::metadata(tmp.path().join("file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        PrivateDir::open_or_create(tmp.path()).unwrap_err(),
        Error::NotPrivate
    );
    assert_eq!(dir.lock(Path::new("lock")).unwrap_err(), Error::NotPrivate);
}

#[test]
fn writable_ancestor_is_rejected() {
    let (tmp, _) = dir();
    let child = tmp.path().join("child");
    PrivateDir::open_or_create(&child).unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    // Non-root test accounts exercise the untrusted-ancestor case. Root-owned
    // non-sticky directories are also refused.
    assert_eq!(PrivateDir::open(&child).unwrap_err(), Error::UnsafePath);
}

#[test]
fn held_directory_handle_cannot_be_retargeted_by_path_swap() {
    let tmp = private_tempdir();
    let first = tmp.path().join("first");
    let moved = tmp.path().join("moved");
    let dir = PrivateDir::open_or_create(&first).unwrap();
    fs::rename(&first, &moved).unwrap();
    symlink(tmp.path(), &first).unwrap();
    dir.write(Path::new("file"), b"safe", Publish::CreateNew)
        .unwrap();
    assert_eq!(fs::read(moved.join("file")).unwrap(), b"safe");
    assert!(!tmp.path().join("file").exists());
}

#[test]
fn concurrent_create_has_one_winner_and_reads_never_see_partial_replacement() {
    let (tmp, _) = dir();
    let barrier = Arc::new(Barrier::new(8));
    let mut jobs = Vec::new();
    for i in 0..8 {
        let path = tmp.path().to_owned();
        let barrier = barrier.clone();
        jobs.push(std::thread::spawn(move || {
            let dir = PrivateDir::open(&path).unwrap();
            barrier.wait();
            dir.write(Path::new("file"), &[i; 4096], Publish::CreateNew)
        }));
    }
    let outcomes: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|v| v.is_ok()).count(), 1);
    assert!(outcomes
        .iter()
        .all(|v| v.is_ok() || *v == Err(Error::AlreadyExists)));
    let path = tmp.path().to_owned();
    let writer = std::thread::spawn(move || {
        let dir = PrivateDir::open(&path).unwrap();
        for i in 0..50 {
            dir.write(Path::new("file"), &[i; 4096], Publish::ReplaceExisting)
                .unwrap();
        }
    });
    let dir = PrivateDir::open(tmp.path()).unwrap();
    for _ in 0..100 {
        let bytes = dir.read(Path::new("file"), 4096).unwrap();
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.iter().all(|b| *b == bytes[0]));
    }
    writer.join().unwrap();
}

const CHILD_PATH: &str = "ANVAI_SECURE_IO_TEST_PATH";
// Serialize subprocess tests: an unrelated concurrent fork can inherit a held
// flock descriptor until exec closes it (even with CLOEXEC). That transient
// reference would invalidate the immediate release-on-drop assertion below.
// Keep the assertion strict; exclude only unrelated forks from its lifetime.
static SUBPROCESS_TEST: Mutex<()> = Mutex::new(());

pub(crate) fn checkpoint(point: &str) {
    if std::env::var("ANVAI_SECURE_IO_TEST_CRASH").as_deref() == Ok(point) {
        std::process::exit(86);
    }
}

#[test]
fn subprocess_operation() {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return;
    };
    let dir = PrivateDir::open(Path::new(&path)).unwrap();
    if std::env::var_os("ANVAI_SECURE_IO_TEST_LOCK").is_some() {
        assert_eq!(dir.lock(Path::new("lock")).unwrap_err(), Error::Busy);
    } else {
        dir.write(Path::new("file"), b"new", Publish::ReplaceExisting)
            .unwrap();
    }
}

fn child(path: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "tests::subprocess_operation", "--nocapture"]);
    command.env(CHILD_PATH, path);
    command
}

#[test]
fn locks_exclude_other_processes_and_release_on_drop() {
    let _subprocess_test = SUBPROCESS_TEST.lock().unwrap();
    let (tmp, dir) = dir();
    let lock = dir.lock(Path::new("lock")).unwrap();
    assert!(child(tmp.path())
        .env("ANVAI_SECURE_IO_TEST_LOCK", "1")
        .status()
        .unwrap()
        .success());
    drop(lock);
    dir.lock(Path::new("lock")).unwrap();
}

#[test]
fn process_crashes_leave_only_complete_old_or_new_files() {
    let _subprocess_test = SUBPROCESS_TEST.lock().unwrap();
    for (point, expected) in [
        ("before-publication", b"old"),
        ("after-publication", b"new"),
    ] {
        let (tmp, dir) = dir();
        dir.write(Path::new("file"), b"old", Publish::CreateNew)
            .unwrap();
        let status = child(tmp.path())
            .env("ANVAI_SECURE_IO_TEST_CRASH", point)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert_eq!(&*dir.read(Path::new("file"), 3).unwrap(), expected);
        // Restart can replace even when a private orphan temp remains.
        dir.write(Path::new("file"), b"end", Publish::ReplaceExisting)
            .unwrap();
        assert_eq!(&*dir.read(Path::new("file"), 3).unwrap(), b"end");
    }
}

#[test]
fn error_messages_never_contain_path_or_payload() {
    let (tmp, dir) = dir();
    let path = tmp.path().join("private-path-value");
    let error = read_private(&path, 10).unwrap_err();
    assert_eq!(error, Error::Missing);
    assert!(!error.to_string().contains("private-path-value"));
    let error = dir
        .write(
            Path::new("../sensitive-value"),
            b"secret-payload",
            Publish::Upsert,
        )
        .unwrap_err();
    assert!(!format!("{error:?}: {error}").contains("secret-payload"));
}
