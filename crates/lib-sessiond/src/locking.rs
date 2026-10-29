//! Internal UID locking. Never expose caller-managed guards to PAM/CLI.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

pub(crate) struct LockDirectory {
    directory: File,
    owner: u32,
}
pub(crate) struct UidGuard {
    _file: File,
}

impl LockDirectory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let directory = secure_directory(path, true)?;
        validate_directory(&directory, 0, false)?;
        Ok(Self {
            directory,
            owner: 0,
        })
    }

    pub(crate) fn acquire(&self, uid: u32, timeout: Duration) -> io::Result<UidGuard> {
        let name = uid.to_string();
        // Every acquisition opens an independent file description. Never clone
        // or cache the locked descriptor, including between daemon threads.
        let file = open_at(
            &self.directory,
            &name,
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        validate_lock(&file, self.owner)?;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "UID lock deadline overflow")
        })?;
        loop {
            // SAFETY: live descriptor; flock has no pointer arguments.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                return Err(error);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("waiting for UID {uid} lifecycle lock"),
                ));
            };
            std::thread::sleep(remaining.min(Duration::from_millis(5)));
        }
        validate_directory(&self.directory, self.owner, false)?;
        validate_lock(&file, self.owner)?;
        let named = open_at(&self.directory, &name, libc::O_RDWR | libc::O_NONBLOCK, 0)?;
        validate_lock(&named, self.owner)?;
        let held = file.metadata()?;
        let current = named.metadata()?;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err(io::Error::other(
                "UID lock inode was replaced while acquiring it",
            ));
        }
        Ok(UidGuard { _file: file })
    }
}

fn validate_lock(file: &File, owner: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe UID lock: require owned regular single-link 0600 file",
        ));
    }
    Ok(())
}
fn validate_directory(directory: &File, owner: u32, allow_sticky: bool) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner
        || (metadata.mode() & 0o022 != 0 && !(allow_sticky && metadata.mode() & 0o1000 != 0))
        || metadata.nlink() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lifecycle directory ownership/mode",
        ));
    }
    Ok(())
}

/// Resolve root-controlled parents without following symlinks. Root-owned
/// sticky ancestors such as /tmp are allowed, but callers validate the final
/// directory according to its role. Never create through an untrusted parent.
pub(crate) fn secure_directory(path: &Path, create: bool) -> io::Result<File> {
    secure_directory_mode(path, create, 0o700)
}

pub(crate) fn secure_directory_mode(path: &Path, create: bool, mode: u32) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lifecycle path must be absolute",
        ));
    }
    let mut directory = File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 lifecycle path")
            })?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe lifecycle path component",
                ));
            }
        };
        validate_directory(&directory, 0, true)?;
        directory = match open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(dir) => dir,
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                let name_c = CString::new(name)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                // SAFETY: pinned directory and validated, NUL-terminated name.
                let created = unsafe {
                    libc::mkdirat(directory.as_raw_fd(), name_c.as_ptr(), mode as libc::mode_t)
                } == 0;
                if !created {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                let opened = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                validate_directory(&opened, 0, true)?;
                if created {
                    opened.set_permissions(std::fs::Permissions::from_mode(mode))?;
                }
                opened
            }
            Err(e) => return Err(e),
        };
        validate_directory(&directory, 0, true)?;
    }
    Ok(directory)
}

pub(crate) fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: pinned directory, valid C name, flags/mode and checked ownership.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transfers a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Arc;

    fn fixture() -> (tempfile::TempDir, LockDirectory) {
        let path = tempfile::tempdir().unwrap();
        let directory = File::open(path.path()).unwrap();
        let owner = directory.metadata().unwrap().uid();
        (path, LockDirectory { directory, owner })
    }
    #[test]
    fn same_uid_serializes_threads_and_different_uids_progress() {
        let (path, locks) = fixture();
        let locks = Arc::new(locks);
        let guard = locks.acquire(1000, Duration::ZERO).unwrap();
        let other = locks.clone();
        let thread = std::thread::spawn(move || {
            assert_eq!(
                other
                    .acquire(1000, Duration::from_millis(20))
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            other.acquire(1001, Duration::ZERO).unwrap();
        });
        thread.join().unwrap();
        drop(guard);
        locks.acquire(1000, Duration::ZERO).unwrap();
        assert!(path.path().join("1000").is_file());
        assert_eq!(
            fs::metadata(path.path().join("1000")).unwrap().mode() & 0o7777,
            0o600
        );
    }
    #[test]
    fn lock_subprocess_probe() {
        let Some(path) = std::env::var_os("LIB_SESSIOND_LOCK_TEST_DIRECTORY") else {
            return;
        };
        let directory = File::open(path).unwrap();
        let owner = directory.metadata().unwrap().uid();
        let locks = LockDirectory { directory, owner };
        match locks.acquire(1000, Duration::ZERO) {
            Ok(_guard) => {}
            Err(error) if error.kind() == io::ErrorKind::TimedOut => std::process::exit(73),
            Err(error) => panic!("{error}"),
        }
    }
    #[test]
    fn independent_processes_contend_for_the_same_uid() {
        let (path, locks) = fixture();
        let guard = locks.acquire(1000, Duration::ZERO).unwrap();
        let run = || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "locking::tests::lock_subprocess_probe"])
                .env("LIB_SESSIOND_LOCK_TEST_DIRECTORY", path.path())
                .output()
                .unwrap()
        };
        assert_eq!(run().status.code(), Some(73));
        drop(guard);
        let output = run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn replacement_while_waiting_is_rejected_instead_of_locking_the_wrong_inode() {
        use std::os::unix::fs::OpenOptionsExt;
        let (path, locks) = fixture();
        let locks = Arc::new(locks);
        let guard = locks.acquire(1000, Duration::ZERO).unwrap();
        let other = locks.clone();
        let thread = std::thread::spawn(move || other.acquire(1000, Duration::from_secs(3)));
        let lock_path = path.path().join("1000");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let open_count = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| fs::read_link(e.path()).ok().as_ref() == Some(&lock_path))
                .count();
            if open_count >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "waiter never opened its independent descriptor"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        fs::remove_file(&lock_path).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        drop(guard);
        assert!(thread.join().unwrap().is_err());
        assert!(lock_path.is_file());
    }
    #[test]
    fn unsafe_lock_nodes_are_rejected_without_following_symlinks() {
        let (path, locks) = fixture();
        fs::write(path.path().join("target"), "untouched").unwrap();
        symlink("target", path.path().join("1000")).unwrap();
        assert!(locks.acquire(1000, Duration::ZERO).is_err());
        assert_eq!(
            fs::read_to_string(path.path().join("target")).unwrap(),
            "untouched"
        );
        fs::remove_file(path.path().join("1000")).unwrap();
        fs::write(path.path().join("1000"), "").unwrap();
        fs::set_permissions(path.path().join("1000"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(locks.acquire(1000, Duration::ZERO).is_err());
        fs::remove_file(path.path().join("1000")).unwrap();
        fs::create_dir(path.path().join("1000")).unwrap();
        assert!(locks.acquire(1000, Duration::ZERO).is_err());
    }
    #[test]
    fn held_descriptors_are_close_on_exec_and_files_are_never_unlinked() {
        let (path, locks) = fixture();
        let guard = locks.acquire(1000, Duration::ZERO).unwrap();
        // SAFETY: fcntl reads flags of a live descriptor.
        let flags = unsafe { libc::fcntl(guard._file.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let inode = fs::metadata(path.path().join("1000")).unwrap().ino();
        drop(guard);
        assert_eq!(fs::metadata(path.path().join("1000")).unwrap().ino(), inode);
    }
    #[test]
    fn hard_linked_lock_files_are_rejected() {
        let (path, locks) = fixture();
        drop(locks.acquire(1000, Duration::ZERO).unwrap());
        fs::hard_link(path.path().join("1000"), path.path().join("alias")).unwrap();
        assert!(locks.acquire(1000, Duration::ZERO).is_err());
    }
}
