//! Root-controlled filesystem helpers and the daemon's one lifetime lock.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

pub struct Singleton {
    _file: File,
}
impl Singleton {
    /// Held through worker quiescence. Never unlink this stable lock inode.
    pub fn acquire(state: &Path) -> io::Result<Self> {
        let directory = secure_directory(state, true)?;
        validate_directory(&directory, false)?;
        let file = open_at(
            &directory,
            "daemon.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe daemon lifetime lock",
            ));
        }
        // SAFETY: live descriptor, nonblocking flock has no pointer arguments.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let current = open_at(
            &directory,
            "daemon.lock",
            libc::O_RDWR | libc::O_NONBLOCK,
            0,
        )?
        .metadata()?;
        if (current.dev(), current.ino(), current.nlink()) != (metadata.dev(), metadata.ino(), 1) {
            return Err(io::Error::other("daemon lifetime lock was replaced"));
        }
        Ok(Self { _file: file })
    }
}
fn validate_directory(directory: &File, allow_sticky: bool) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.nlink() == 0
        || (metadata.mode() & 0o022 != 0 && !(allow_sticky && metadata.mode() & 0o1000 != 0))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lifecycle directory ownership/mode",
        ));
    }
    Ok(())
}
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
        validate_directory(&directory, true)?;
        directory = match open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(dir) => dir,
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                let name_c = CString::new(name)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                // SAFETY: pinned directory, validated relative C name.
                let created = unsafe {
                    libc::mkdirat(directory.as_raw_fd(), name_c.as_ptr(), mode as libc::mode_t)
                } == 0;
                if !created {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
                let opened = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                validate_directory(&opened, true)?;
                if created {
                    opened.set_permissions(std::fs::Permissions::from_mode(mode))?;
                }
                opened
            }
            Err(e) => return Err(e),
        };
        validate_directory(&directory, true)?;
    }
    Ok(directory)
}
pub(crate) fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: live directory, valid C name and checked return value.
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
    // SAFETY: successful openat transferred fresh ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}
