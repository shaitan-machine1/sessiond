//! Owned runtime-directory deletion. Never follow symlinks or cross mounts.
use crate::{Error, Result, locking};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) fn ensure(parent: &Path, uid: u32, gid: u32) -> Result<PathBuf> {
    let directory = locking::secure_directory_mode(parent, true, 0o755)
        .map_err(|e| Error::io("open/create runtime parent", e))?;
    let stat = directory
        .metadata()
        .map_err(|e| Error::io("stat runtime parent", e))?;
    if stat.uid() != 0 || stat.mode() & 0o022 != 0 {
        return Err(Error::io(
            "validate runtime parent",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime parent must be root-controlled",
            ),
        ));
    }
    ensure_owned(&directory, uid, gid).map_err(|e| Error::io("ensure runtime directory", e))?;
    Ok(parent.join(uid.to_string()))
}
fn ensure_owned(parent: &File, uid: u32, gid: u32) -> io::Result<()> {
    let name = CString::new(uid.to_string()).expect("numeric UID");
    // SAFETY: pinned parent descriptor and canonical numeric C name.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
    if !created {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let directory = open_child(parent, &name)?;
    if created {
        // SAFETY: fchown operates on the pinned newly created directory only.
        if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    let metadata = directory.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must belong to UID and have mode 0700",
        ));
    }
    Ok(())
}

pub(crate) fn remove(parent: &Path, uid: u32) -> Result<()> {
    let parent = match locking::secure_directory(parent, false) {
        Ok(parent) => parent,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io("open runtime parent", e)),
    };
    let stat = parent
        .metadata()
        .map_err(|e| Error::io("stat runtime parent", e))?;
    if stat.uid() != 0 || stat.mode() & 0o022 != 0 {
        return Err(Error::io(
            "validate runtime parent",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime parent must be root-controlled",
            ),
        ));
    }
    remove_owned(&parent, uid)
        .map_err(|e| Error::io(format!("remove runtime directory for UID {uid}"), e))
}

fn remove_owned(parent: &File, uid: u32) -> io::Result<()> {
    let name = CString::new(uid.to_string()).expect("numeric UID");
    let directory = match open_child(parent, &name) {
        Ok(directory) => directory,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let metadata = directory.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must belong to UID and have mode 0700",
        ));
    }
    remove_contents(&directory)?;
    unlink(parent, &name, libc::AT_REMOVEDIR)
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn open_child(parent: &File, name: &CStr) -> io::Result<File> {
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        // Linux openat2: RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        resolve: 0x01 | 0x04 | 0x08,
    };
    // SAFETY: valid descriptors/C string, Linux open_how ABI and checked result.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat2 returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn unlink(parent: &File, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: pinned directory and valid relative C name; does not follow links.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}
fn remove_contents(directory: &File) -> io::Result<()> {
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let entry = entry?;
        let name = CString::new(entry.file_name().as_encoded_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if kind.is_dir() {
            let child = match open_child(directory, &name) {
                Ok(child) => child,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            remove_contents(&child)?;
            unlink(directory, &name, libc::AT_REMOVEDIR)?;
        } else {
            unlink(directory, &name, 0)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn owned_runtime_is_created_and_reused_without_repairing_unsafe_nodes() {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let stat = parent.metadata().unwrap();
        let uid = stat.uid();
        ensure_owned(&parent, uid, stat.gid()).unwrap();
        ensure_owned(&parent, uid, stat.gid()).unwrap();
        let path = root.path().join(uid.to_string());
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o700);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_owned(&parent, uid, stat.gid()).is_err());
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o755);
    }
    #[test]
    fn owned_runtime_removal_never_follows_contents_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let uid = parent.metadata().unwrap().uid();
        let runtime = root.path().join(uid.to_string());
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), "foreign").unwrap();
        fs::create_dir(runtime.join("nested")).unwrap();
        fs::write(runtime.join("nested/file"), "owned").unwrap();
        symlink(outside.path(), runtime.join("foreign")).unwrap();
        remove_owned(&parent, uid).unwrap();
        assert!(!runtime.exists());
        assert_eq!(
            fs::read_to_string(outside.path().join("keep")).unwrap(),
            "foreign"
        );
        remove_owned(&parent, uid).unwrap();
    }
    #[test]
    fn runtime_root_symlinks_and_unsafe_modes_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let uid = parent.metadata().unwrap().uid();
        let runtime = root.path().join(uid.to_string());
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), &runtime).unwrap();
        assert!(remove_owned(&parent, uid).is_err());
        fs::remove_file(&runtime).unwrap();
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(remove_owned(&parent, uid).is_err());
        assert!(runtime.exists());
    }
}
