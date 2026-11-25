//! Private server/worker codec and exec FD boundary, not a public SDK interface.
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
pub const START: u8 = b'S';
pub const READY: &str = "READY";
pub const MAX_MESSAGE: usize = 4096;

/// Pass only the explicit coordination FD at 3. Credential/NSS/PAM work happens
/// after exec, not in this multithreaded parent's fork-to-exec interval.
pub fn spawn_with_fd(mut command: Command, source: BorrowedFd<'_>) -> io::Result<Child> {
    // SAFETY: duplicate a live descriptor away from stdio before Command setup.
    let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fcntl transferred new owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let raw = owned.as_raw_fd();
    // SAFETY: only async-signal-safe raw syscalls between fork and exec; the
    // caller-owned duplicate remains alive until spawn completes.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 1u32 << 2) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    #[test]
    fn only_explicit_coordination_descriptor_survives_exec() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        let secret = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: intentionally create a non-CLOEXEC fixture FD, like arbitrary
        // private PAM code could. Only the child exec boundary may sanitize it.
        let raw = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(raw >= 100);
        let secret = unsafe { OwnedFd::from_raw_fd(raw) };
        let script = format!("[ ! -e /proc/self/fd/{raw} ] && printf hello >&3");
        let mut command = Command::new("sh");
        command
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut helper = spawn_with_fd(command, child.as_fd()).unwrap();
        drop(child);
        let mut message = String::new();
        parent.read_to_string(&mut message).unwrap();
        assert_eq!(message, "hello");
        assert!(helper.wait().unwrap().success());
        assert_eq!(
            unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}
