//! Shared synchronous launcher protocol. These are executable coordination
//! details, not session lifecycle records or a manager-health database.
use lib_scoped::{ProcessIdentity, ScopeIdentity};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

pub const MIGRATE: u8 = b'M';
pub const START: u8 = b'S';
pub const REGISTERED: &str = "REGISTERED";
pub const READY: &str = "READY";
pub const MAX_MESSAGE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub process: ProcessIdentity,
    pub scope: ScopeIdentity,
}
impl Hello {
    pub fn encode(self) -> String {
        format!(
            "HELLO 1 {} {} {} {}",
            self.process.pid, self.process.start_time, self.scope.device, self.scope.inode
        )
    }
    pub fn parse(message: &str) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid launcher HELLO/version");
        let mut fields = message.split_whitespace();
        if fields.next() != Some("HELLO") || fields.next() != Some("1") {
            return Err(bad());
        }
        let pid = fields
            .next()
            .ok_or_else(bad)?
            .parse::<u32>()
            .map_err(|_| bad())?;
        let start_time = fields
            .next()
            .ok_or_else(bad)?
            .parse::<u64>()
            .map_err(|_| bad())?;
        let device = fields
            .next()
            .ok_or_else(bad)?
            .parse::<u64>()
            .map_err(|_| bad())?;
        let inode = fields
            .next()
            .ok_or_else(bad)?
            .parse::<u64>()
            .map_err(|_| bad())?;
        if fields.next().is_some() || pid == 0 || pid > i32::MAX as u32 || inode == 0 {
            return Err(bad());
        }
        Ok(Self {
            process: ProcessIdentity { pid, start_time },
            scope: ScopeIdentity { device, inode },
        })
    }
}

/// Exec with exactly one explicitly passed descriptor at fd 3. All other
/// descriptors >=4 are close-on-exec, including UID locks, root bus connections,
/// and unrelated PAM-module descriptors. No allocation/credential setup occurs
/// in pre_exec, which may run in a multithreaded PAM host.
pub fn spawn_with_fd(mut command: Command, source: BorrowedFd<'_>) -> io::Result<Child> {
    // Duplicate away from stdio *before* Command configures child stdin/out/err.
    // The caller may originally have had one or more standard descriptors shut.
    // SAFETY: fcntl duplicates a live descriptor and returns fresh ownership.
    let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC produced this owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let raw = owned.as_raw_fd();
    // SAFETY: only raw dup/fcntl/close_range syscalls between fork and exec.
    // The duplicate remains owned in this process until spawn completes.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            // CLOSE_RANGE_CLOEXEC, Linux >=5.11. This also retains Rust's exec
            // error pipe until exec, so failed exec still reaches the parent.
            if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 1u32 << 2) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn();
    drop(owned);
    child
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    #[test]
    fn hello_roundtrips_and_rejects_invalid_messages() {
        let hello = Hello {
            process: ProcessIdentity {
                pid: 123,
                start_time: 456,
            },
            scope: ScopeIdentity {
                device: 0,
                inode: 789,
            },
        };
        assert_eq!(Hello::parse(&hello.encode()).unwrap(), hello);
        for bad in [
            "HELLO 2 1 2 3 4",
            "HELLO 1 0 2 3 4",
            "HELLO 1 1 2 3 0",
            "HELLO 1 1 2",
            "HELLO 1 1 2 3 4 extra",
        ] {
            assert!(Hello::parse(bad).is_err());
        }
    }
    #[test]
    fn explicit_descriptor_survives_exec() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        let mut command = Command::new("sh");
        command
            .args(["-c", "printf hello >&3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut helper = spawn_with_fd(command, child.as_fd()).unwrap();
        drop(child);
        let mut message = String::new();
        parent.read_to_string(&mut message).unwrap();
        assert_eq!(message, "hello");
        assert!(helper.wait().unwrap().success());
    }
}
