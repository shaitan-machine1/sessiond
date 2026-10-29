//! Linux process-instance handles used by tracked targets.
//!
//! A numeric PID alone is not an identity: it can be recycled. We pair a
//! pidfd with `/proc/<pid>/stat`'s start-time field so bindings can be stored
//! durably and reconstructed independently of any daemon.

use super::Pid;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use rustix::fd::{AsFd, OwnedFd};
use rustix::process::{PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: Pid,
    pub start_time: u64,
}

#[derive(Debug)]
pub struct ProcessHandle {
    identity: ProcessIdentity,
    pidfd: OwnedFd,
}

impl ProcessHandle {
    /// Pins the process currently named by `pid` and records its start time.
    /// The final liveness check is important: the process may have exited and
    /// its number may have been reused while `/proc/<pid>/stat` was read.
    pub fn open(pid: Pid) -> io::Result<Self> {
        let raw = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "pid must be positive"))?;
        let pidfd = pidfd_open(raw, PidfdFlags::empty()).map_err(|errno| {
            if errno == rustix::io::Errno::SRCH {
                io::Error::new(io::ErrorKind::NotFound, errno_to_io(errno))
            } else {
                errno_to_io(errno)
            }
        })?;
        let start_time = read_start_time(pid)?;
        let handle = ProcessHandle {
            identity: ProcessIdentity { pid, start_time },
            pidfd,
        };
        if !handle.is_alive()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} exited while its identity was being read"),
            ));
        }
        Ok(handle)
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Whether this exact process instance is still alive.
    pub fn is_alive(&self) -> io::Result<bool> {
        let mut fds = [PollFd::new(
            self.pidfd.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        poll(&mut fds, PollTimeout::ZERO)?;
        let events = fds[0].revents().unwrap_or_else(PollFlags::empty);
        if events.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
            return Err(io::Error::other("invalid or failed pidfd observation"));
        }
        Ok(!events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
    }

    /// Revalidates the durable `(pid, start_time)` identity.
    pub fn identity_still_matches(&self) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        match read_start_time(self.identity.pid) {
            Ok(start) => Ok(start == self.identity.start_time && self.is_alive()?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn send_terminate(&self) -> io::Result<()> {
        pidfd_send_signal(&self.pidfd, Signal::TERM).map_err(errno_to_io)
    }

    pub fn send_kill(&self) -> io::Result<()> {
        pidfd_send_signal(&self.pidfd, Signal::KILL).map_err(errno_to_io)
    }
}

impl AsFd for ProcessHandle {
    fn as_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

/// Reads field 22 (`starttime`) from `/proc/<pid>/stat`.
///
/// The process name in field 2 is parenthesized and may itself contain spaces
/// or `)`, so parsing starts after the final `)` rather than splitting the
/// whole line on whitespace.
pub fn read_start_time(pid: Pid) -> io::Result<u64> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} does not exist"),
            )
        } else {
            e
        }
    })?;
    let close = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path} has no closing process-name parenthesis"),
        )
    })?;
    // After the command name, token 0 is field 3 (`state`), so field 22 is
    // token 19.
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("short {path}")))?
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn errno_to_io(errno: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn own_process_has_a_stable_live_identity() {
        let handle = ProcessHandle::open(std::process::id()).unwrap();
        assert_eq!(handle.identity().pid, std::process::id());
        assert!(handle.identity().start_time > 0);
        assert!(handle.identity_still_matches().unwrap());
    }

    #[test]
    fn exited_process_makes_its_pidfd_readable() {
        let mut child = Command::new("sleep")
            .arg("300")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let handle = ProcessHandle::open(child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        for _ in 0..100 {
            if !handle.is_alive().unwrap() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("pidfd never reported process exit");
    }
}
