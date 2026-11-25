//! Connection-bound process identity. A numeric bus PID is never an acquisition fallback.
use crate::{Error, Result, core::failure};
use lib_sessiond::ErrorCode;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

pub struct Caller {
    fd: OwnedFd,
    pid: u32,
    start_time: u64,
}
impl Caller {
    pub fn acquire(credentials: &zbus::fdo::ConnectionCredentials) -> Result<Self> {
        require_root(credentials)?;
        let fd = credentials
            .process_fd()
            .ok_or_else(|| {
                failure(
                    ErrorCode::ReadinessFailed,
                    "bus ProcessFD credential is required; no PID fallback",
                )
            })?
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| Error::io("retain bus ProcessFD", e))?;
        live(&fd)?;
        // fdinfo resolves this exact pidfd in OUR PID namespace. ProcessID is not used.
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
            .map_err(|e| Error::io("resolve bus ProcessFD", e))?;
        let pid: u32 = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t"))
            .and_then(|pid| pid.parse().ok())
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32)
            .ok_or_else(|| {
                failure(
                    ErrorCode::ProcessNotFound,
                    "bus ProcessFD has no live resolvable process",
                )
            })?;
        let start_time = lib_scoped::read_start_time(pid)
            .map_err(|e| Error::io("read authenticated caller start time", e))?;
        let caller = Self {
            fd,
            pid,
            start_time,
        };
        caller.validate()?;
        Ok(caller)
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn start_time(&self) -> u64 {
        self.start_time
    }
    pub fn validate(&self) -> Result<()> {
        live(&self.fd)?;
        if lib_scoped::read_start_time(self.pid)
            .map_err(|e| Error::io("revalidate authenticated caller", e))?
            != self.start_time
        {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "authenticated caller start time changed",
            ));
        }
        live(&self.fd)
    }
}
pub fn require_root(credentials: &zbus::fdo::ConnectionCredentials) -> Result<()> {
    if credentials.unix_user_id() == Some(0) {
        Ok(())
    } else {
        Err(failure(
            ErrorCode::NotAuthorized,
            "session mutation is root-only",
        ))
    }
}
fn live(fd: &OwnedFd) -> Result<()> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd; nonblocking observation only.
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(Error::io(
            "observe bus ProcessFD",
            io::Error::last_os_error(),
        ));
    }
    if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(failure(ErrorCode::ReadinessFailed, "invalid bus ProcessFD"));
    }
    if poll.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
        return Err(failure(
            ErrorCode::ProcessNotFound,
            "authenticated caller exited",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dead_credential_handles_and_changed_start_time_are_rejected() {
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let process = lib_scoped::ProcessHandle::open(child.id()).unwrap();
        let credentials = zbus::fdo::ConnectionCredentials::default()
            .set_unix_user_id(0)
            .set_process_fd(process.as_fd().try_clone_to_owned().unwrap().into());
        let caller = Caller::acquire(&credentials).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            caller.validate().unwrap_err().public().code,
            ErrorCode::ProcessNotFound
        );
        assert_eq!(
            Caller::acquire(&credentials).err().unwrap().public().code,
            ErrorCode::ProcessNotFound
        );
        let process = lib_scoped::ProcessHandle::open(std::process::id()).unwrap();
        let credentials =
            credentials.set_process_fd(process.as_fd().try_clone_to_owned().unwrap().into());
        let mut caller = Caller::acquire(&credentials).unwrap();
        caller.start_time += 1;
        assert_eq!(
            caller.validate().unwrap_err().public().code,
            ErrorCode::ProcessChanged
        );
    }
    #[test]
    fn no_numeric_pid_fallback_and_root_is_required() {
        let credentials = zbus::fdo::ConnectionCredentials::default()
            .set_unix_user_id(0)
            .set_process_id(std::process::id().saturating_add(1));
        assert_eq!(
            Caller::acquire(&credentials).err().unwrap().public().code,
            ErrorCode::ReadinessFailed
        );
        let process = lib_scoped::ProcessHandle::open(std::process::id()).unwrap();
        let credentials =
            credentials.set_process_fd(process.as_fd().try_clone_to_owned().unwrap().into());
        let caller = Caller::acquire(&credentials).unwrap();
        assert_eq!(caller.pid(), std::process::id());
        caller.validate().unwrap();
        assert_eq!(
            Caller::acquire(&credentials.set_unix_user_id(1000))
                .err()
                .unwrap()
                .public()
                .code,
            ErrorCode::NotAuthorized
        );
    }
}
