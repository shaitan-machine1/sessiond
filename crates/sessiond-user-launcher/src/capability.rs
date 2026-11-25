//! The credential stage sends its own pidfd before any manager work. This binds
//! signalling even if arbitrary private PAM code reaps children or changes SIGCHLD.
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
pub fn send_self(stream: &UnixStream) -> io::Result<()> {
    // SAFETY: self PID is live and controlled by this process.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful syscall returned a fresh owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let fds = [fd.as_raw_fd()];
    let bytes = [IoSlice::new(b"P")];
    let written = sendmsg::<()>(
        stream.as_raw_fd(),
        &bytes,
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(io::Error::from)?;
    if written != 1 {
        return Err(io::Error::other("short manager identity message"));
    }
    Ok(())
}
pub fn receive(stream: &UnixStream, deadline: Instant) -> io::Result<OwnedFd> {
    loop {
        let mut byte = [0];
        let mut ancillary = nix::cmsg_space!([i32; 1]);
        let mut buffers = [IoSliceMut::new(&mut byte)];
        match recvmsg::<()>(
            stream.as_raw_fd(),
            &mut buffers,
            Some(&mut ancillary),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Ok(message) => {
                let mut fds = Vec::new();
                for control in message.cmsgs().map_err(io::Error::from)? {
                    if let ControlMessageOwned::ScmRights(raw) = control {
                        for fd in raw {
                            // SAFETY: recvmsg transfers each SCM_RIGHTS FD exactly once.
                            fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                        }
                    }
                }
                if message.bytes != 1
                    || message.flags.contains(MsgFlags::MSG_CTRUNC)
                    || byte[0] != b'P'
                    || fds.len() != 1
                {
                    return Err(io::Error::other("invalid manager identity capability"));
                }
                let fd = fds.pop().expect("one descriptor");
                signal(&fd, 0)?; // Validate descriptor kind, without sending a signal.
                if !alive(&fd)? {
                    return Err(io::Error::other("manager credential stage exited"));
                }
                return Ok(fd);
            }
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}
pub fn alive(fd: &OwnedFd) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: valid pollfd, nonblocking exact-process observation.
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(io::Error::other("invalid manager process capability"));
    }
    Ok(poll.revents & (libc::POLLIN | libc::POLLHUP) == 0)
}
pub fn wait(fd: &OwnedFd, nonblocking: bool) -> io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;
    // SAFETY: waitid initializes siginfo and targets only this exact pidfd.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let flags = libc::WEXITED | if nonblocking { libc::WNOHANG } else { 0 };
    if unsafe {
        libc::waitid(
            libc::P_PIDFD,
            fd.as_raw_fd() as libc::id_t,
            &mut info,
            flags,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid supplied SIGCHLD-layout siginfo (or the zero no-event state).
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let status = unsafe { info.si_status() };
    let raw = match info.si_code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_KILLED => status,
        libc::CLD_DUMPED => status | 0x80,
        _ => return Err(io::Error::other("unexpected manager wait status")),
    };
    Ok(Some(std::process::ExitStatus::from_raw(raw)))
}
pub fn signal(fd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: exact pidfd signalling; no recycled PID/process-group fallback.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_capability_roundtrips_and_is_close_on_exec() {
        let (parent, child) = UnixStream::pair().unwrap();
        send_self(&child).unwrap();
        let fd = receive(&parent, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(alive(&fd).unwrap());
        // SAFETY: query flags of the live received FD.
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}
