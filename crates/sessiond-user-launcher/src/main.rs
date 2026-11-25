use anyhow::Context;
use clap::Parser;
use nix::unistd::{Uid, User};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
mod capability;
mod pam;
#[path = "../../../protocol/worker.rs"]
mod protocol;
static TERMINATE: AtomicBool = AtomicBool::new(false);
#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    uid: u32,
    #[arg(long)]
    runtime_dir: PathBuf,
    #[arg(long)]
    entrypoint: PathBuf,
    #[arg(long, default_value = "sessiond-user")]
    pam_service: String,
    #[arg(long, default_value_t = 30_000)]
    ready_timeout_ms: u64,
    #[arg(long, hide = true)]
    run_manager: bool,
}
extern "C" fn termination_handler(_: i32) {
    TERMINATE.store(true, Ordering::Relaxed);
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // SAFETY: geteuid has no arguments/side effects.
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "launcher requires effective UID 0"
    );
    anyhow::ensure!(
        args.entrypoint.is_absolute() && args.runtime_dir.is_absolute(),
        "manager and runtime paths must be absolute"
    );
    if args.run_manager {
        return exec_manager(&args);
    }
    anyhow::ensure!(
        args.ready_timeout_ms > 0,
        "readiness timeout must be nonzero"
    );
    set_cloexec(3, true)?;
    // SAFETY: daemon passes the unique coordination descriptor at fd 3.
    let mut status = unsafe { UnixStream::from_raw_fd(3) };
    install_handlers()?;
    // No fork/detachment or scoped access: parent-owned placement and master
    // publication have completed before this gate authorizes arbitrary PAM.
    gate(&mut status, protocol::START)?;
    let result = serve(&args, &mut status);
    if let Err(error) = &result {
        let text: String = format!("ERROR {error:#}")
            .replace(['\n', '\r'], " ")
            .chars()
            .take(protocol::MAX_MESSAGE / 4)
            .collect();
        let _ = send(&mut status, &text);
    }
    result
}
fn send(status: &mut UnixStream, message: &str) -> anyhow::Result<()> {
    status.write_all(message.as_bytes())?;
    status.write_all(b"\n")?;
    Ok(())
}
fn gate(status: &mut UnixStream, expected: u8) -> anyhow::Result<()> {
    let mut byte = [0];
    loop {
        anyhow::ensure!(
            !TERMINATE.load(Ordering::Relaxed),
            "worker cancelled before authorization"
        );
        match status.read(&mut byte) {
            Ok(1) if byte[0] == expected => return Ok(()),
            Ok(0) => anyhow::bail!("EOF before startup authorization"),
            Ok(_) => anyhow::bail!("invalid startup authorization"),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read startup authorization"),
        }
    }
}
fn serve(args: &Args, status: &mut UnixStream) -> anyhow::Result<()> {
    let user = User::from_uid(Uid::from_raw(args.uid))?.context("unknown manager UID")?;
    anyhow::ensure!(!TERMINATE.load(Ordering::Relaxed), "launcher cancelled");
    let mut pam = pam::Transaction::start(&args.pam_service, &user.name)
        .map_err(|s| anyhow::anyhow!("private pam_start failed: {s}"))?;
    pam.open_session()
        .map_err(|s| anyhow::anyhow!("private pam_open_session failed: {s}"))?;
    anyhow::ensure!(
        !TERMINATE.load(Ordering::Relaxed),
        "launcher cancelled during PAM"
    );
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(args.ready_timeout_ms))
        .context("readiness deadline overflow")?;
    let (mut ready, ready_child) = UnixStream::pair()?;
    ready.set_nonblocking(true)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--run-manager")
        .arg("--uid")
        .arg(args.uid.to_string())
        .arg("--runtime-dir")
        .arg(&args.runtime_dir)
        .arg("--entrypoint")
        .arg(&args.entrypoint)
        .env_clear()
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &user.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", user.dir.join(".config"))
        .env("XDG_RUNTIME_DIR", &args.runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child =
        protocol::spawn_with_fd(command, ready_child.as_fd()).context("exec credential stage")?;
    drop(ready_child);
    // The child sends its OWN pidfd. Never acquire authority from its possibly
    // reaped/recycled numeric PID after arbitrary private PAM code ran.
    let pidfd =
        capability::receive(&ready, deadline).context("receive credential-stage identity")?;
    let mut child = ManagedChild {
        _child: child,
        pidfd,
        reaped: false,
    };
    ready.write_all(&[protocol::START])?;
    let mut byte = [0];
    loop {
        match ready.read(&mut byte) {
            Ok(1) => break,
            Ok(0) => anyhow::bail!("manager closed readiness channel"),
            Ok(_) => unreachable!(),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read manager readiness"),
        }
        anyhow::ensure!(
            child.try_wait()?.is_none(),
            "manager exited before readiness"
        );
        anyhow::ensure!(
            Instant::now() < deadline,
            "manager readiness deadline exceeded"
        );
        if TERMINATE.swap(false, Ordering::Relaxed) {
            child.terminate()?;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    anyhow::ensure!(
        capability::alive(&child.pidfd)?,
        "manager exited at readiness"
    );
    drop(ready);
    send(status, protocol::READY)?;
    loop {
        if let Some(exit) = child.try_wait()? {
            if !exit.success() {
                eprintln!("sessiond-user-launcher: manager exited with {exit}");
            }
            break;
        }
        if TERMINATE.swap(false, Ordering::Relaxed) {
            child.terminate()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    pam.close_session()
        .map_err(|s| anyhow::anyhow!("private pam_close_session failed: {s}"))?;
    Ok(())
}
struct ManagedChild {
    _child: Child,
    pidfd: OwnedFd,
    reaped: bool,
}
impl ManagedChild {
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match capability::wait(&self.pidfd, true) {
            Ok(status) => {
                if status.is_some() {
                    self.reaped = true;
                }
                Ok(status)
            }
            Err(error) => {
                if error.raw_os_error() == Some(libc::ECHILD) && !capability::alive(&self.pidfd)? {
                    self.reaped = true;
                }
                Err(error) // An external reaper is not an invented successful exit status.
            }
        }
    }
    fn terminate(&self) -> std::io::Result<()> {
        capability::signal(&self.pidfd, libc::SIGTERM)
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = capability::signal(&self.pidfd, libc::SIGKILL);
            let _ = capability::wait(&self.pidfd, false);
        }
        // Descendant cleanup belongs to daemon-owned service-subtree drain,
        // never a potentially recycled numeric process-group ID.
    }
}
fn exec_manager(args: &Args) -> anyhow::Result<()> {
    // SAFETY: this post-exec stage owns the explicitly passed fd 3.
    let mut coordination = unsafe { UnixStream::from_raw_fd(3) };
    capability::send_self(&coordination)?;
    gate(&mut coordination, protocol::START)?;
    let fd = coordination.into_raw_fd();
    anyhow::ensure!(fd == 3, "unexpected readiness descriptor");
    let user = User::from_uid(Uid::from_raw(args.uid))?.context("unknown manager UID")?;
    let name = CString::new(user.name)?;
    reset_signals()?;
    set_cloexec(3, false)?;
    // SAFETY: credential/NSS work runs only after exec, without inherited PAM state.
    unsafe {
        if libc::setpgid(0, 0) < 0
            || libc::initgroups(name.as_ptr(), user.gid.as_raw()) < 0
            || libc::setgid(user.gid.as_raw()) < 0
            || libc::setuid(args.uid) < 0
        {
            return Err(std::io::Error::last_os_error()).context("set manager credentials");
        }
    }
    Err(Command::new(&args.entrypoint)
        .arg("--ready-fd")
        .arg("3")
        .exec())
    .context("exec user service manager")
}
fn set_cloexec(fd: i32, enabled: bool) -> std::io::Result<()> {
    // SAFETY: query/update only this explicitly passed descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn reset_signals() -> std::io::Result<()> {
    // SAFETY: dedicated post-exec process, never a PAM embedding application.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        if libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        for signal in [
            libc::SIGCHLD,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGHUP,
            libc::SIGPIPE,
        ] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
fn install_handlers() -> std::io::Result<()> {
    reset_signals()?;
    // SAFETY: dedicated process handlers only store a lock-free atomic.
    unsafe {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = termination_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
