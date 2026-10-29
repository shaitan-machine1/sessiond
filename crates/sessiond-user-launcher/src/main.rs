use anyhow::Context;
use clap::Parser;
use lib_scoped::{Domain, ProcessIdentity, ScopeId, TargetId, read_start_time, well_known};
use lib_sessiond::launcher_protocol as protocol;
use nix::unistd::{Uid, User};
use pam_ffi::Transaction;
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
    #[arg(long)]
    service_scope: Option<String>,
    #[arg(long, default_value_t = 30_000)]
    ready_timeout_ms: u64,
    /// A second post-exec stage isolates credential setup even if a private
    /// PAM module made the manager-owning launcher multithreaded.
    #[arg(long, hide = true)]
    run_manager: bool,
}
extern "C" fn termination_handler(_: libc::c_int) {
    TERMINATE.store(true, Ordering::Relaxed);
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // SAFETY: geteuid has no arguments or side effects.
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "launcher requires effective UID 0"
    );
    anyhow::ensure!(
        args.entrypoint.is_absolute(),
        "manager entrypoint must be absolute"
    );
    if args.run_manager {
        return exec_manager(&args);
    }
    anyhow::ensure!(
        args.ready_timeout_ms > 0,
        "readiness deadline must be nonzero"
    );
    set_cloexec(3, true)?;
    // SAFETY: lib-sessiond explicitly passed the unique coordination socket at 3.
    let mut status = unsafe { UnixStream::from_raw_fd(3) };
    install_handlers()?;
    let scope = ScopeId::parse(
        args.service_scope
            .as_deref()
            .context("--service-scope is required")?,
    )?;
    anyhow::ensure!(
        scope == well_known::sessiond_user_service(args.uid),
        "incorrect manager service scope"
    );
    let domain = Domain::open(&args.cgroup_root, "sessiond")?;
    let pinned = domain.pin_scope(&scope)?;
    // This helper is single-threaded, post-exec, and has not called PAM. No
    // held UID lock, original PAM descriptors or root bus connection survived exec.
    // SAFETY: the fresh helper has no other threads/held userspace library locks.
    let final_pid = unsafe { libc::fork() };
    if final_pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork final launcher");
    }
    if final_pid > 0 {
        // SAFETY: short-lived helper exits without Rust/library teardown. The
        // original login host reaps it; final launcher goes to its actual adopter.
        unsafe { libc::_exit(0) };
    }
    // SAFETY: the freshly forked child is not a process-group leader.
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error()).context("detach launcher session");
    }
    let result = (|| {
        let pid = std::process::id();
        let hello = protocol::Hello {
            process: ProcessIdentity {
                pid,
                start_time: read_start_time(pid)?,
            },
            scope: pinned.identity(),
        };
        send(&mut status, &hello.encode())?;
        gate(&mut status, protocol::MIGRATE)?;
        // These ordinary APIs use a pinned scope generation, not a self-move
        // special case. A late helper cannot enter a replacement service scope.
        pinned.move_process(pid)?;
        pinned.assign_target(&TargetId::parse("manager")?, pid)?;
        send(&mut status, protocol::REGISTERED)?;
        gate(&mut status, protocol::START)?;
        serve(&args, &mut status)
    })();
    if let Err(error) = &result {
        let text = format!("ERROR {error:#}").replace(['\n', '\r'], " ");
        let text: String = text.chars().take(1024).collect();
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
            "launcher cancelled before startup"
        );
        match status.read(&mut byte) {
            Ok(1) if byte[0] == expected => return Ok(()),
            Ok(0) => anyhow::bail!("opening host disappeared before startup authorization"),
            Ok(_) => anyhow::bail!("invalid startup authorization"),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read startup authorization"),
        }
    }
}
fn serve(args: &Args, outer_status: &mut UnixStream) -> anyhow::Result<()> {
    let user = User::from_uid(Uid::from_raw(args.uid))?.context("unknown manager UID")?;
    anyhow::ensure!(!TERMINATE.load(Ordering::Relaxed), "launcher cancelled");
    let mut pam = Transaction::start(&args.pam_service, &user.name)
        .map_err(|s| anyhow::anyhow!("private pam_start failed: {s}"))?;
    pam.open_session()
        .map_err(|s| anyhow::anyhow!("private pam_open_session failed: {s}"))?;
    anyhow::ensure!(
        !TERMINATE.load(Ordering::Relaxed),
        "launcher cancelled during private PAM"
    );
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
    let mut child = ManagedChild {
        child,
        reaped: false,
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(args.ready_timeout_ms))
        .context("readiness deadline overflow")?;
    let mut byte = [0];
    loop {
        match ready.read(&mut byte) {
            Ok(1) => break,
            Ok(0) => anyhow::bail!("manager closed readiness channel"),
            Ok(_) => unreachable!(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
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
    drop(ready); // One byte is opaque; do not drain extra manager payload.
    send(outer_status, protocol::READY)?;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                eprintln!("sessiond-user-launcher: manager exited with {status}");
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
    child: Child,
    reaped: bool,
}
impl ManagedChild {
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }
    fn terminate(&self) -> anyhow::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let pid = i32::try_from(self.child.id())?;
        // The directly owned child remains unreaped, so its PID/group cannot
        // be recycled. Its post-exec credential stage establishes this group.
        // SAFETY: negative PID addresses that child-controlled process group.
        if unsafe { libc::kill(-pid, libc::SIGTERM) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
            // The child may not have established its group yet. Pin and signal
            // that exact process; no recycled numeric-PID signalling fallback.
            match lib_scoped::ProcessHandle::open(self.child.id()) {
                Ok(handle) => {
                    let _ = handle.send_terminate();
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let pid = self.child.id() as i32;
            // SAFETY: unreaped owned child pins the process/group ID. This is
            // startup/error cleanup; normal configured teardown signals us.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Credential lookup and privilege drop occur after this second exec, never in
/// a pre_exec closure following arbitrary private PAM modules.
fn exec_manager(args: &Args) -> anyhow::Result<()> {
    let user = User::from_uid(Uid::from_raw(args.uid))?.context("unknown manager UID")?;
    let name = CString::new(user.name)?;
    reset_signals()?;
    set_cloexec(3, false)?;
    // SAFETY: post-exec credential stage owns the process and has no PAM state.
    unsafe {
        if libc::setpgid(0, 0) < 0
            || libc::initgroups(name.as_ptr(), user.gid.as_raw()) < 0
            || libc::setgid(user.gid.as_raw()) < 0
            || libc::setuid(args.uid) < 0
        {
            return Err(std::io::Error::last_os_error()).context("set manager credentials");
        }
    }
    let error = Command::new(&args.entrypoint)
        .arg("--ready-fd")
        .arg("3")
        .exec();
    Err(error).context("exec user service manager")
}
fn set_cloexec(fd: i32, enabled: bool) -> std::io::Result<()> {
    // SAFETY: operates only on explicitly passed descriptors.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: descriptor was validated by F_GETFD.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn reset_signals() -> std::io::Result<()> {
    // SAFETY: this runs after exec in the dedicated process, not the PAM host.
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
    // SAFETY: the signal handler only stores to a lock-free AtomicBool. All
    // dispositions are changed in the dedicated post-exec process, never host.
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
