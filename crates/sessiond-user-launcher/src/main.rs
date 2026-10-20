use anyhow::Context;
use clap::Parser;
use nix::unistd::{Uid, User};
use pam_ffi::Transaction;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
}

extern "C" fn termination_handler(_signal: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    set_cloexec(3)?;
    set_cloexec(4)?;
    // SAFETY: fd 3 is the gate installed by sessiond and uniquely owned here.
    let mut gate = unsafe { File::from_raw_fd(3) };
    let mut byte = [0];
    gate.read_exact(&mut byte).context("read start gate")?;
    anyhow::ensure!(byte[0] == 1, "invalid start-gate byte");
    drop(gate);

    let uid = Uid::from_raw(args.uid);
    let user = User::from_uid(uid)?.ok_or_else(|| anyhow::anyhow!("unknown uid {}", args.uid))?;
    let username = user.name.clone();
    let mut pam = Transaction::start(&args.pam_service, &username)
        .map_err(|status| anyhow::anyhow!("pam_start failed: {status}"))?;
    pam.open_session()
        .map_err(|status| anyhow::anyhow!("pam_open_session failed: {status}"))?;

    install_handlers()?;
    let (readiness_read, readiness_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
    let readiness_write_raw = readiness_write.into_raw_fd();
    let username_c = CString::new(username.clone())?;
    let gid = user.gid.as_raw();
    let uid = uid.as_raw();
    let mut command = Command::new(&args.entrypoint);
    command
        .env_clear()
        .env("HOME", &user.dir)
        .env("USER", &username)
        .env("LOGNAME", &username)
        .env("SHELL", &user.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", user.dir.join(".config"))
        .env("XDG_RUNTIME_DIR", &args.runtime_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", args.runtime_dir.display()),
        )
        .env("SESSIOND_READY_FD", "5");
    // SAFETY: this dedicated launcher is single-threaded. The operations are
    // precisely the child credential/process-group setup before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(readiness_write_raw, 5) == -1
                || libc::fcntl(5, libc::F_SETFD, 0) == -1
                || libc::setpgid(0, 0) == -1
                || libc::initgroups(username_c.as_ptr(), gid) == -1
                || libc::setgid(gid) == -1
                || libc::setuid(uid) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            let empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("start user service manager")?;
    // SAFETY: parent owns the original raw descriptor after into_raw_fd.
    unsafe { libc::close(readiness_write_raw) };

    let mut readiness_read = File::from(readiness_read);
    set_nonblocking(&readiness_read)?;
    loop {
        match readiness_read.read(&mut byte) {
            Ok(1) => break,
            Ok(0) => anyhow::bail!("user manager closed readiness channel"),
            Ok(_) => unreachable!(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("user manager readiness"),
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("user manager exited before readiness: {status}");
        }
        if TERMINATE.swap(false, Ordering::SeqCst) {
            terminate_child_group(child.id())?;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::ensure!(byte[0] == 1, "invalid user-manager readiness byte");
    // SAFETY: fd 4 is the readiness channel installed by sessiond.
    let mut outer_ready = unsafe { File::from_raw_fd(4) };
    outer_ready.write_all(&[1])?;
    drop(outer_ready);

    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                eprintln!("sessiond-user-launcher: manager exited with {status}");
            }
            break;
        }
        if TERMINATE.swap(false, Ordering::SeqCst) {
            terminate_child_group(child.id())?;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    pam.close_session()
        .map_err(|status| anyhow::anyhow!("pam_close_session failed: {status}"))?;
    Ok(())
}

fn set_cloexec(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: fcntl operates on inherited descriptor numbers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_nonblocking(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: fcntl operates on the live pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn terminate_child_group(child: u32) -> anyhow::Result<()> {
    let pid = i32::try_from(child).context("child pid overflow")?;
    // SAFETY: negative pid addresses the process group created in pre_exec.
    if unsafe { libc::kill(-pid, libc::SIGTERM) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn install_handlers() -> std::io::Result<()> {
    // SAFETY: handler only stores to an AtomicBool and is async-signal-safe.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = termination_handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) == -1
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) == -1
            || libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
