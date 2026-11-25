use crate::{
    Error, Result, SessionCore, config::Config, core::master, shutdown, worker_protocol as protocol,
};
use lib_scoped::{Domain, ScopeId, TargetStatus, well_known};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
const USER_SERVICE_MANAGER: &str = match option_env!("SESSIOND_USER_SERVICE_MANAGER") {
    Some(path) => path,
    None => "/usr/libexec/user-service-manager",
};

/// NSS runs only in a fresh exec'd helper, including below the manager threshold.
/// It does not require a manager executable, launcher or writable home.
pub(crate) fn lookup_gid(config: &Config, uid: u32) -> Result<u32> {
    let deadline = Instant::now()
        .checked_add(config.user_service_manager.ready_timeout)
        .ok_or_else(|| Error::Startup("NSS deadline overflow".into()))?;
    let mut child = Command::new(
        std::env::current_exe().map_err(|e| Error::io("resolve NSS helper executable", e))?,
    )
    .arg("--lookup-gid")
    .arg(uid.to_string())
    .env_clear()
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| Error::io("exec NSS helper", e))?;
    loop {
        match child
            .try_wait()
            .map_err(|e| Error::io("reap NSS helper", e))?
        {
            Some(status) => {
                if !status.success() {
                    return Err(Error::Startup(format!(
                        "account lookup for UID {uid} failed"
                    )));
                }
                let mut output = String::new();
                let stdout = child.stdout.take().expect("piped stdout");
                // SAFETY: live pipe; never block if an NSS-created descendant retained it.
                if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                    return Err(Error::io(
                        "configure NSS helper output",
                        io::Error::last_os_error(),
                    ));
                }
                stdout
                    .take(64)
                    .read_to_string(&mut output)
                    .map_err(|e| Error::io("read NSS helper result", e))?;
                return output
                    .trim()
                    .parse()
                    .map_err(|_| Error::Startup("invalid NSS helper GID".into()));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                child
                    .wait()
                    .map_err(|e| Error::io("reap timed-out NSS helper", e))?;
                return Err(Error::Startup("account lookup deadline exceeded".into()));
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
pub(crate) fn ensure_manager(
    core: &SessionCore,
    domain: &Domain,
    uid: u32,
    runtime: &Path,
) -> Result<Vec<String>> {
    if uid < core.config.user_service_manager.min_uid {
        return Ok(Vec::new());
    }
    let service = well_known::sessiond_user_service(uid);
    if matches!(
        domain.target_status(&service, &master())?,
        TargetStatus::Running(_)
    ) {
        return Ok(Vec::new());
    }
    let warnings = shutdown::shutdown(
        domain,
        &service,
        &master(),
        &core.config.user_service_manager.shutdown,
    )?;
    domain.create_scope(&service)?;
    if let Err(startup) = launch(core, domain, &service, uid, runtime) {
        return match shutdown::shutdown(
            domain,
            &service,
            &master(),
            &core.config.user_service_manager.shutdown,
        ) {
            Ok(_) => Err(startup),
            Err(cleanup) => Err(Error::Startup(format!(
                "{startup}; failed-start cleanup incomplete: {cleanup}"
            ))),
        };
    }
    Ok(warnings)
}
fn launch(
    core: &SessionCore,
    domain: &Domain,
    service: &ScopeId,
    uid: u32,
    runtime: &Path,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(core.config.user_service_manager.ready_timeout)
        .ok_or_else(|| Error::Startup("manager deadline overflow".into()))?;
    let pinned = domain.pin_scope(service)?;
    let (mut parent, child_socket) =
        UnixStream::pair().map_err(|e| Error::io("create worker socket", e))?;
    parent
        .set_nonblocking(true)
        .map_err(|e| Error::io("configure worker socket", e))?;
    let mut command = Command::new(&core.config.user_service_manager.launcher);
    command
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--runtime-dir")
        .arg(runtime)
        .arg("--entrypoint")
        .arg(USER_SERVICE_MANAGER)
        .arg("--pam-service")
        .arg(&core.config.user_service_manager.pam_service)
        .arg("--ready-timeout-ms")
        .arg(
            core.config
                .user_service_manager
                .ready_timeout
                .as_millis()
                .to_string(),
        )
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = protocol::spawn_with_fd(command, child_socket.as_fd())
        .map_err(|e| Error::io("exec manager worker", e))?;
    drop(child_socket);
    // The daemon owns SIGCHLD and has not reaped this direct child. Its PID
    // cannot be recycled across parent-owned placement and master publication.
    let result = (|| {
        if child
            .try_wait()
            .map_err(|e| Error::io("check worker before placement", e))?
            .is_some()
        {
            return Err(Error::Startup("worker exited before placement".into()));
        }
        pinned.move_process(child.id())?;
        pinned.assign_target(&master(), child.id())?;
        parent
            .write_all(&[protocol::START])
            .map_err(|e| Error::io("authorize private PAM startup", e))?;
        let message = read_message(&mut parent, deadline)?;
        if message != protocol::READY {
            return Err(Error::Startup(format!("manager worker: {message}")));
        }
        if child
            .try_wait()
            .map_err(|e| Error::io("check ready worker", e))?
            .is_some()
        {
            return Err(Error::Startup("worker exited at readiness".into()));
        }
        Ok(())
    })();
    drop(parent);
    // Retain direct-child reaping ownership through normal manager lifetime or
    // failed-start subtree cleanup; the observer thread reaps exited workers.
    core.children
        .lock()
        .expect("child registry poisoned")
        .push(child);
    result
}
fn read_message(stream: &mut UnixStream, deadline: Instant) -> Result<String> {
    let mut message = Vec::new();
    loop {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return Err(Error::Startup("worker EOF before readiness".into())),
            Ok(_) if byte[0] == b'\n' => {
                return String::from_utf8(message)
                    .map_err(|_| Error::Startup("non-UTF8 worker response".into()));
            }
            Ok(_) => {
                message.push(byte[0]);
                if message.len() > protocol::MAX_MESSAGE {
                    return Err(Error::Startup("worker response exceeds limit".into()));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("read worker readiness", e)),
        }
        if Instant::now() >= deadline {
            return Err(Error::Startup("manager readiness deadline exceeded".into()));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn below_threshold_never_inspects_a_manager_or_requires_a_launcher() {
        let root = tempfile::tempdir().unwrap();
        let domain = Domain::create(root.path(), "sessiond").unwrap();
        let core = SessionCore::new(Config {
            cgroup_root: root.path().into(),
            ..Config::default()
        })
        .unwrap();
        assert!(
            ensure_manager(&core, &domain, 999, &root.path().join("runtime"))
                .unwrap()
                .is_empty()
        );
        assert!(
            domain
                .scope_identity(&well_known::sessiond_user_service(999))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn readiness_eof_is_not_success() {
        let (mut receiver, sender) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(read_message(&mut receiver, Instant::now() + Duration::from_secs(1)).is_err());
    }
}
