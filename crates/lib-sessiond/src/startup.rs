use crate::{
    Error, OpenSession, Result, SessionCore, SessionIdentity, inventory,
    launcher_protocol as protocol, locking, runtime, shutdown,
};
use lib_scoped::{Domain, ProcessHandle, ScopeId, TargetId, TargetStatus, well_known};
use nix::unistd::{Uid, User};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const USER_SERVICE_MANAGER: &str = match option_env!("SESSIOND_USER_SERVICE_MANAGER") {
    Some(path) => path,
    None => "/usr/libexec/user-service-manager",
};

pub(crate) fn open(core: &SessionCore, uid: u32) -> Result<OpenSession> {
    // SAFETY: geteuid has no pointer arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::PermissionDenied);
    }
    let domain = Domain::create(&core.config.cgroup_root, "sessiond")?;
    reject_bound_host(&domain)?;
    let locks = locking::LockDirectory::open(&core.config.state_dir.join("locks"))
        .map_err(|e| Error::io("open UID lock directory", e))?;
    let _guard = locks
        .acquire(uid, core.config.session.open_timeout)
        .map_err(|e| Error::io("acquire UID lifecycle lock", e))?;
    reject_bound_host(&domain)?;
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| Error::Startup(format!("look up UID {uid}: {e}")))?
        .ok_or_else(|| Error::Startup(format!("unknown UID {uid}")))?;
    let session_parent = well_known::sessiond_user_session_root(uid);
    let mut ancestors: Vec<_> = session_parent.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors
        .into_iter()
        .chain([session_parent.clone()])
        .filter(|s| s != &domain.root_id())
    {
        match domain.create_scope(&ancestor) {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e.into()),
        }
    }
    let (sid, session_scope) = allocate_session(&domain, uid)?;
    domain.move_process(&session_scope, std::process::id())?;
    domain.assign_target(
        &session_scope,
        &TargetId::parse("leader").expect("literal target"),
        std::process::id(),
    )?;
    let runtime = runtime::ensure(&core.config.runtime_parent, uid, user.gid.as_raw())?;
    let service = well_known::sessiond_user_service(uid);
    let manager = TargetId::parse("manager").expect("literal target");
    let mut warnings = Vec::new();
    if !matches!(
        domain.target_status(&service, &manager)?,
        TargetStatus::Running(_)
    ) {
        warnings.extend(shutdown::shutdown(
            &domain,
            &service,
            &manager,
            &core.config.user_service_manager.shutdown,
        )?);
        domain.create_scope(&service)?;
        if let Err(startup_error) = launch(core, &domain, &service, uid, &runtime) {
            // This is failed-startup helper cleanup, not ordinary session close:
            // the live optional-PAM login host is deliberately left alone.
            return match shutdown::shutdown(
                &domain,
                &service,
                &manager,
                &core.config.user_service_manager.shutdown,
            ) {
                Ok(_) => Err(startup_error),
                Err(cleanup_error) => Err(Error::Startup(format!(
                    "{startup_error}; startup cleanup incomplete: {cleanup_error}"
                ))),
            };
        }
    }
    let identity = SessionIdentity {
        id: sid.clone(),
        uid,
    };
    if let Err(error) = core.events.session_new(&identity) {
        warnings.push(error.to_string());
    }
    Ok(OpenSession {
        id: sid,
        runtime,
        warnings,
    })
}

fn reject_bound_host(domain: &Domain) -> Result<()> {
    if let Some(scope) = domain.scope_of(std::process::id())?
        && scope.is_or_is_under(&ScopeId::parse("sessiond/user").expect("literal scope"))
    {
        return Err(Error::AlreadyBound(scope.to_string()));
    }
    Ok(())
}
fn allocate_session(domain: &Domain, uid: u32) -> Result<(String, ScopeId)> {
    for _ in 0..16 {
        let id = uuid::Uuid::now_v7().simple().to_string();
        inventory::validate_session_id(&id)?;
        let scope = well_known::sessiond_user_session(uid, &id).expect("UUID is a portable ID");
        match domain.create_scope(&scope) {
            Ok(()) => return Ok((id, scope)),
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Startup(
        "session ID allocation repeatedly collided".into(),
    ))
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
        .ok_or_else(|| Error::Configuration("manager readiness deadline overflow".into()))?;
    let pinned = domain.pin_scope(service)?;
    let (mut parent, child) =
        UnixStream::pair().map_err(|e| Error::io("create launcher coordination socket", e))?;
    parent
        .set_nonblocking(true)
        .map_err(|e| Error::io("configure launcher coordination socket", e))?;
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
        .arg("--cgroup-root")
        .arg(&core.config.cgroup_root)
        .arg("--service-scope")
        .arg(service.as_str())
        .arg("--ready-timeout-ms")
        .arg(
            core.config
                .user_service_manager
                .ready_timeout
                .as_millis()
                .to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut helper = protocol::spawn_with_fd(command, child.as_fd())
        .map_err(|e| Error::io("exec user-manager helper", e))?;
    drop(child);
    let mut reaped = false;
    let mut final_host = None;
    let mut pam_authorized = false;
    let mut buffer = Vec::new();
    let result = (|| {
        let message = read_message(&mut parent, &mut buffer, deadline)?;
        let hello = protocol::Hello::parse(&message)
            .map_err(|e| Error::io("parse launcher identity", e))?;
        if hello.scope != pinned.identity()
            || hello.process.pid == std::process::id()
            || hello.process.pid == helper.id()
        {
            return Err(Error::Startup(
                "launcher reported the wrong process/scope generation".into(),
            ));
        }
        let process = ProcessHandle::open(hello.process.pid)
            .map_err(|e| Error::io("pin final launcher", e))?;
        if process.identity() != hello.process {
            return Err(Error::Startup("launcher identity changed".into()));
        }
        final_host = Some(process);
        reap_helper(&mut helper, deadline)?;
        reaped = true;
        parent
            .write_all(&[protocol::MIGRATE])
            .map_err(|e| Error::io("authorize launcher self-migration", e))?;
        expect_message(&mut parent, &mut buffer, deadline, protocol::REGISTERED)?;
        parent
            .write_all(&[protocol::START])
            .map_err(|e| Error::io("authorize manager private PAM/startup", e))?;
        pam_authorized = true;
        expect_message(&mut parent, &mut buffer, deadline, protocol::READY)?;
        if !final_host
            .as_ref()
            .expect("pinned launcher")
            .is_alive()
            .map_err(|e| Error::io("check ready launcher", e))?
        {
            return Err(Error::Startup("launcher exited at readiness".into()));
        }
        Ok(())
    })();
    drop(parent); // EOF cancels every unauthorized phase, including late helpers.
    if result.is_err()
        && !pam_authorized
        && let Some(process) = final_host
    {
        // Before START there is no private PAM/manager child to close. This
        // identity-safe cancellation never kills the original login PAM host.
        let _ = process.send_kill();
    }
    if !reaped {
        let _ = helper.kill();
        match helper.wait() {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {}
            Err(e) => {
                return Err(Error::Startup(format!(
                    "{result:?}; failed to reap helper: {e}"
                )));
            }
        }
    }
    result
}
fn reap_helper(helper: &mut Child, deadline: Instant) -> Result<()> {
    loop {
        match helper.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(Error::Startup(format!(
                    "detachment helper exited with {status}"
                )));
            }
            // A host's existing SIGCHLD handler or SA_NOCLDWAIT may already
            // have reaped it. Do not change the host's signal disposition.
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(e) => return Err(Error::io("reap detachment helper", e)),
            Ok(None) => {}
        }
        let remaining = remaining(deadline)?;
        std::thread::sleep(remaining.min(Duration::from_millis(5)));
    }
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::Startup("user-manager readiness deadline exceeded".into()))
}
fn expect_message(
    stream: &mut UnixStream,
    buffer: &mut Vec<u8>,
    deadline: Instant,
    expected: &str,
) -> Result<()> {
    let message = read_message(stream, buffer, deadline)?;
    if message == expected {
        Ok(())
    } else {
        Err(Error::Startup(format!(
            "expected launcher {expected}, received {message:?}"
        )))
    }
}
fn read_message(
    stream: &mut UnixStream,
    buffer: &mut Vec<u8>,
    deadline: Instant,
) -> Result<String> {
    loop {
        if let Some(end) = buffer.iter().position(|b| *b == b'\n') {
            let message = String::from_utf8(buffer[..end].to_vec())
                .map_err(|e| Error::Startup(format!("invalid launcher message: {e}")))?;
            buffer.drain(..=end);
            return Ok(message);
        }
        if buffer.len() >= protocol::MAX_MESSAGE {
            return Err(Error::Startup("launcher message exceeded bound".into()));
        }
        let budget = remaining(deadline)?;
        let mut bytes = [0; 512];
        match stream.read(&mut bytes) {
            Ok(0) => {
                return Err(Error::Startup(
                    "launcher coordination channel closed before readiness".into(),
                ));
            }
            Ok(n) => {
                buffer.extend_from_slice(&bytes[..n]);
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(Error::io("read launcher status", e)),
        }
        let millis = budget.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
        let mut fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives a live descriptor and valid writable structure.
        let ready = unsafe { libc::poll(&mut fd, 1, millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(Error::io("poll launcher status", error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_reads_have_one_monotonic_deadline_and_handle_eof() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        let mut buffer = Vec::new();
        let start = Instant::now();
        assert!(read_message(&mut parent, &mut buffer, start + Duration::from_millis(20)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(child);
        assert!(
            read_message(
                &mut parent,
                &mut buffer,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
    }
    #[test]
    fn buffered_messages_preserve_phase_boundaries() {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        child.write_all(b"REGISTERED\nREADY\n").unwrap();
        let mut buffer = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        expect_message(&mut parent, &mut buffer, deadline, protocol::REGISTERED).unwrap();
        expect_message(&mut parent, &mut buffer, deadline, protocol::READY).unwrap();
    }
}
