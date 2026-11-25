use crate::{Error, ErrorCode, Result};
use lib_scoped::{Domain, ScopeId, TargetId, well_known};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub cgroup_root: PathBuf,
    /// Initial opaque attributes, installed locally before readiness. `ready` is reserved.
    pub initial_attributes: crate::Attributes,
}
impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            cgroup_root: "/sys/fs/cgroup".into(),
            initial_attributes: crate::Attributes::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedSession {
    pub sid: String,
    pub uid: u32,
}

/// Create containment, migrate this process and record its master identity.
/// Concurrent calls in the same process are unsupported. No runtime check or
/// lifecycle lock enforces that precondition. Use one PAM host per session.
pub fn open_session(uid: u32) -> Result<OpenedSession> {
    open_session_with_options(uid, &OpenOptions::default())
}
pub fn open_session_with_options(uid: u32, options: &OpenOptions) -> Result<OpenedSession> {
    // SAFETY: no arguments, no side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::new(
            ErrorCode::NotAuthorized,
            "local opening requires effective UID 0",
        ));
    }
    if !options.cgroup_root.is_absolute() || options.cgroup_root.as_os_str().as_bytes().contains(&0)
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "cgroup_root must be absolute and NUL-free",
        ));
    }
    if options.initial_attributes.contains_key("ready") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "ready is daemon-owned",
        ));
    }
    let mut bounded = options.initial_attributes.clone();
    bounded.insert("ready".into(), "1".into());
    lib_scoped::validate_attributes(&bounded)?;
    let domain = Domain::create(&options.cgroup_root, "sessiond")?;
    if let Some(scope) = domain.scope_of(std::process::id())? {
        let parts: Vec<_> = scope.segments().collect();
        if parts.len() >= 5
            && parts[..2] == ["sessiond", "user"]
            && parts[3] == "session"
            && parts[2]
                .parse::<u32>()
                .is_ok_and(|uid| uid.to_string() == parts[2])
            && crate::validate_session_id(parts[4]).is_ok()
        {
            return Err(Error::new(
                ErrorCode::AlreadyInSession,
                format!("already in {scope}"),
            ));
        }
    }
    let parent = well_known::sessiond_user_session_root(uid);
    let mut ancestors: Vec<_> = parent.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors
        .into_iter()
        .chain([parent])
        .filter(|s| s != &domain.root_id())
    {
        match domain.create_scope(&ancestor) {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e.into()),
        }
    }
    for _ in 0..16 {
        let sid = uuid::Uuid::now_v7().simple().to_string();
        let id: ScopeId = well_known::sessiond_user_session(uid, &sid).expect("UUID SID");
        match domain.create_scope(&id) {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => continue,
            Err(e) => return Err(e.into()),
        }
        let pinned = domain.pin_scope(&id)?;
        pinned.move_process(std::process::id())?;
        pinned.assign_target(
            &TargetId::parse("master").expect("literal target"),
            std::process::id(),
        )?;
        pinned.replace_attributes(&options.initial_attributes)?;
        return Ok(OpenedSession { sid, uid });
    }
    Err(Error::new(
        ErrorCode::BackendError,
        "repeated SID collisions",
    ))
}
