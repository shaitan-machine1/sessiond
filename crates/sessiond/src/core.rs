//! Daemon-owned lifecycle effects. The scheduler owns per-UID serialization.
use crate::{config::Config, inventory, runtime, shutdown, startup};
use lib_scoped::{
    Domain, ProcessHandle, ScopeHandle, ScopeId, ScopeIdentity, TargetId, TargetStatus, well_known,
};
use lib_sessiond::{Attributes, ErrorCode, SessionInfo};
use std::io;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Containment(#[from] lib_scoped::Error),
    #[error(transparent)]
    Public(#[from] lib_sessiond::Error),
    #[error("invalid session ID: {0}")]
    InvalidSession(String),
    #[error("session ID appears under multiple UIDs: {0}")]
    AmbiguousSession(String),
    #[error("invalid configuration: {0}")]
    Configuration(String),
    #[error("{operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("cleanup of {scope} is incomplete: {reason}")]
    Incomplete { scope: String, reason: String },
    #[error("user-manager startup: {0}")]
    Startup(String),
}
impl Error {
    pub(crate) fn io(operation: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }
    pub(crate) fn incomplete(scope: &ScopeId, reason: impl Into<String>) -> Self {
        Self::Incomplete {
            scope: scope.to_string(),
            reason: reason.into(),
        }
    }
    pub fn public(&self) -> lib_sessiond::Error {
        let code = match &self {
            Self::Public(error) => return error.clone(),
            Self::InvalidSession(_) => ErrorCode::InvalidArgument,
            Self::Incomplete { .. } => ErrorCode::CleanupFailed,
            Self::Startup(_) => ErrorCode::ReadinessFailed,
            _ => ErrorCode::BackendError,
        };
        lib_sessiond::Error::new(code, self.to_string())
    }
}
pub(crate) fn failure(code: ErrorCode, message: impl Into<String>) -> Error {
    lib_sessiond::Error::new(code, message).into()
}
fn session_lookup_error(error: lib_scoped::Error) -> Error {
    if error.is_not_found() {
        failure(
            ErrorCode::SessionNotFound,
            "session disappeared during lookup",
        )
    } else {
        error.into()
    }
}
fn initializer_expired(modified: lib_scoped::Timestamp, now: SystemTime) -> Result<bool> {
    let time = modified
        .to_system_time()
        .ok_or_else(|| failure(ErrorCode::BackendError, "unrepresentable modified_at"))?;
    Ok(now
        .duration_since(time)
        .is_ok_and(|age| age >= Duration::from_secs(10)))
}
#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
pub(crate) fn master() -> TargetId {
    TargetId::parse("master").expect("literal target")
}

#[derive(Clone, Debug)]
pub enum Signal {
    New { sid: String, uid: u32 },
    Removed { sid: String, uid: u32 },
}
pub struct CloseCompletion {
    pub generation: ScopeIdentity,
    pub result: tokio::sync::watch::Sender<Option<lib_sessiond::Result<()>>>,
}
pub struct SessionCore {
    pub(crate) config: Config,
    pub(crate) completions: Mutex<std::collections::HashMap<String, Arc<CloseCompletion>>>,
    pub(crate) children: Mutex<Vec<Child>>,
    pub(crate) observation: Arc<crate::observation::Observation>,
    signals: tokio::sync::mpsc::Sender<Signal>,
}
impl SessionCore {
    pub fn new(config: Config) -> Result<Self> {
        let (sender, _) = tokio::sync::mpsc::channel(1);
        Self::with_signals(config, sender)
    }
    pub fn with_signals(
        config: Config,
        signals: tokio::sync::mpsc::Sender<Signal>,
    ) -> Result<Self> {
        config
            .validate()
            .map_err(|e| Error::Configuration(e.to_string()))?;
        Ok(Self {
            config,
            completions: Mutex::new(std::collections::HashMap::new()),
            children: Mutex::new(Vec::new()),
            observation: Arc::new(crate::observation::Observation::new()?),
            signals,
        })
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub(crate) fn domain(&self) -> Result<Option<Domain>> {
        match Domain::open(&self.config.cgroup_root, "sessiond") {
            Ok(domain) => Ok(Some(domain)),
            Err(lib_scoped::Error::DomainNotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn list_sessions(&self) -> Result<Vec<inventory::Session>> {
        match self.domain()? {
            Some(domain) => inventory::list(&domain),
            None => Ok(Vec::new()),
        }
    }
    pub fn list_infos(&self) -> Result<Vec<SessionInfo>> {
        self.list_sessions()?
            .into_iter()
            .map(|row| self.info(&row.id, row.uid))
            .collect()
    }
    pub fn find_session(&self, sid: &str) -> Result<Option<inventory::SessionIdentity>> {
        inventory::validate_session_id(sid)?;
        match self.domain()? {
            Some(domain) => inventory::find(&domain, sid),
            None => Ok(None),
        }
    }
    pub fn session_for_process(&self, pid: u32) -> Result<Option<inventory::SessionIdentity>> {
        let Some(domain) = self.domain()? else {
            return Ok(None);
        };
        Ok(domain
            .scope_of(pid)?
            .as_ref()
            .and_then(inventory::enclosing_session))
    }
    pub fn session_by_pid(&self, pid: u32, start_time: u64) -> Result<SessionInfo> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(failure(ErrorCode::InvalidArgument, "invalid PID"));
        }
        let process = ProcessHandle::open(pid).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH) {
                failure(ErrorCode::ProcessNotFound, e.to_string())
            } else {
                Error::io("pin process lookup", e)
            }
        })?;
        if process.identity().start_time != start_time {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "process start time changed",
            ));
        }
        let found = self.session_for_process(pid)?;
        if !process
            .identity_still_matches()
            .map_err(|e| Error::io("revalidate process lookup", e))?
        {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "process exited during lookup",
            ));
        }
        let found =
            found.ok_or_else(|| failure(ErrorCode::NoSession, "process is outside a session"))?;
        self.info(&found.id, found.uid)
    }
    pub fn get_session(&self, sid: &str) -> Result<SessionInfo> {
        let found = self
            .find_session(sid)?
            .ok_or_else(|| failure(ErrorCode::SessionNotFound, "session not found"))?;
        self.info(sid, found.uid)
    }
    pub(crate) fn info(&self, sid: &str, uid: u32) -> Result<SessionInfo> {
        let runtime_dir = self
            .config
            .runtime_parent
            .join(uid.to_string())
            .into_os_string()
            .into_string()
            .map_err(|_| failure(ErrorCode::BackendError, "runtime path is not UTF-8"))?;
        Ok(SessionInfo {
            sid: sid.to_owned(),
            uid,
            runtime_dir,
        })
    }
    pub fn session_scope(
        &self,
        sid: &str,
    ) -> Result<(Domain, inventory::SessionIdentity, lib_scoped::ScopeHandle)> {
        let row = self
            .find_session(sid)?
            .ok_or_else(|| failure(ErrorCode::SessionNotFound, "session not found"))?;
        let domain = self
            .domain()?
            .ok_or_else(|| failure(ErrorCode::SessionNotFound, "session domain disappeared"))?;
        let id = well_known::sessiond_user_session(row.uid, sid).expect("validated SID");
        let pinned = domain.pin_scope(&id).map_err(session_lookup_error)?;
        Ok((domain, row, pinned))
    }
    pub fn get_master(&self, sid: &str) -> Result<(u32, u64)> {
        let (domain, _, pinned) = self.session_scope(sid)?;
        let identity = domain
            .read_target_identity(pinned.id(), &master())
            .map_err(session_lookup_error)?
            .ok_or_else(|| failure(ErrorCode::MasterNotRecorded, "master is not recorded"))?;
        if domain.scope_identity(pinned.id())? != Some(pinned.identity()) {
            return Err(failure(
                ErrorCode::SessionNotFound,
                "session generation disappeared",
            ));
        }
        Ok((identity.pid, identity.start_time))
    }
    pub fn get_attrs(&self, sid: &str) -> Result<Attributes> {
        self.session_scope(sid)?
            .2
            .get_attributes()
            .map_err(Into::into)
    }
    pub fn update_attrs(
        &self,
        pinned: ScopeHandle,
        set: Attributes,
        remove: Vec<String>,
    ) -> Result<()> {
        lib_scoped::validate_attributes(&set)
            .map_err(|e| failure(ErrorCode::InvalidArgument, e.to_string()))?;
        if remove.len() > lib_scoped::MAX_ATTRIBUTES
            || remove.iter().any(|name| {
                name.is_empty()
                    || name.len() > lib_scoped::MAX_ATTRIBUTE_NAME_BYTES
                    || name.contains('\0')
                    || set.contains_key(name)
            })
        {
            return Err(failure(
                ErrorCode::InvalidArgument,
                "invalid or overlapping attribute patch keys",
            ));
        }
        let mut map = pinned.get_attributes()?;
        for name in remove {
            map.remove(&name);
        }
        map.extend(set);
        lib_scoped::validate_attributes(&map)
            .map_err(|e| failure(ErrorCode::LimitExceeded, e.to_string()))?;
        pinned.replace_attributes(&map)?;
        Ok(())
    }
    pub fn ready(
        &self,
        caller: crate::auth::Caller,
        expected: SessionInfo,
        expected_scope: ScopeHandle,
    ) -> Result<SessionInfo> {
        caller.validate()?;
        let initial = self.session_by_pid(caller.pid(), caller.start_time())?;
        if initial.sid != expected.sid || initial.uid != expected.uid {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "caller changed UID/session before lane acquisition",
            ));
        }
        let (domain, session, pinned) = self.session_scope(&initial.sid)?;
        if pinned.identity() != expected_scope.identity() {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "session generation changed before lane acquisition",
            ));
        }
        caller.validate()?;
        let current = self.session_for_process(caller.pid())?;
        if current.as_ref() != Some(&session) {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "caller membership changed",
            ));
        }
        match domain.target_status(pinned.id(), &master())? {
            TargetStatus::Running(_) => self.observation.arm(&domain, &session)?,
            _ => {
                return Err(failure(
                    ErrorCode::NotReady,
                    "session has no live recorded master",
                ));
            }
        }
        self.reconcile(session.uid)?;
        caller.validate()?;
        if domain.scope_identity(pinned.id())? != Some(pinned.identity()) {
            return Err(failure(
                ErrorCode::NoSession,
                "session removed during readiness",
            ));
        }
        let gid = startup::lookup_gid(&self.config, session.uid)?;
        let runtime = runtime::ensure(&self.config.runtime_parent, session.uid, gid)?;
        for warning in startup::ensure_manager(self, &domain, session.uid, &runtime)? {
            tracing::warn!(%warning, "manager readiness warning");
        }
        caller.validate()?;
        if domain.scope_identity(pinned.id())? != Some(pinned.identity())
            || self.session_for_process(caller.pid())?.as_ref() != Some(&session)
        {
            return Err(failure(
                ErrorCode::ProcessChanged,
                "caller/session changed during readiness",
            ));
        }
        if !matches!(
            domain.target_status(pinned.id(), &master())?,
            TargetStatus::Running(_)
        ) {
            return Err(failure(
                ErrorCode::NotReady,
                "session master exited during readiness",
            ));
        }
        self.emit(Signal::New {
            sid: session.id.clone(),
            uid: session.uid,
        });
        self.info(&session.id, session.uid)
    }
    pub fn close_tree(&self, sid: &str, expected: Option<ScopeIdentity>) -> Result<()> {
        let result = self.close_tree_inner(sid, expected);
        if let Some(completion) = self
            .completions
            .lock()
            .expect("close registry poisoned")
            .get(sid)
            && expected == Some(completion.generation)
        {
            completion.result.send_replace(Some(
                result.as_ref().map(|_| ()).map_err(|error| error.public()),
            ));
        }
        result
    }
    fn close_tree_inner(&self, sid: &str, expected: Option<ScopeIdentity>) -> Result<()> {
        let Some(row) = self.find_session(sid)? else {
            return Ok(());
        };
        let Some(domain) = self.domain()? else {
            return Ok(());
        };
        let root = well_known::sessiond_user_session(row.uid, sid).expect("validated SID");
        if let Some(expected) = expected
            && domain.scope_identity(&root)? != Some(expected)
        {
            return Ok(());
        }
        for warning in shutdown::shutdown(&domain, &root, &master(), &self.config.session.shutdown)?
        {
            tracing::warn!(%warning, sid, "session teardown warning");
        }
        self.observation.remove(sid);
        self.emit(Signal::Removed {
            sid: sid.to_owned(),
            uid: row.uid,
        });
        Ok(())
    }
    pub fn uids(&self) -> Result<Vec<u32>> {
        match self.domain()? {
            Some(domain) => Ok(inventory::user_roots(&domain)?
                .into_iter()
                .map(|(uid, _)| uid)
                .collect()),
            None => Ok(Vec::new()),
        }
    }
    pub fn reconcile(&self, uid: u32) -> Result<()> {
        let Some(domain) = self.domain()? else {
            return Ok(());
        };
        for root in inventory::session_roots(&domain, uid)? {
            let sid = root.segments().next_back().expect("scope segment");
            if inventory::validate_session_id(sid).is_err() {
                continue;
            }
            let pinned = match domain.pin_scope(&root) {
                Ok(pinned) => pinned,
                Err(e) if e.is_not_found() => continue,
                Err(e) => return Err(e.into()),
            };
            match domain.target_status(&root, &master())? {
                TargetStatus::Running(_) => self.observation.arm(
                    &domain,
                    &inventory::SessionIdentity {
                        id: sid.to_owned(),
                        uid,
                    },
                )?,
                TargetStatus::Exited(_) => self.close_tree(sid, Some(pinned.identity()))?,
                TargetStatus::Untracked => {
                    let modified = pinned.modified_at()?;
                    if initializer_expired(modified, SystemTime::now())?
                        && domain.scope_identity(&root)? == Some(pinned.identity())
                        && domain.read_target_identity(&root, &master())?.is_none()
                        && pinned.modified_at()? == modified
                    {
                        self.close_tree(sid, Some(pinned.identity()))?;
                    }
                }
            }
        }
        if self.config.linger || !inventory::session_roots(&domain, uid)?.is_empty() {
            return Ok(());
        }
        let service = well_known::sessiond_user_service(uid);
        for warning in shutdown::shutdown(
            &domain,
            &service,
            &master(),
            &self.config.user_service_manager.shutdown,
        )? {
            tracing::warn!(%warning, uid, "manager cleanup warning");
        }
        if !inventory::session_roots(&domain, uid)?.is_empty() {
            return Ok(());
        }
        // Any runtime error exits BEFORE final UID pruning, preserving discovery.
        runtime::remove(&self.config.runtime_parent, uid)?;
        for root in [
            well_known::sessiond_user_session_root(uid),
            well_known::sessiond_user_root(uid),
        ] {
            domain.remove_scope(&root)?;
        }
        Ok(())
    }
    fn emit(&self, event: Signal) {
        if let Err(error) = self.signals.try_send(event) {
            tracing::warn!(%error, "best-effort lifecycle hint dropped");
        }
    }
    pub fn reap_workers(&self) {
        self.children
            .lock()
            .expect("child registry poisoned")
            .retain_mut(|child| match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(error) => {
                    tracing::warn!(%error, "manager worker reap failed");
                    true
                }
            });
    }
}
