//! Synchronous session-domain logic. PAM opens locally; only daemon workers
//! execute teardown. Inventory is derived from containment, never a journal.
//! PAM, daemon, launcher, and administrative clients use this implementation.

pub mod bus;
pub mod config;
mod inventory;
#[doc(hidden)]
pub mod launcher_protocol;
mod locking;
mod runtime;
mod shutdown;
mod startup;

use config::Config;
pub use inventory::{Session, SessionIdentity, validate_session_id};
use lib_scoped::{Domain, ScopeId, TargetId};
use std::io;
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Containment(#[from] lib_scoped::Error),
    #[error("invalid session ID: {0}")]
    InvalidSession(String),
    #[error("session ID {0} appears under multiple UIDs")]
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
    #[error("session mutation requires effective UID 0")]
    PermissionDenied,
    #[error("PAM host is already bound to {0}")]
    AlreadyBound(String),
    #[error("user-manager startup: {0}")]
    Startup(String),
    #[error("sessiond transport: {0}")]
    Transport(String),
}
impl Error {
    fn io(operation: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }
    fn incomplete(scope: &ScopeId, reason: impl Into<String>) -> Self {
        Self::Incomplete {
            scope: scope.to_string(),
            reason: reason.into(),
        }
    }
}

/// Transport implementations must use bounded best-effort sends. Domain code
/// owns the event boundary; a failed notification never resurrects a scope.
pub trait LifecycleEvents: Send + Sync {
    fn session_new(&self, session: &SessionIdentity) -> Result<()>;
    fn session_removed(&self, session: &SessionIdentity) -> Result<()>;
}
struct NoEvents;
impl LifecycleEvents for NoEvents {
    fn session_new(&self, _: &SessionIdentity) -> Result<()> {
        Ok(())
    }
    fn session_removed(&self, _: &SessionIdentity) -> Result<()> {
        Ok(())
    }
}

pub struct SessionCore {
    config: Config,
    events: Arc<dyn LifecycleEvents>,
}
impl SessionCore {
    pub fn new(config: Config) -> Result<Self> {
        config
            .validate()
            .map_err(|e| Error::Configuration(e.to_string()))?;
        Ok(Self {
            config,
            events: Arc::new(NoEvents),
        })
    }
    pub fn with_events(mut self, events: impl LifecycleEvents + 'static) -> Self {
        self.events = Arc::new(events);
        self
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn open_session(&self, uid: u32) -> Result<OpenSession> {
        startup::open(self, uid)
    }
    fn domain(&self) -> Result<Option<Domain>> {
        match Domain::open(&self.config.cgroup_root, "sessiond") {
            Ok(domain) => Ok(Some(domain)),
            Err(lib_scoped::Error::DomainNotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn list_sessions(&self) -> Result<Vec<Session>> {
        match self.domain()? {
            Some(domain) => inventory::list(&domain),
            None => Ok(Vec::new()),
        }
    }
    /// Resolve a public SID to its authoritative containment identity. This is
    /// lock-free; mutators revalidate after acquiring the UID lock.
    pub fn find_session(&self, sid: &str) -> Result<Option<SessionIdentity>> {
        let Some(domain) = self.domain()? else {
            validate_session_id(sid)?;
            return Ok(None);
        };
        inventory::find(&domain, sid)
    }
    /// Resolve enclosing session membership, independent of saved PAM data,
    /// environment publication, and the presence/validity of leader tracking.
    pub fn session_for_process(&self, pid: u32) -> Result<Option<SessionIdentity>> {
        let Some(domain) = self.domain()? else {
            return Ok(None);
        };
        Ok(domain
            .scope_of(pid)?
            .as_ref()
            .and_then(inventory::enclosing_session))
    }
}

#[derive(Debug)]
pub struct OpenSession {
    pub id: String,
    pub runtime: std::path::PathBuf,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct CloseReport {
    pub session_removed: bool,
    pub warnings: Vec<String>,
}

/// Execution is deliberately separate from client APIs. PAM/CLI must request
/// daemon execution rather than invoking these functions or taking UID locks.
pub mod daemon_support {
    use super::*;
    use lib_scoped::well_known;

    pub fn execute_close_session(core: &SessionCore, sid: &str) -> Result<CloseReport> {
        validate_session_id(sid)?;
        // SAFETY: geteuid has no pointer arguments or side effects.
        if unsafe { libc::geteuid() } != 0 {
            return Err(Error::PermissionDenied);
        }
        let Some(domain) = core.domain()? else {
            return Ok(CloseReport::default());
        };
        // Resolve without reading leader records: broken tracking must not make
        // explicit close unusable. No UID lock is needed for this initial scan.
        let Some(session) = inventory::find(&domain, sid)? else {
            return Ok(CloseReport::default());
        };
        let locks = locking::LockDirectory::open(&core.config.state_dir.join("locks"))
            .map_err(|e| Error::io("open UID lock directory", e))?;
        let _guard = locks
            .acquire(session.uid, core.config.session.open_timeout)
            .map_err(|e| Error::io("acquire UID lifecycle lock", e))?;
        let root = well_known::sessiond_user_session(session.uid, &session.id)
            .expect("validated session ID");
        if domain.scope_identity(&root)?.is_none() {
            return Ok(CloseReport::default());
        }
        let others = inventory::session_roots(&domain, session.uid)?
            .into_iter()
            .any(|scope| scope != root);
        let last = !others && !core.config.linger;
        let service = well_known::sessiond_user_service(session.uid);
        let mut report = CloseReport::default();
        let mut failures = Vec::new();
        if last {
            match shutdown::shutdown(
                &domain,
                &service,
                &TargetId::parse("manager").expect("literal target"),
                &core.config.user_service_manager.shutdown,
            ) {
                Ok(warnings) => report.warnings.extend(warnings),
                Err(error) => failures.push(error.to_string()),
            }
        }
        match shutdown::shutdown(
            &domain,
            &root,
            &TargetId::parse("leader").expect("literal target"),
            &core.config.session.shutdown,
        ) {
            Ok(warnings) => {
                report.warnings.extend(warnings);
                report.session_removed = true;
                if let Err(error) = core.events.session_removed(&session) {
                    report.warnings.push(error.to_string());
                }
            }
            Err(error) => failures.push(error.to_string()),
        }
        // Revalidate before removing shared resources. Other session roots,
        // including partial/untracked roots, retain the manager/runtime.
        let no_sessions = inventory::session_roots(&domain, session.uid)?.is_empty();
        if last
            && failures.is_empty()
            && no_sessions
            && let Err(error) = runtime::remove(&core.config.runtime_parent, session.uid)
        {
            failures.push(error.to_string());
        }
        if no_sessions && domain.scope_identity(&service)?.is_none() {
            for container in [
                well_known::sessiond_user_session_root(session.uid),
                well_known::sessiond_user_root(session.uid),
            ] {
                if let Err(error) = domain.remove_scope(&container) {
                    failures.push(error.to_string());
                    break;
                }
            }
        }
        // The guard closes its descriptor but never unlinks the stable lock.
        // There is no journal or startup replay if the worker/daemon dies.
        if failures.is_empty() {
            Ok(report)
        } else {
            failures.extend(report.warnings);
            Err(Error::incomplete(&root, failures.join("; ")))
        }
    }
}
