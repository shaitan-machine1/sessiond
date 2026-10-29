//! Synchronous, domain-neutral containment mechanisms.
//!
//! No daemon, bus dependency, transaction locks, background threads, or garbage
//! collection. Callers serialize mutations and control numeric-PID lifetimes
//! during move/assignment. IDs are fully qualified, including the domain.
//! Linux requires cgroup v2, pidfds, cgroup.kill and cgroup directory xattrs.
//! The cgroup mount and /proc must describe the same cgroup/PID namespaces.

mod ids;
mod linux;
mod observer;
mod process;

pub use ids::*;
pub use linux::{Domain, ScopeHandle, ScopeIdentity};
pub use observer::{Event, EventKind, Observer, ObserverControl, ScopeWatch, TargetWatch, Watch};
pub use process::{ProcessHandle, ProcessIdentity, read_start_time};
use std::io;

pub type Pid = u32;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InvalidScope(#[from] ParseError),
    #[error(transparent)]
    InvalidTarget(#[from] TargetIdError),
    #[error("scope {scope} is outside domain {domain}")]
    OutsideDomain { scope: ScopeId, domain: String },
    #[error("cannot remove the domain root with remove_scope")]
    DomainRoot,
    #[error("containment domain {0} does not exist")]
    DomainNotFound(String),
    #[error("target {target} is not assigned in scope {scope}")]
    Untracked { scope: ScopeId, target: TargetId },
    #[error("target {target} already exists in scope {scope}")]
    TargetExists { scope: ScopeId, target: TargetId },
    #[error("process {pid} is not in scope {scope}")]
    Membership { scope: ScopeId, pid: Pid },
    #[error("refusing to freeze a subtree containing the caller")]
    SelfFreeze,
    #[error("observer watch {token}: {source}")]
    Watch {
        token: u64,
        #[source]
        source: Box<Error>,
    },
    #[error("{operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("{operation}: {primary}; additionally, thaw failed: {thaw}")]
    Thaw {
        operation: String,
        primary: Box<Error>,
        thaw: Box<Error>,
    },
}

impl Error {
    pub(crate) fn io(operation: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }

    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { source, .. } => Some(source.kind()),
            _ => None,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::DomainNotFound(_)) || self.io_kind() == Some(io::ErrorKind::NotFound)
    }

    pub fn is_already_exists(&self) -> bool {
        matches!(self, Self::TargetExists { .. })
            || self.io_kind() == Some(io::ErrorKind::AlreadyExists)
    }
}

/// Process existence, deliberately independent of current scope membership.
/// Missing/corrupt tracking is not proof that a process exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    Untracked,
    Running(ProcessIdentity),
    Exited(ProcessIdentity),
}
