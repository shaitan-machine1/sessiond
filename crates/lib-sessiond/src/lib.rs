//! Local session containment and synchronous sessiond clients. No lifecycle locks,
//! runtime/manager orchestration, executor or background worker belongs here.
#[cfg(feature = "blocking-client")]
pub mod bus;
#[cfg(feature = "c-api")]
mod ffi;
#[cfg(feature = "local-open")]
mod local;
#[cfg(feature = "local-open")]
pub use local::{OpenOptions, OpenedSession, open_session, open_session_with_options};
use std::collections::BTreeMap;

pub type Attributes = BTreeMap<String, String>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "wire-serde",
    derive(serde::Serialize, serde::Deserialize, zvariant::Type)
)]
pub struct SessionInfo {
    pub sid: String,
    pub uid: u32,
    pub runtime_dir: String,
}

/// Stable categories shared by the wire, Rust and C APIs. Transport and
/// UnknownRemote describe client-side failures, not daemon error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    InvalidArgument = 1,
    NotAuthorized,
    SessionNotFound,
    NoSession,
    ProcessNotFound,
    ProcessChanged,
    MasterNotRecorded,
    AlreadyInSession,
    Busy,
    LimitExceeded,
    NotReady,
    Stopping,
    ReadinessFailed,
    CleanupFailed,
    Pending,
    BackendError,
    Transport,
    UnknownRemote,
}
impl ErrorCode {
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "InvalidArgument",
            Self::NotAuthorized => "NotAuthorized",
            Self::SessionNotFound => "SessionNotFound",
            Self::NoSession => "NoSession",
            Self::ProcessNotFound => "ProcessNotFound",
            Self::ProcessChanged => "ProcessChanged",
            Self::MasterNotRecorded => "MasterNotRecorded",
            Self::AlreadyInSession => "AlreadyInSession",
            Self::Busy => "Busy",
            Self::LimitExceeded => "LimitExceeded",
            Self::NotReady => "NotReady",
            Self::Stopping => "Stopping",
            Self::ReadinessFailed => "ReadinessFailed",
            Self::CleanupFailed => "CleanupFailed",
            Self::Pending => "Pending",
            Self::BackendError => "BackendError",
            Self::Transport => "Transport",
            Self::UnknownRemote => "UnknownRemote",
        }
    }
    pub fn from_name(name: &str) -> Option<Self> {
        (1..=18)
            .filter_map(Self::from_number)
            .find(|code| code.name() == name)
    }
    fn from_number(number: u32) -> Option<Self> {
        Some(match number {
            1 => Self::InvalidArgument,
            2 => Self::NotAuthorized,
            3 => Self::SessionNotFound,
            4 => Self::NoSession,
            5 => Self::ProcessNotFound,
            6 => Self::ProcessChanged,
            7 => Self::MasterNotRecorded,
            8 => Self::AlreadyInSession,
            9 => Self::Busy,
            10 => Self::LimitExceeded,
            11 => Self::NotReady,
            12 => Self::Stopping,
            13 => Self::ReadinessFailed,
            14 => Self::CleanupFailed,
            15 => Self::Pending,
            16 => Self::BackendError,
            17 => Self::Transport,
            18 => Self::UnknownRemote,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    /// Preserved for remote/transport errors, including unknown named errors.
    pub remote_name: Option<String>,
}
impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            remote_name: None,
        }
    }
}
impl From<lib_scoped::Error> for Error {
    fn from(error: lib_scoped::Error) -> Self {
        Self::new(ErrorCode::BackendError, error.to_string())
    }
}

pub fn validate_session_id(sid: &str) -> Result<()> {
    if sid.len() == 32
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "SID must contain 32 lowercase hexadecimal characters",
        ))
    }
}

/// Current process start time: /proc stat field 22 in clock ticks since boot.
pub fn current_process_start_time() -> Result<u64> {
    lib_scoped::read_start_time(std::process::id())
        .map_err(|e| Error::new(ErrorCode::BackendError, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_error_codes_and_ids_are_precise() {
        for number in 1..=18 {
            let code = ErrorCode::from_number(number).unwrap();
            assert_eq!(ErrorCode::from_name(code.name()), Some(code));
        }
        assert!(validate_session_id("0123456789abcdef0123456789abcdef").is_ok());
        for bad in ["", "../x", "0123456789ABCDEF0123456789ABCDEF"] {
            assert!(validate_session_id(bad).is_err());
        }
        assert!(current_process_start_time().unwrap() > 0);
    }
}
