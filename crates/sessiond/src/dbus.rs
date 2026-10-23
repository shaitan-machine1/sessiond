pub use sessiond_api::{BUS_NAME, INTERFACE_NAME, OBJECT_PATH, SessionDescription};
use std::sync::Arc;
use zbus::Connection;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;

use crate::manager::SessionManager;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.decoupling.sessiond1.Error")]
pub enum ManagerError {
    AccessDenied(String),
    InvalidUser(String),
    BackendFailure(String),
}

pub struct Manager {
    manager: Arc<SessionManager>,
}

impl Manager {
    pub fn new(manager: Arc<SessionManager>) -> Self {
        Self { manager }
    }
}

#[zbus::interface(name = "org.decoupling.sessiond1.Manager")]
impl Manager {
    async fn open_session(
        &self,
        uid: u32,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(String, String), ManagerError> {
        let (caller_uid, caller_pid) = caller_identity(connection, &header).await?;
        require_root(caller_uid)?;
        let pid = caller_pid.ok_or_else(|| {
            ManagerError::AccessDenied("bus did not report caller process id".into())
        })?;
        let result = self
            .manager
            .open_session(uid, pid)
            .await
            .map_err(|error| ManagerError::BackendFailure(error.to_string()))?;
        Ok((result.0, result.1.to_string_lossy().into_owned()))
    }

    async fn close_session(
        &self,
        sid: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), ManagerError> {
        let (caller_uid, _) = caller_identity(connection, &header).await?;
        require_root(caller_uid)?;
        self.manager
            .request_close(&sid)
            .await
            .map_err(|error| ManagerError::BackendFailure(error.to_string()))
    }

    async fn list_sessions(&self) -> Vec<SessionDescription> {
        self.manager.list_sessions().await
    }

    #[zbus(signal)]
    pub async fn session_new(emitter: &SignalEmitter<'_>, sid: &str, uid: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn session_removed(
        emitter: &SignalEmitter<'_>,
        sid: &str,
        uid: u32,
    ) -> zbus::Result<()>;
}

async fn caller_identity(
    connection: &Connection,
    header: &Header<'_>,
) -> Result<(Option<u32>, Option<u32>), ManagerError> {
    let sender = header
        .sender()
        .ok_or_else(|| ManagerError::AccessDenied("message has no sender".into()))?;
    let proxy = fdo::DBusProxy::new(connection)
        .await
        .map_err(|error| ManagerError::BackendFailure(error.to_string()))?;
    let credentials = proxy
        .get_connection_credentials(BusName::from(sender.clone()))
        .await
        .map_err(|error| ManagerError::BackendFailure(error.to_string()))?;
    Ok((credentials.unix_user_id(), credentials.process_id()))
}

fn require_root(uid: Option<u32>) -> Result<(), ManagerError> {
    if uid == Some(0) {
        Ok(())
    } else {
        Err(ManagerError::AccessDenied(
            "session mutation is root-only".into(),
        ))
    }
}
