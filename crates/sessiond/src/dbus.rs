use crate::{
    auth::{Caller, require_root},
    core::Signal,
    scheduler::{Permit, Scheduler},
};
use lib_sessiond::{Attributes, Error, ErrorCode, SessionInfo};
use std::time::Duration;
use zbus::{Connection, message::Header, object_server::SignalEmitter};
pub const BUS_NAME: &str = "org.SGLogin.Sessiond1";
pub const OBJECT_PATH: &str = "/org/SGLogin/Sessiond1";
const REPLY_BUDGET: Duration = Duration::from_secs(25);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.SGLogin.Sessiond1.Error")]
pub enum WireError {
    InvalidArgument(String),
    NotAuthorized(String),
    SessionNotFound(String),
    NoSession(String),
    ProcessNotFound(String),
    ProcessChanged(String),
    MasterNotRecorded(String),
    AlreadyInSession(String),
    Busy(String),
    LimitExceeded(String),
    NotReady(String),
    Stopping(String),
    ReadinessFailed(String),
    CleanupFailed(String),
    Pending(String),
    BackendError(String),
}
impl From<Error> for WireError {
    fn from(error: Error) -> Self {
        let message = error.message;
        match error.code {
            ErrorCode::InvalidArgument => Self::InvalidArgument(message),
            ErrorCode::NotAuthorized => Self::NotAuthorized(message),
            ErrorCode::SessionNotFound => Self::SessionNotFound(message),
            ErrorCode::NoSession => Self::NoSession(message),
            ErrorCode::ProcessNotFound => Self::ProcessNotFound(message),
            ErrorCode::ProcessChanged => Self::ProcessChanged(message),
            ErrorCode::MasterNotRecorded => Self::MasterNotRecorded(message),
            ErrorCode::AlreadyInSession => Self::AlreadyInSession(message),
            ErrorCode::Busy => Self::Busy(message),
            ErrorCode::LimitExceeded => Self::LimitExceeded(message),
            ErrorCode::NotReady => Self::NotReady(message),
            ErrorCode::Stopping => Self::Stopping(message),
            ErrorCode::ReadinessFailed => Self::ReadinessFailed(message),
            ErrorCode::CleanupFailed => Self::CleanupFailed(message),
            ErrorCode::Pending => Self::Pending(message),
            _ => Self::BackendError(message),
        }
    }
}
type Result<T> = std::result::Result<T, WireError>;
pub(crate) struct Manager {
    scheduler: Scheduler,
    permit: Permit,
}
impl Manager {
    pub(crate) fn new(scheduler: Scheduler, permit: Permit) -> Self {
        Self { scheduler, permit }
    }
    async fn execute<R: Send + 'static>(
        &self,
        permit: Permit,
        uid: Option<u32>,
        effect: impl FnOnce(&crate::SessionCore) -> crate::Result<R> + Send + 'static,
    ) -> Result<R> {
        tokio::time::timeout(REPLY_BUDGET, self.scheduler.execute(permit, uid, effect))
            .await
            .map_err(|_| {
                WireError::Pending(
                    "reply deadline expired; admitted effects retain their worker and UID lane"
                        .into(),
                )
            })?
            .map_err(Into::into)
    }
    async fn credentials(
        connection: &Connection,
        header: &Header<'_>,
    ) -> Result<zbus::fdo::ConnectionCredentials> {
        let sender = header
            .sender()
            .ok_or_else(|| WireError::NotAuthorized("missing unique sender".into()))?;
        let proxy = zbus::fdo::DBusProxy::new(connection)
            .await
            .map_err(|e| WireError::BackendError(e.to_string()))?;
        let credentials = tokio::time::timeout(
            Duration::from_secs(5),
            proxy.get_connection_credentials(sender.clone().into()),
        )
        .await
        .map_err(|_| WireError::BackendError("bus credential lookup timed out".into()))?
        .map_err(|e| WireError::BackendError(e.to_string()))?;
        require_root(&credentials).map_err(|e| WireError::from(e.public()))?;
        Ok(credentials)
    }
}
#[zbus::interface(name = "org.SGLogin.Sessiond1.Manager")]
impl Manager {
    async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let permit = self.permit.clone();
        self.execute(permit, None, |core| core.list_infos()).await
    }
    async fn get_session(&self, sid: String) -> Result<SessionInfo> {
        let permit = self.permit.clone();
        self.execute(permit, None, move |core| core.get_session(&sid))
            .await
    }
    async fn get_session_by_pid(&self, pid: u32, start_time: u64) -> Result<SessionInfo> {
        let permit = self.permit.clone();
        self.execute(permit, None, move |core| {
            core.session_by_pid(pid, start_time)
        })
        .await
    }
    #[zbus(out_args("pid", "start_time"))]
    async fn get_session_master_pid(&self, sid: String) -> Result<(u32, u64)> {
        let permit = self.permit.clone();
        self.execute(permit, None, move |core| core.get_master(&sid))
            .await
    }
    async fn get_session_attrs(&self, sid: String) -> Result<Attributes> {
        let permit = self.permit.clone();
        self.execute(permit, None, move |core| core.get_attrs(&sid))
            .await
    }
    async fn ensure_session_ready(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<SessionInfo> {
        let permit = self.permit.clone();
        let credentials = Self::credentials(connection, &header).await?;
        let (caller, expected, scope) = self
            .execute(permit.clone(), None, move |core| {
                let caller = Caller::acquire(&credentials)?;
                let (info, scope) = core.caller_scope(&caller)?;
                caller.validate()?;
                Ok((caller, info, scope))
            })
            .await?;
        let uid = expected.uid;
        self.execute(permit, Some(uid), move |core| {
            core.ready(caller, expected, scope)
        })
        .await
    }
    async fn update_session_attrs(
        &self,
        sid: String,
        set: Attributes,
        remove: Vec<String>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<()> {
        let permit = self.permit.clone();
        Self::credentials(connection, &header).await?;
        let (uid, scope) = self
            .execute(permit.clone(), None, move |core| {
                let (_, session, scope) = core.session_scope(&sid)?;
                Ok((session.uid, scope))
            })
            .await?;
        self.execute(permit, Some(uid), move |core| {
            core.update_attrs(scope, set, remove)
        })
        .await
    }
    async fn schedule_close_session(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<()> {
        let permit = self.permit.clone();
        let credentials = Self::credentials(connection, &header).await?;
        let (caller, expected, scope) = self
            .execute(permit.clone(), None, move |core| {
                let caller = Caller::acquire(&credentials)?;
                let (info, scope) = core.caller_scope(&caller)?;
                Ok((caller, info, scope))
            })
            .await?;
        let scheduler = self.scheduler.clone();
        self.execute(permit, Some(expected.uid), move |core| {
            let (current, pinned) = core.caller_scope(&caller)?;
            if current != expected || pinned.identity() != scope.identity() {
                return Err(crate::core::failure(
                    ErrorCode::ProcessChanged,
                    "caller/session changed before close admission",
                ));
            }
            scheduler.schedule(&current.sid, false).map(|_| ())
        })
        .await
    }
    async fn close_session(
        &self,
        sid: String,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<()> {
        let permit = self.permit.clone();
        let credentials = Self::credentials(connection, &header).await?;
        let captured_sid = sid.clone();
        let (caller, target) = self
            .execute(permit.clone(), None, move |core| {
                let caller = Caller::acquire(&credentials)?;
                let target = match core.find_session(&captured_sid)? {
                    Some(row) => Some((row.uid, core.session_scope(&captured_sid)?.2.identity())),
                    None => None,
                };
                Ok((caller, target))
            })
            .await?;
        let Some((uid, generation)) = target else {
            return Ok(());
        };
        let scheduler = self.scheduler.clone();
        let completion = self
            .execute(permit.clone(), Some(uid), move |core| {
                caller.validate()?;
                if core
                    .session_for_process(caller.pid())?
                    .is_some_and(|session| session.id == sid)
                {
                    return Err(crate::core::failure(
                        ErrorCode::InvalidArgument,
                        "blocking close refuses a caller inside the target session subtree",
                    ));
                }
                match core.session_scope(&sid) {
                    Ok((_, _, scope)) if scope.identity() == generation => {
                        scheduler.schedule(&sid, true)
                    }
                    Ok(_) => Ok(None),
                    Err(e) if e.public().code == ErrorCode::SessionNotFound => Ok(None),
                    Err(e) => Err(e),
                }
            })
            .await?;
        let Some(completion) = completion else {
            return Ok(());
        };
        // This permit bounds waiting clients, not the separately retained close
        // operation. Dropping a timeout waiter never cancels admitted teardown.
        let _permit = permit;
        tokio::time::timeout(REPLY_BUDGET, Scheduler::wait(completion))
            .await
            .map_err(|_| WireError::Pending("session-tree removal is still pending".into()))?
            .map_err(Into::into)
    }
    #[zbus(signal)]
    async fn session_new(emitter: &SignalEmitter<'_>, sid: &str, uid: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn session_removed(emitter: &SignalEmitter<'_>, sid: &str, uid: u32) -> zbus::Result<()>;
}

pub async fn serve(
    session_bus: bool,
    scheduler: Scheduler,
    signals: tokio::sync::mpsc::Receiver<Signal>,
) -> anyhow::Result<()> {
    crate::dispatch::serve(session_bus, scheduler, signals).await
}

pub(crate) async fn emit(connection: &Connection, signal: Signal) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(connection, OBJECT_PATH)?;
    match signal {
        Signal::New { sid, uid } => Manager::session_new(&emitter, &sid, uid).await,
        Signal::Removed { sid, uid } => Manager::session_removed(&emitter, &sid, uid).await,
    }
}

pub(crate) async fn handle(
    manager: Manager,
    connection: &Connection,
    message: zbus::Message,
) -> zbus::Result<()> {
    let header = message.header();
    let interface = header.interface().map(|name| name.as_str()).unwrap_or("");
    let member = header.member().map(|name| name.as_str()).unwrap_or("");
    macro_rules! args {
        ($ty:ty) => {
            match message.body().deserialize::<$ty>() {
                Ok(args) => args,
                Err(error) => {
                    return connection
                        .reply_dbus_error(&header, zbus::fdo::Error::InvalidArgs(error.to_string()))
                        .await
                }
            }
        };
    }
    macro_rules! respond {
        ($result:expr) => {
            match $result {
                Ok(value) => connection.reply(&header, &value).await,
                Err(error) => connection.reply_dbus_error(&header, error).await,
            }
        };
    }
    if interface == "org.freedesktop.DBus.Peer" {
        args!(());
        return match member {
            "Ping" => connection.reply(&header, &()).await,
            "GetMachineId" => respond!(
                manager
                    .execute(manager.permit.clone(), None, |_| {
                        std::fs::read_to_string("/etc/machine-id")
                            .map(|id| (id.trim().to_owned(),))
                            .map_err(|e| crate::Error::io("read machine ID", e))
                    })
                    .await
            ),
            _ => {
                connection
                    .reply_dbus_error(&header, zbus::fdo::Error::UnknownMethod(member.into()))
                    .await
            }
        };
    }
    if header.path().map(|path| path.as_str()) != Some(OBJECT_PATH) {
        return connection
            .reply_dbus_error(
                &header,
                zbus::fdo::Error::UnknownObject("unknown sessiond path".into()),
            )
            .await;
    }
    if interface == "org.freedesktop.DBus.Introspectable" && member == "Introspect" {
        args!(());
        return connection
            .reply(
                &header,
                &(include_str!("../../../dist/dbus/org.SGLogin.Sessiond1.xml"),),
            )
            .await;
    }
    if interface != "org.SGLogin.Sessiond1.Manager" {
        return connection
            .reply_dbus_error(
                &header,
                zbus::fdo::Error::UnknownInterface(interface.into()),
            )
            .await;
    }
    match member {
        "ListSessions" => {
            args!(());
            respond!(manager.list_sessions().await.map(|rows| (rows,)))
        }
        "GetSession" => {
            let (sid,) = args!((String,));
            respond!(manager.get_session(sid).await.map(|row| (row,)))
        }
        "GetSessionByPid" => {
            let (pid, start) = args!((u32, u64));
            respond!(
                manager
                    .get_session_by_pid(pid, start)
                    .await
                    .map(|row| (row,))
            )
        }
        "GetSessionMasterPid" => {
            let (sid,) = args!((String,));
            respond!(manager.get_session_master_pid(sid).await)
        }
        "GetSessionAttrs" => {
            let (sid,) = args!((String,));
            respond!(manager.get_session_attrs(sid).await.map(|attrs| (attrs,)))
        }
        "EnsureSessionReady" => {
            args!(());
            respond!(
                manager
                    .ensure_session_ready(connection, header.clone())
                    .await
                    .map(|row| (row,))
            )
        }
        "UpdateSessionAttrs" => {
            let (sid, set, remove) = args!((String, Attributes, Vec<String>));
            respond!(
                manager
                    .update_session_attrs(sid, set, remove, connection, header.clone())
                    .await
            )
        }
        "ScheduleCloseSession" => {
            args!(());
            respond!(
                manager
                    .schedule_close_session(connection, header.clone())
                    .await
            )
        }
        "CloseSession" => {
            let (sid,) = args!((String,));
            respond!(manager.close_session(sid, connection, header.clone()).await)
        }
        _ => {
            connection
                .reply_dbus_error(&header, zbus::fdo::Error::UnknownMethod(member.into()))
                .await
        }
    }
}
