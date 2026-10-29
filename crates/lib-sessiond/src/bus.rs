//! Synchronous D-Bus clients and lifecycle signal publication.
//! No connection starts a background executor or transport thread.
use crate::{Error, LifecycleEvents, Result, SessionIdentity};
use dbus::blocking::{Connection, Proxy};
use dbus::channel::Sender;
use dbus::message::Message;
use dbus::strings::{Interface, Member, Path};
use std::sync::Mutex;
use std::time::Duration;

pub const BUS_NAME: &str = "org.decoupling.sessiond1";
pub const INTERFACE_NAME: &str = "org.decoupling.sessiond1.Manager";
pub const OBJECT_PATH: &str = "/org/decoupling/sessiond1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bus {
    System,
    Session,
}
fn connect(bus: Bus) -> std::result::Result<Connection, dbus::Error> {
    match bus {
        Bus::System => Connection::new_system(),
        Bus::Session => Connection::new_session(),
    }
}

/// Root-side lifecycle publication. Signals intentionally have no well-known
/// sender: listeners match type/interface/path/member, as PAM does not own the
/// daemon name.
pub struct BusLifecycleEvents {
    bus: Bus,
    connection: Mutex<Option<Connection>>,
}
impl BusLifecycleEvents {
    pub fn system() -> Self {
        Self::new(Bus::System)
    }
    pub fn new(bus: Bus) -> Self {
        Self {
            bus,
            connection: Mutex::new(None),
        }
    }
    fn emit(&self, member: &str, session: &SessionIdentity) -> Result<()> {
        let path = Path::new(OBJECT_PATH).expect("literal object path");
        let interface = Interface::new(INTERFACE_NAME).expect("literal interface");
        let member = Member::new(member).expect("literal member");
        let mut message = Message::signal(&path, &interface, &member);
        message = message.append2(session.id.as_str(), session.uid);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| Error::Transport("lifecycle bus mutex poisoned".into()))?;
        if connection.is_none() {
            *connection = Some(connect(self.bus).map_err(transport)?);
        }
        if connection
            .as_ref()
            .expect("connected lifecycle bus")
            .send(message)
            .is_err()
        {
            *connection = None;
            return Err(Error::Transport("send lifecycle signal".into()));
        }
        connection
            .as_ref()
            .expect("connected lifecycle bus")
            .channel()
            .flush();
        Ok(())
    }
}
impl LifecycleEvents for BusLifecycleEvents {
    fn session_new(&self, session: &SessionIdentity) -> Result<()> {
        self.emit("SessionNew", session)
    }
    fn session_removed(&self, session: &SessionIdentity) -> Result<()> {
        self.emit("SessionRemoved", session)
    }
}

/// Blocking daemon client. Callers choose a finite transport timeout. A client
/// timeout never cancels cleanup already accepted by the daemon.
pub struct Client {
    connection: Connection,
    timeout: Duration,
}
impl Client {
    pub fn system(timeout: Duration) -> Result<Self> {
        Self::new(Bus::System, timeout)
    }
    pub fn new(bus: Bus, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::Transport("D-Bus timeout must be nonzero".into()));
        }
        Ok(Self {
            connection: connect(bus).map_err(transport)?,
            timeout,
        })
    }
    fn proxy(&self) -> Proxy<'static, &Connection> {
        self.connection
            .with_proxy(BUS_NAME, OBJECT_PATH, self.timeout)
    }
    pub fn schedule_close_session(&self, sid: &str) -> Result<()> {
        crate::validate_session_id(sid)?;
        let _: () = self
            .proxy()
            .method_call(INTERFACE_NAME, "ScheduleCloseSession", (sid,))
            .map_err(transport)?;
        Ok(())
    }
    /// Compatibility method with scheduling-only semantics.
    pub fn close_session_scheduled(&self, sid: &str) -> Result<()> {
        crate::validate_session_id(sid)?;
        let _: () = self
            .proxy()
            .method_call(INTERFACE_NAME, "CloseSession", (sid,))
            .map_err(transport)?;
        Ok(())
    }
    pub fn close_session(&self, sid: &str) -> Result<()> {
        crate::validate_session_id(sid)?;
        let _: () = self
            .proxy()
            .method_call(INTERFACE_NAME, "CloseSessionAndWait", (sid,))
            .map_err(transport)?;
        Ok(())
    }
    pub fn list_sessions_legacy(&self) -> Result<Vec<(String, u32)>> {
        let (sessions,): (Vec<(String, u32)>,) = self
            .proxy()
            .method_call(INTERFACE_NAME, "ListSessions", ())
            .map_err(transport)?;
        Ok(sessions)
    }
}
fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_names_remain_stable() {
        assert_eq!(BUS_NAME, "org.decoupling.sessiond1");
        assert_eq!(INTERFACE_NAME, "org.decoupling.sessiond1.Manager");
        assert_eq!(OBJECT_PATH, "/org/decoupling/sessiond1");
    }
}
