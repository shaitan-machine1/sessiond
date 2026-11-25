//! Caller-driven libdbus transport: no executor, background thread or lifecycle lock.
use crate::{Attributes, Error, ErrorCode, Result, SessionInfo, validate_session_id};
use dbus::blocking::Connection;
use dbus::channel::{MatchingReceiver, Token};
use dbus::message::MatchRule;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
pub const BUS_NAME: &str = "org.SGLogin.Sessiond1";
pub const INTERFACE_NAME: &str = "org.SGLogin.Sessiond1.Manager";
pub const OBJECT_PATH: &str = "/org/SGLogin/Sessiond1";
pub const ERROR_PREFIX: &str = "org.SGLogin.Sessiond1.Error.";
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bus {
    System,
    Session,
    Address(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    SessionNew { sid: String, uid: u32 },
    SessionRemoved { sid: String, uid: u32 },
    OwnerReplaced,
    Overflow,
}
#[derive(Default)]
struct Events {
    queue: VecDeque<Event>,
    invalidated: bool,
}
impl Events {
    fn invalidate(&mut self, reason: Event) {
        self.invalidated = true;
        self.queue.clear();
        self.queue.push_back(reason);
    }
    fn lifecycle(&mut self, event: Event) {
        if self.invalidated {
            return;
        }
        if self.queue.len() >= 128 {
            self.invalidate(Event::Overflow);
        } else {
            self.queue.push_back(event);
        }
    }
}
/// Owned by the creating process: never inherit/use after fork. Serialize access
/// externally. Subscribe BEFORE querying; explicitly pump lifecycle hints. Any
/// invalidation requires a NEW verified client/subscription and fresh inventory.
pub struct Client {
    connection: Connection,
    owner: String,
    timeout: Duration,
    events: Arc<Mutex<Events>>,
    subscribed: bool,
    buffered: Cell<bool>,
}
impl Client {
    pub fn system(timeout: Duration) -> Result<Self> {
        Self::new(Bus::System, timeout)
    }
    pub fn new(bus: Bus, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "timeout must be in (0, 1 hour]",
            ));
        }
        let mut channel = match bus {
            Bus::System => dbus::channel::Channel::get_private(dbus::channel::BusType::System),
            Bus::Session => dbus::channel::Channel::get_private(dbus::channel::BusType::Session),
            Bus::Address(address) => {
                let mut channel = dbus::channel::Channel::open_private(&address).map_err(remote)?;
                channel.register().map_err(remote)?;
                Ok(channel)
            }
        }
        .map_err(remote)?;
        channel.set_watch_enabled(true);
        let connection = Connection::from(channel);
        let owner = name_owner(&connection, timeout)?;
        let (uid,): (u32,) = bus_call(&connection, timeout, "GetConnectionUnixUser", (&owner,))?;
        if uid != 0 {
            return Err(Error::new(
                ErrorCode::NotAuthorized,
                "sessiond unique owner is not root",
            ));
        }
        if name_owner(&connection, timeout)? != owner {
            return Err(Error::new(
                ErrorCode::Transport,
                "sessiond owner changed during authentication",
            ));
        }
        Ok(Self {
            connection,
            owner,
            timeout,
            events: Arc::default(),
            subscribed: false,
            buffered: Cell::new(true),
        })
    }
    fn valid(&self) -> Result<()> {
        if self
            .events
            .lock()
            .expect("event mutex poisoned")
            .invalidated
        {
            return Err(Error::new(
                ErrorCode::Transport,
                "subscription invalidated; create a new verified client and query fresh inventory",
            ));
        }
        Ok(())
    }
    fn rpc<R: dbus::arg::ReadAll, A: dbus::arg::AppendAll>(
        &self,
        method: &str,
        args: A,
    ) -> Result<R> {
        self.verify_owner()?;
        self.buffered.set(true);
        self.connection
            .with_proxy(&self.owner, OBJECT_PATH, self.timeout)
            .method_call(INTERFACE_NAME, method, args)
            .map_err(remote)
    }
    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let (rows,): (Vec<(String, u32, String)>,) = self.rpc("ListSessions", ())?;
        Ok(rows.into_iter().map(info).collect())
    }
    pub fn get_session(&self, sid: &str) -> Result<SessionInfo> {
        validate_session_id(sid)?;
        let (row,) = self.rpc("GetSession", (sid,))?;
        Ok(info(row))
    }
    pub fn get_session_by_pid(&self, pid: u32, start_time: u64) -> Result<SessionInfo> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(Error::new(ErrorCode::InvalidArgument, "invalid PID"));
        }
        let (row,) = self.rpc("GetSessionByPid", (pid, start_time))?;
        Ok(info(row))
    }
    pub fn get_session_master_pid(&self, sid: &str) -> Result<(u32, u64)> {
        validate_session_id(sid)?;
        self.rpc("GetSessionMasterPid", (sid,))
    }
    pub fn get_session_attrs(&self, sid: &str) -> Result<Attributes> {
        validate_session_id(sid)?;
        let (map,) = self.rpc("GetSessionAttrs", (sid,))?;
        Ok(map)
    }
    pub fn get_session_attribute(&self, sid: &str, name: &str) -> Result<Option<String>> {
        Ok(self.get_session_attrs(sid)?.remove(name))
    }
    pub fn ensure_session_ready(&self) -> Result<SessionInfo> {
        let (row,) = self.rpc("EnsureSessionReady", ())?;
        Ok(info(row))
    }
    pub fn update_session_attrs(
        &self,
        sid: &str,
        set: &Attributes,
        remove: &[String],
    ) -> Result<()> {
        validate_session_id(sid)?;
        self.rpc("UpdateSessionAttrs", (sid, set, remove))
    }
    pub fn schedule_close_session(&self) -> Result<()> {
        self.rpc("ScheduleCloseSession", ())
    }
    pub fn verify_owner(&self) -> Result<()> {
        self.valid()?;
        self.buffered.set(true);
        if name_owner(&self.connection, self.timeout)? != self.owner {
            self.events
                .lock()
                .expect("event mutex poisoned")
                .invalidate(Event::OwnerReplaced);
            return Err(Error::new(ErrorCode::Transport, "sessiond owner replaced"));
        }
        Ok(())
    }
    /// No asynchronous RPC timers: None means no transport deadline.
    pub fn poll_state(&self) -> (dbus::channel::Watch, bool, Option<Duration>) {
        (
            self.connection.channel().watch(),
            self.buffered.get()
                || !self
                    .events
                    .lock()
                    .expect("event mutex poisoned")
                    .queue
                    .is_empty(),
            None,
        )
    }
    pub fn dispatch(&self, limit: usize) -> Result<bool> {
        if !(1..=256).contains(&limit) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "dispatch limit must be 1..256",
            ));
        }
        for _ in 0..limit {
            if !self.connection.process(Duration::ZERO).map_err(remote)? {
                self.buffered.set(false);
                return Ok(false);
            }
        }
        self.buffered.set(true);
        Ok(true)
    }
    pub fn close_session(&self, sid: &str) -> Result<()> {
        validate_session_id(sid)?;
        self.rpc("CloseSession", (sid,))
    }
    pub fn subscribe(&mut self) -> Result<()> {
        self.valid()?;
        if self.subscribed {
            return Ok(());
        }
        let mut matches = InstalledMatches {
            connection: &self.connection,
            timeout: self.timeout,
            entries: Vec::new(),
            committed: false,
        };
        let events = self.events.clone();
        let mut rule = MatchRule::new_signal("org.freedesktop.DBus", "NameOwnerChanged");
        rule.sender = Some("org.freedesktop.DBus".into());
        rule.path = Some("/org/freedesktop/DBus".into());
        matches.add(rule, move |message, _| {
            if let Ok((name, _, _)) = message.read3::<String, String, String>()
                && name == BUS_NAME
            {
                events
                    .lock()
                    .expect("event mutex poisoned")
                    .invalidate(Event::OwnerReplaced);
            }
            true
        })?;
        for (member, added) in [("SessionNew", true), ("SessionRemoved", false)] {
            let mut rule = MatchRule::new_signal(INTERFACE_NAME, member);
            rule.sender = Some(self.owner.clone().into());
            rule.path = Some(OBJECT_PATH.into());
            let events = self.events.clone();
            matches.add(rule, move |message, _| {
                if let Ok((sid, uid)) = message.read2::<String, u32>()
                    && validate_session_id(&sid).is_ok()
                {
                    events
                        .lock()
                        .expect("event mutex poisoned")
                        .lifecycle(if added {
                            Event::SessionNew { sid, uid }
                        } else {
                            Event::SessionRemoved { sid, uid }
                        });
                }
                true
            })?;
        }
        match name_owner(&self.connection, self.timeout) {
            Ok(owner) if owner == self.owner => {}
            _ => {
                self.events
                    .lock()
                    .expect("event mutex poisoned")
                    .invalidate(Event::OwnerReplaced);
                return Err(Error::new(
                    ErrorCode::Transport,
                    "sessiond owner changed while subscribing",
                ));
            }
        }
        matches.committed = true;
        self.subscribed = true;
        Ok(())
    }
    /// NULL/None means no event yet, not completion of any lifecycle operation.
    pub fn next_event(&self, wait: Duration) -> Result<Option<Event>> {
        if !self.subscribed {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "subscribe before pumping events",
            ));
        }
        if let Some(event) = self
            .events
            .lock()
            .expect("event mutex poisoned")
            .queue
            .pop_front()
        {
            return Ok(Some(event));
        }
        let processed = self
            .connection
            .process(wait.min(self.timeout))
            .map_err(remote)?;
        self.buffered.set(processed);
        Ok(self
            .events
            .lock()
            .expect("event mutex poisoned")
            .queue
            .pop_front())
    }
}
// Failed subscriptions remove every provisional callback/rule; retry cannot
// accumulate callbacks. All AddMatch/RemoveMatch calls use the chosen timeout.
struct InstalledMatches<'a> {
    connection: &'a Connection,
    timeout: Duration,
    entries: Vec<(Token, String)>,
    committed: bool,
}
impl InstalledMatches<'_> {
    fn add(
        &mut self,
        rule: MatchRule<'static>,
        callback: impl FnMut(dbus::Message, &Connection) -> bool + Send + 'static,
    ) -> Result<()> {
        let text = rule.match_str();
        let (): () = bus_call(self.connection, self.timeout, "AddMatch", (&text,))?;
        let token = self.connection.start_receive(rule, Box::new(callback));
        self.entries.push((token, text));
        Ok(())
    }
}
impl Drop for InstalledMatches<'_> {
    fn drop(&mut self) {
        if !self.committed {
            for (token, text) in self.entries.drain(..) {
                self.connection.stop_receive(token);
                let _: Result<()> =
                    bus_call(self.connection, self.timeout, "RemoveMatch", (&text,));
            }
        }
    }
}
fn bus_call<R: dbus::arg::ReadAll, A: dbus::arg::AppendAll>(
    connection: &Connection,
    timeout: Duration,
    method: &str,
    args: A,
) -> Result<R> {
    connection
        .with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", timeout)
        .method_call("org.freedesktop.DBus", method, args)
        .map_err(remote)
}
fn name_owner(connection: &Connection, timeout: Duration) -> Result<String> {
    let (owner,) = bus_call(connection, timeout, "GetNameOwner", (BUS_NAME,))?;
    Ok(owner)
}
fn info((sid, uid, runtime_dir): (String, u32, String)) -> SessionInfo {
    SessionInfo {
        sid,
        uid,
        runtime_dir,
    }
}
fn remote(error: dbus::Error) -> Error {
    let name = error.name().unwrap_or("");
    let code = name
        .strip_prefix(ERROR_PREFIX)
        .map_or(ErrorCode::Transport, |local| {
            ErrorCode::from_name(local).unwrap_or(ErrorCode::UnknownRemote)
        });
    Error {
        code,
        message: error.message().unwrap_or("D-Bus failure").to_owned(),
        remote_name: error.name().map(str::to_owned),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflow_is_bounded_invalidates_and_stops_accepting_hints() {
        let mut state = Events::default();
        for _ in 0..129 {
            state.lifecycle(Event::SessionNew {
                sid: "a".repeat(32),
                uid: 1000,
            });
        }
        assert!(state.invalidated);
        assert_eq!(state.queue, VecDeque::from([Event::Overflow]));
        state.lifecycle(Event::SessionRemoved {
            sid: "a".repeat(32),
            uid: 1000,
        });
        assert_eq!(state.queue.len(), 1);
    }
    #[test]
    fn named_remote_and_transport_errors_are_not_lost_or_reclassified_as_absence() {
        for (name, code) in [
            (
                "org.SGLogin.Sessiond1.Error.MasterNotRecorded",
                ErrorCode::MasterNotRecorded,
            ),
            (
                "org.SGLogin.Sessiond1.Error.FutureError",
                ErrorCode::UnknownRemote,
            ),
            ("org.freedesktop.DBus.Error.NoReply", ErrorCode::Transport),
        ] {
            let error = remote(dbus::Error::new_custom(name, "test"));
            assert_eq!(error.code, code);
            assert_eq!(error.remote_name.as_deref(), Some(name));
        }
    }
}
