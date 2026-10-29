use crate::scheduler::Scheduler;
use dbus::blocking::{Connection, SyncConnection};
use dbus::channel::MatchingReceiver;
use dbus::message::{MatchRule, Message};
use dbus_crossroads::{Context, Crossroads, MethodErr};
use lib_sessiond::bus::{BUS_NAME, Bus, INTERFACE_NAME, OBJECT_PATH};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

struct Authorization {
    connection: Mutex<Connection>,
}
impl Authorization {
    fn new(bus: Bus) -> Result<Self, dbus::Error> {
        let connection = match bus {
            Bus::System => Connection::new_system()?,
            Bus::Session => Connection::new_session()?,
        };
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
    fn require_root(&self, message: &Message) -> Result<(), MethodErr> {
        let sender = message
            .sender()
            .ok_or_else(|| denied("message has no sender"))?
            .to_string();
        let connection = self
            .connection
            .lock()
            .map_err(|_| backend(&"authorization connection mutex poisoned"))?;
        let proxy = connection.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_secs(5),
        );
        let (uid,): (u32,) = proxy
            .method_call("org.freedesktop.DBus", "GetConnectionUnixUser", (sender,))
            .map_err(|e| backend(&e))?;
        if uid == 0 {
            Ok(())
        } else {
            Err(denied("session mutation is root-only"))
        }
    }
}
fn denied(message: &str) -> MethodErr {
    ("org.decoupling.sessiond1.Error.AccessDenied", message).into()
}
fn backend(message: &dyn std::fmt::Display) -> MethodErr {
    (
        "org.decoupling.sessiond1.Error.BackendFailure",
        message.to_string(),
    )
        .into()
}
struct WaitReply {
    context: Context,
    operation: Arc<crate::scheduler::Operation>,
    _permit: crate::scheduler::WaiterPermit,
}
fn reply_workers(connection: Arc<SyncConnection>) -> mpsc::SyncSender<WaitReply> {
    let (sender, receiver) = mpsc::sync_channel::<WaitReply>(128);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..8 {
        let receiver = receiver.clone();
        let connection = connection.clone();
        std::thread::Builder::new()
            .name(format!("sessiond-reply-{index}"))
            .spawn(move || {
                loop {
                    let item = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(mut item) = item else {
                        return;
                    };
                    item.context
                        .reply(item.operation.wait().map(|_| ()).map_err(|e| backend(&e)));
                    let _ = item.context.flush_messages(connection.as_ref());
                    connection.channel().flush();
                }
            })
            .expect("spawn D-Bus reply worker");
    }
    sender
}

pub fn serve(
    bus: Bus,
    scheduler: Scheduler,
    discovery_hints: mpsc::SyncSender<()>,
    stopping: &AtomicBool,
) -> anyhow::Result<()> {
    let connection = Arc::new(match bus {
        Bus::System => SyncConnection::new_system()?,
        Bus::Session => SyncConnection::new_session()?,
    });
    match connection.request_name(BUS_NAME, false, false, true)? {
        dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply::PrimaryOwner => {}
        other => anyhow::bail!("{BUS_NAME} is already owned on this bus ({other:?})"),
    }
    let authorization = Arc::new(Authorization::new(bus)?);
    let reply_queue = reply_workers(connection.clone());
    let mut crossroads = Crossroads::new();
    let interface = crossroads.register(INTERFACE_NAME, |builder| {
        let close_scheduler = scheduler.clone();
        let close_authorization = authorization.clone();
        builder.method(
            "CloseSession",
            ("sid",),
            (),
            move |context, _, (sid,): (String,)| {
                close_authorization.require_root(context.message())?;
                close_scheduler.schedule(&sid).map_err(|e| backend(&e))?;
                Ok(())
            },
        );
        let schedule_scheduler = scheduler.clone();
        let schedule_authorization = authorization.clone();
        builder.method(
            "ScheduleCloseSession",
            ("sid",),
            (),
            move |context, _, (sid,): (String,)| {
                schedule_authorization.require_root(context.message())?;
                schedule_scheduler.schedule(&sid).map_err(|e| backend(&e))?;
                Ok(())
            },
        );
        let wait_scheduler = scheduler.clone();
        let wait_authorization = authorization.clone();
        let wait_reply_queue = reply_queue.clone();
        builder.method_with_cr_custom::<(String,), (), _, _>(
            "CloseSessionAndWait",
            ("sid",),
            (),
            move |mut context, _, (sid,)| {
                if let Err(error) = wait_authorization.require_root(context.message()) {
                    context.reply::<()>(Err(error));
                    return Some(context);
                }
                let operation = match wait_scheduler.schedule(&sid) {
                    Ok(operation) => operation,
                    Err(error) => {
                        context.reply::<()>(Err(backend(&error)));
                        return Some(context);
                    }
                };
                let Some(operation) = operation else {
                    context.reply(Ok(()));
                    return Some(context);
                };
                let permit = match wait_scheduler.acquire_waiter() {
                    Ok(permit) => permit,
                    Err(error) => {
                        context.reply::<()>(Err(backend(&error)));
                        return Some(context);
                    }
                };
                match wait_reply_queue.try_send(WaitReply {
                    context,
                    operation,
                    _permit: permit,
                }) {
                    Ok(()) => None,
                    Err(mpsc::TrySendError::Full(mut item)) => {
                        item.context
                            .reply::<()>(Err(backend(&"blocking close reply queue is full")));
                        Some(item.context)
                    }
                    Err(mpsc::TrySendError::Disconnected(mut item)) => {
                        item.context.reply::<()>(Err(backend(
                            &"blocking close reply workers are unavailable",
                        )));
                        Some(item.context)
                    }
                }
            },
        );
        let scheduler = scheduler.clone();
        builder.method("ListSessions", (), ("sessions",), move |_, _, ()| {
            let sessions = scheduler
                .core()
                .list_sessions()
                .map_err(|e| backend(&e))?
                .into_iter()
                .map(|session| (session.id, session.uid))
                .collect::<Vec<_>>();
            Ok((sessions,))
        });
        builder.signal::<(&str, u32), _>("SessionNew", ("sid", "uid"));
        builder.signal::<(&str, u32), _>("SessionRemoved", ("sid", "uid"));
    });
    crossroads.insert(OBJECT_PATH, &[interface], ());
    let crossroads = Arc::new(Mutex::new(crossroads));
    let dispatch = crossroads.clone();
    connection.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |message, connection| {
            match dispatch.lock() {
                Ok(mut crossroads) => {
                    let _ = crossroads.handle_message(message, connection);
                }
                Err(_) => tracing::error!("D-Bus crossroads mutex poisoned"),
            }
            true
        }),
    );
    let mut signal = MatchRule::new_signal(INTERFACE_NAME, "SessionNew");
    signal.path = Some(OBJECT_PATH.into());
    connection.add_match::<(String, u32), _>(signal, move |_, _, _| {
        let _ = discovery_hints.try_send(());
        true
    })?;
    tracing::info!(bus_name = BUS_NAME, "sessiond ready");
    while !stopping.load(Ordering::Relaxed) {
        connection.process(Duration::from_millis(250))?;
    }
    Ok(())
}
