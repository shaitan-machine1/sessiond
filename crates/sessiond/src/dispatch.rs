//! Wire admission precedes task creation. zbus's default ObjectServer spawns
//! an unbounded task per method call BEFORE invoking Interface::call, so do not
//! register Manager with it. This pump owns a bounded set of request futures;
//! the fixed effect workers retain admitted work independently of wire replies.
use crate::{
    core::Signal,
    dbus::{self, BUS_NAME, Manager},
    scheduler::Scheduler,
};
use futures_util::StreamExt;
use std::time::Duration;
use zbus::message::Type;
pub async fn serve(
    session_bus: bool,
    scheduler: Scheduler,
    mut signals: tokio::sync::mpsc::Receiver<Signal>,
) -> anyhow::Result<()> {
    let builder = if session_bus {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    // No serve_at/object_server call: no unbounded automatic dispatch tasks.
    let connection = builder
        .max_queued(128)
        .method_timeout(Duration::from_secs(5))
        .build()
        .await?;
    let mut messages = zbus::MessageStream::from(&connection);
    // Activate the receiver BEFORE owning the name; do not lose startup calls.
    let reply = zbus::fdo::DBusProxy::new(&connection)
        .await?
        .request_name(
            BUS_NAME.try_into()?,
            zbus::fdo::RequestNameFlags::DoNotQueue.into(),
        )
        .await?;
    anyhow::ensure!(
        matches!(
            reply,
            zbus::fdo::RequestNameReply::PrimaryOwner | zbus::fdo::RequestNameReply::AlreadyOwner
        ),
        "sessiond bus name is already owned"
    );
    // Manager child reaping is not session-master observation or reconciliation.
    let mut reap = tokio::time::interval(Duration::from_millis(50));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let emitter_connection = connection.clone();
    let emitter = tokio::spawn(async move {
        while let Some(signal) = signals.recv().await {
            if let Err(error) = dbus::emit(&emitter_connection, signal).await {
                tracing::warn!(%error, "lifecycle hint send failed");
            }
        }
    });
    let mut calls = tokio::task::JoinSet::new();
    tracing::info!(bus_name = BUS_NAME, "sessiond ready");
    let result = loop {
        // Eagerly reap completed handles before accepting another message; even
        // a continuous flood cannot accumulate completed JoinSet entries.
        while let Some(result) = calls.try_join_next() {
            check_task(result);
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = term.recv() => break Ok(()),
            _ = reap.tick() => scheduler.core().reap_workers(),
            _ = hup.recv() => break Ok(()),
            Some(result) = calls.join_next(), if !calls.is_empty() => check_task(result),
            next = messages.next() => {
                let message = match next { Some(Ok(message)) => message, Some(Err(error)) => break Err(error.into()), None => break Err(anyhow::anyhow!("system bus disconnected")) };
                let header = message.header();
                if header.message_type() == Type::Signal
                    && header.sender().is_some_and(|s| s.as_str() == "org.freedesktop.DBus")
                    && header.member().is_some_and(|m| m.as_str() == "NameLost")
                    && message.body().deserialize::<(String,)>().is_ok_and(|(name,)| name == BUS_NAME)
                { break Err(anyhow::anyhow!("lost sessiond bus ownership")); }
                if header.message_type() != Type::MethodCall { continue; }
                match scheduler.admit() {
                    Ok(permit) => {
                        let manager = Manager::new(scheduler.clone(), permit);
                        let connection = connection.clone();
                        calls.spawn(async move {
                            if let Err(error) = dbus::handle(manager, &connection, message).await { tracing::warn!(%error, "method reply failed; admitted effects are retained"); }
                        });
                    },
                    Err(error) => {
                        if let Err(error) = connection.reply_dbus_error(&header, dbus::WireError::from(error)).await { break Err(error.into()); }
                    },
                }
            },
        }
    };
    scheduler.stop_admission();
    calls.abort_all();
    while calls.join_next().await.is_some() {}
    emitter.abort();
    let _ = emitter.await;
    drop(messages);
    let close = connection.close().await;
    result?;
    close?;
    Ok(())
}
fn check_task(result: std::result::Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        assert!(!error.is_panic(), "wire worker panicked: {error}");
    }
}
