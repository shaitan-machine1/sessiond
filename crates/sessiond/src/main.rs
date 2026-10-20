use anyhow::Context;
use clap::{Parser, ValueEnum};
use sessiond::config::Config;
use sessiond::dbus::{BUS_NAME, Manager, OBJECT_PATH};
use sessiond::launcher::RealLauncher;
use sessiond::manager::{Event, SessionManager};
use sessiond::runtime::FsRuntimeStore;
use sessiond::scoped::RealScoped;
use std::path::PathBuf;
use std::sync::Arc;
use zbus::object_server::SignalEmitter;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Bus {
    System,
    Session,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "/etc/sessiond/sessiond.toml")]
    config: PathBuf,
    #[arg(long, value_enum, default_value = "system", hide = true)]
    bus: Bus,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sessiond=info".into()),
        )
        .init();
    let args = Args::parse();
    let config = if args.config.exists() {
        Config::load(&args.config)?
    } else {
        let config = Config::default();
        config.validate()?;
        config
    };

    let connection = match args.bus {
        Bus::System => zbus::Connection::system().await?,
        Bus::Session => zbus::Connection::session().await?,
    };
    let scoped = RealScoped::new(connection.clone()).await?;
    let runtime = Arc::new(FsRuntimeStore::new(
        config.runtime_parent.clone(),
        config.state_dir.clone(),
    ));
    let launcher = Arc::new(RealLauncher::new(
        scoped.clone(),
        config.user_service_manager.launcher.clone(),
        config.user_service_manager.entrypoint.clone(),
        config.user_service_manager.ready_timeout,
    ));
    let manager = SessionManager::new(scoped.clone(), runtime, launcher, config);
    manager
        .reconcile()
        .await
        .context("startup reconciliation failed")?;

    connection
        .object_server()
        .at(OBJECT_PATH, Manager::new(manager.clone()))
        .await?;
    // Not zbus's default flags (ALLOW_REPLACEMENT | REPLACE_EXISTING |
    // DO_NOT_QUEUE): those let a second instance steal the name from the
    // running daemon, which keeps running unreachable while the supervisor
    // still sees it as healthy. Duplicates must fail instead.
    match connection
        .request_name_with_flags(BUS_NAME, zbus::fdo::RequestNameFlags::DO_NOT_QUEUE)
        .await
    {
        Ok(_) => {}
        Err(zbus::Error::NameTaken) => {
            anyhow::bail!("{BUS_NAME} is already owned on this bus; another sessiond is running")
        }
        Err(e) => return Err(e.into()),
    }

    let emitter = SignalEmitter::new(&connection, OBJECT_PATH)?;
    let mut events = manager.subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(Event::SessionNew { sid, uid }) => {
                    let _ = Manager::session_new(&emitter, &sid, uid).await;
                }
                Ok(Event::SessionRemoved { sid, uid }) => {
                    let _ = Manager::session_removed(&emitter, &sid, uid).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(count, "session event forwarding lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });

    let mut target_events = scoped.subscribe_targets();
    let target_manager = manager.clone();
    tokio::spawn(async move {
        loop {
            match target_events.recv().await {
                Ok((scope, target)) if target == "leader" => {
                    if let Some(sid) = target_manager.session_for_scope(&scope).await
                        && let Err(error) = target_manager.request_close(&sid).await
                    {
                        tracing::error!(%sid, %error, "leader-loss teardown request failed");
                    }
                }
                Ok((scope, target)) if target == "manager" => {
                    tracing::warn!(%scope, "user manager exited; it will not be restarted while sessions remain");
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(count, "target lifecycle handling lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });

    let mut drain_events = scoped.subscribe_drains();
    let drain_manager = manager.clone();
    tokio::spawn(async move {
        loop {
            match drain_events.recv().await {
                Ok(scope) => {
                    if let Some(sid) = drain_manager.session_for_scope(&scope).await
                        && let Err(error) = drain_manager.request_close(&sid).await
                    {
                        tracing::error!(%sid, %error, "scope-drain teardown request failed");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(count, "scope lifecycle handling lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });

    tracing::info!(bus_name = BUS_NAME, "sessiond ready");
    // Losing the bus connection means losing the name and every session
    // operation with it, so exit and let the supervisor restart us;
    // `reconcile` rebuilds state from the runtime store on the way back up.
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        () = connection.closed() => anyhow::bail!("lost the D-Bus connection"),
    }
    Ok(())
}
