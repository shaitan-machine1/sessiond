use async_trait::async_trait;
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use zbus::Connection;

use crate::config::{ShutdownConfig, ShutdownMode};

pub const SCOPED_BUS_NAME: &str = "org.decoupling.scoped1";
pub const SCOPED_OBJECT_PATH: &str = "/org/decoupling/scoped1";

#[derive(Debug, thiserror::Error)]
pub enum ScopedError {
    #[error("scope does not exist")]
    NotFound,
    #[error("scope already exists")]
    AlreadyExists,
    #[error("scoped operation failed: {0}")]
    Other(String),
}

#[async_trait]
pub trait DrainWatch: Send {
    async fn wait(&mut self, timeout: Duration) -> bool;
}

#[async_trait]
pub trait ScopedApi: Send + Sync {
    async fn create(&self, id: &str) -> Result<(), ScopedError>;
    async fn move_pid(&self, pid: u32, id: &str, target: &str) -> Result<(), ScopedError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ScopedError>;
    async fn target_exists(&self, id: &str, target: &str) -> Result<bool, ScopedError>;
    async fn scope_populated(&self, id: &str) -> Result<bool, ScopedError>;
    async fn terminate_target(&self, id: &str, target: &str) -> Result<(), ScopedError>;
    async fn terminate_scope(&self, id: &str) -> Result<(), ScopedError>;
    async fn kill_scope(&self, id: &str) -> Result<(), ScopedError>;
    fn watch_drain(&self, id: &str) -> Box<dyn DrainWatch>;
}

#[zbus::proxy(
    interface = "org.decoupling.scoped1.Manager",
    default_service = "org.decoupling.scoped1",
    default_path = "/org/decoupling/scoped1"
)]
trait ScopedDbus {
    fn create(&self, id: &str) -> zbus::Result<()>;
    #[zbus(name = "Move")]
    fn move_pid(&self, pid: u32, id: &str, target: &str) -> zbus::Result<()>;
    fn list(&self, prefix: &str) -> zbus::Result<Vec<String>>;
    fn target_exists(&self, id: &str, target: &str) -> zbus::Result<bool>;
    fn scope_populated(&self, id: &str) -> zbus::Result<bool>;
    fn terminate_target(&self, id: &str, target: &str) -> zbus::Result<()>;
    fn terminate_scope(&self, id: &str) -> zbus::Result<()>;
    fn kill_scope(&self, id: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn target_gone(&self, id: &str, target: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    fn scope_empty(&self, id: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    fn scope_removed(&self, id: &str) -> zbus::Result<()>;
}

pub struct RealScoped {
    connection: Connection,
    drains: broadcast::Sender<String>,
    targets: broadcast::Sender<(String, String)>,
}

impl RealScoped {
    pub async fn new(connection: Connection) -> Result<Arc<Self>, ScopedError> {
        let (drains, _) = broadcast::channel(256);
        let (targets, _) = broadcast::channel(256);
        let this = Arc::new(Self {
            connection,
            drains,
            targets,
        });
        let monitor = this.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Err(error) = monitor.monitor(ready_tx).await {
                tracing::error!(%error, "scoped lifecycle monitor ended");
                std::process::exit(1);
            }
        });
        ready_rx
            .await
            .map_err(|_| ScopedError::Other("scoped lifecycle monitor failed to start".into()))?;
        Ok(this)
    }

    pub fn subscribe_targets(&self) -> broadcast::Receiver<(String, String)> {
        self.targets.subscribe()
    }

    pub fn subscribe_drains(&self) -> broadcast::Receiver<String> {
        self.drains.subscribe()
    }

    async fn proxy(&self) -> Result<ScopedDbusProxy<'_>, ScopedError> {
        ScopedDbusProxy::new(&self.connection)
            .await
            .map_err(map_error)
    }

    async fn monitor(&self, ready: tokio::sync::oneshot::Sender<()>) -> Result<(), ScopedError> {
        let proxy = self.proxy().await?;
        let mut empty = proxy.receive_scope_empty().await.map_err(map_error)?;
        let mut removed = proxy.receive_scope_removed().await.map_err(map_error)?;
        let mut targets = proxy.receive_target_gone().await.map_err(map_error)?;
        let _ = ready.send(());
        loop {
            tokio::select! {
                value = empty.next() => {
                    let Some(signal) = value else { return Err(ScopedError::Other("ScopeEmpty stream ended".into())); };
                    if let Ok(args) = signal.args() { let _ = self.drains.send(args.id().to_string()); }
                }
                value = removed.next() => {
                    let Some(signal) = value else { return Err(ScopedError::Other("ScopeRemoved stream ended".into())); };
                    if let Ok(args) = signal.args() { let _ = self.drains.send(args.id().to_string()); }
                }
                value = targets.next() => {
                    let Some(signal) = value else { return Err(ScopedError::Other("TargetGone stream ended".into())); };
                    if let Ok(args) = signal.args() { let _ = self.targets.send((args.id().to_string(), args.target().to_string())); }
                }
            }
        }
    }
}

struct BroadcastDrainWatch {
    id: String,
    receiver: broadcast::Receiver<String>,
}

#[async_trait]
impl DrainWatch for BroadcastDrainWatch {
    async fn wait(&mut self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                match self.receiver.recv().await {
                    Ok(id) if id == self.id => return true,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return false,
                }
            }
        })
        .await
        .unwrap_or(false)
    }
}

#[async_trait]
impl ScopedApi for RealScoped {
    async fn create(&self, id: &str) -> Result<(), ScopedError> {
        self.proxy().await?.create(id).await.map_err(map_error)
    }
    async fn move_pid(&self, pid: u32, id: &str, target: &str) -> Result<(), ScopedError> {
        self.proxy()
            .await?
            .move_pid(pid, id, target)
            .await
            .map_err(map_error)
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ScopedError> {
        self.proxy().await?.list(prefix).await.map_err(map_error)
    }
    async fn target_exists(&self, id: &str, target: &str) -> Result<bool, ScopedError> {
        self.proxy()
            .await?
            .target_exists(id, target)
            .await
            .map_err(map_error)
    }
    async fn scope_populated(&self, id: &str) -> Result<bool, ScopedError> {
        self.proxy()
            .await?
            .scope_populated(id)
            .await
            .map_err(map_error)
    }
    async fn terminate_target(&self, id: &str, target: &str) -> Result<(), ScopedError> {
        self.proxy()
            .await?
            .terminate_target(id, target)
            .await
            .map_err(map_error)
    }
    async fn terminate_scope(&self, id: &str) -> Result<(), ScopedError> {
        self.proxy()
            .await?
            .terminate_scope(id)
            .await
            .map_err(map_error)
    }
    async fn kill_scope(&self, id: &str) -> Result<(), ScopedError> {
        self.proxy().await?.kill_scope(id).await.map_err(map_error)
    }
    fn watch_drain(&self, id: &str) -> Box<dyn DrainWatch> {
        Box::new(BroadcastDrainWatch {
            id: id.to_owned(),
            receiver: self.drains.subscribe(),
        })
    }
}

fn map_error(error: zbus::Error) -> ScopedError {
    if let zbus::Error::MethodError(name, _, _) = &error {
        if name.as_str().ends_with(".ScopeNotFound") {
            return ScopedError::NotFound;
        }
        if name.as_str().ends_with(".ScopeAlreadyExists") {
            return ScopedError::AlreadyExists;
        }
    }
    ScopedError::Other(error.to_string())
}

pub async fn shutdown_scope(
    scoped: &dyn ScopedApi,
    scope: &str,
    target: &str,
    config: &ShutdownConfig,
) -> Result<(), ScopedError> {
    let mut watch = scoped.watch_drain(scope); // arm before command/query
    if config.mode == ShutdownMode::Leader {
        match scoped.target_exists(scope, target).await {
            Ok(true) => match scoped.terminate_target(scope, target).await {
                Ok(()) | Err(ScopedError::NotFound) => {}
                Err(error) => return Err(error),
            },
            Ok(false) | Err(ScopedError::NotFound) => {}
            Err(error) => return Err(error),
        }
        if drained(scoped, scope, &mut *watch, config.leader_timeout).await? {
            return Ok(());
        }
    }

    match scoped.terminate_scope(scope).await {
        Ok(()) | Err(ScopedError::NotFound) => {}
        Err(error) => return Err(error),
    }
    if drained(scoped, scope, &mut *watch, config.scope_timeout).await? {
        return Ok(());
    }
    match scoped.kill_scope(scope).await {
        Ok(()) | Err(ScopedError::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn drained(
    scoped: &dyn ScopedApi,
    scope: &str,
    watch: &mut dyn DrainWatch,
    timeout: Duration,
) -> Result<bool, ScopedError> {
    match scoped.scope_populated(scope).await {
        Ok(false) | Err(ScopedError::NotFound) => return Ok(true),
        Ok(true) => {}
        Err(error) => return Err(error),
    }
    let _ = watch.wait(timeout).await;
    match scoped.scope_populated(scope).await {
        Ok(value) => Ok(!value),
        Err(ScopedError::NotFound) => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Fake {
        calls: Arc<Mutex<Vec<&'static str>>>,
        populated: Arc<AtomicBool>,
        drain_on_wait: bool,
    }

    struct Watch {
        calls: Arc<Mutex<Vec<&'static str>>>,
        populated: Arc<AtomicBool>,
        drain: bool,
    }

    #[async_trait]
    impl DrainWatch for Watch {
        async fn wait(&mut self, _timeout: Duration) -> bool {
            self.calls.lock().unwrap().push("wait");
            if self.drain {
                self.populated.store(false, Ordering::SeqCst);
            }
            self.drain
        }
    }

    #[async_trait]
    impl ScopedApi for Fake {
        async fn create(&self, _: &str) -> Result<(), ScopedError> {
            unreachable!()
        }
        async fn move_pid(&self, _: u32, _: &str, _: &str) -> Result<(), ScopedError> {
            unreachable!()
        }
        async fn list(&self, _: &str) -> Result<Vec<String>, ScopedError> {
            unreachable!()
        }
        async fn target_exists(&self, _: &str, _: &str) -> Result<bool, ScopedError> {
            Ok(true)
        }
        async fn scope_populated(&self, _: &str) -> Result<bool, ScopedError> {
            Ok(self.populated.load(Ordering::SeqCst))
        }
        async fn terminate_target(&self, _: &str, _: &str) -> Result<(), ScopedError> {
            self.calls.lock().unwrap().push("terminate-target");
            Ok(())
        }
        async fn terminate_scope(&self, _: &str) -> Result<(), ScopedError> {
            self.calls.lock().unwrap().push("terminate-scope");
            Ok(())
        }
        async fn kill_scope(&self, _: &str) -> Result<(), ScopedError> {
            self.calls.lock().unwrap().push("kill-scope");
            self.populated.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn watch_drain(&self, _: &str) -> Box<dyn DrainWatch> {
            self.calls.lock().unwrap().push("watch");
            Box::new(Watch {
                calls: self.calls.clone(),
                populated: self.populated.clone(),
                drain: self.drain_on_wait,
            })
        }
    }

    fn fake(drain_on_wait: bool) -> Fake {
        Fake {
            calls: Arc::new(Mutex::new(Vec::new())),
            populated: Arc::new(AtomicBool::new(true)),
            drain_on_wait,
        }
    }

    #[tokio::test]
    async fn scope_mode_arms_before_terminate_and_escalates() {
        let fake = fake(false);
        let config = ShutdownConfig {
            mode: ShutdownMode::Scope,
            leader_timeout: Duration::from_millis(1),
            scope_timeout: Duration::from_millis(1),
        };
        shutdown_scope(&fake, "scope", "leader", &config)
            .await
            .unwrap();
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            ["watch", "terminate-scope", "wait", "kill-scope"]
        );
    }

    #[tokio::test]
    async fn leader_mode_stops_after_scope_drains_during_leader_budget() {
        let fake = fake(true);
        let config = ShutdownConfig {
            mode: ShutdownMode::Leader,
            leader_timeout: Duration::from_millis(1),
            scope_timeout: Duration::from_millis(1),
        };
        shutdown_scope(&fake, "scope", "manager", &config)
            .await
            .unwrap();
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            ["watch", "terminate-target", "wait"]
        );
    }
}
