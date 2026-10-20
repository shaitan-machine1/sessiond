use scope_id::well_known;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

use crate::config::Config;
use crate::launcher::UserManagerLauncher;
use crate::runtime::RuntimeStore;
use crate::scoped::{ScopedApi, ScopedError, shutdown_scope};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    SessionNew { sid: String, uid: u32 },
    SessionRemoved { sid: String, uid: u32 },
}

#[derive(Clone, Debug)]
struct Session {
    uid: u32,
    scope: String,
}

#[derive(Default)]
struct State {
    sessions: BTreeMap<String, Session>,
    closing: HashSet<String>,
}

pub struct SessionManager {
    scoped: Arc<dyn ScopedApi>,
    runtime: Arc<dyn RuntimeStore>,
    launcher: Arc<dyn UserManagerLauncher>,
    config: Config,
    state: Mutex<State>,
    uid_locks: Mutex<HashMap<u32, Arc<Mutex<()>>>>,
    events: broadcast::Sender<Event>,
}

impl SessionManager {
    pub fn new(
        scoped: Arc<dyn ScopedApi>,
        runtime: Arc<dyn RuntimeStore>,
        launcher: Arc<dyn UserManagerLauncher>,
        config: Config,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        Arc::new(Self {
            scoped,
            runtime,
            launcher,
            config,
            state: Mutex::new(State::default()),
            uid_locks: Mutex::new(HashMap::new()),
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    async fn uid_lock(&self, uid: u32) -> Arc<Mutex<()>> {
        self.uid_locks
            .lock()
            .await
            .entry(uid)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn open_session(
        &self,
        uid: u32,
        caller_pid: u32,
    ) -> anyhow::Result<(String, PathBuf)> {
        let uid_lock = self.uid_lock(uid).await;
        let deadline = tokio::time::Instant::now() + self.config.session.open_timeout;
        let _guard = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let guard = tokio::time::timeout(remaining, uid_lock.lock())
                .await
                .map_err(|_| anyhow::anyhow!("uid {uid} is still stopping"))?;
            let closing = {
                let state = self.state.lock().await;
                state
                    .closing
                    .iter()
                    .filter_map(|sid| state.sessions.get(sid))
                    .any(|session| session.uid == uid)
            };
            if !closing {
                break guard;
            }
            drop(guard);
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("uid {uid} is still stopping");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        let runtime = self.runtime.ensure_runtime(uid).await?;
        let had_sessions = self.has_uid_sessions(uid).await;
        if !had_sessions {
            self.ensure_manager(uid, &runtime).await?;
        }

        let (sid, scope) = loop {
            let sid = Uuid::now_v7().simple().to_string();
            let scope = well_known::sessiond_user_session(uid, &sid)?;
            match self.scoped.create(scope.as_str()).await {
                Ok(()) => break (sid, scope.to_string()),
                Err(ScopedError::AlreadyExists) => continue,
                Err(error) => return Err(error.into()),
            }
        };

        if let Err(error) = self.scoped.move_pid(caller_pid, &scope, "leader").await {
            let _ = self.scoped.kill_scope(&scope).await;
            if !had_sessions {
                let service = well_known::sessiond_user_service(uid).to_string();
                let _ = shutdown_scope(
                    &*self.scoped,
                    &service,
                    "manager",
                    &self.config.user_service_manager.shutdown,
                )
                .await;
            }
            return Err(error.into());
        }

        self.state.lock().await.sessions.insert(
            sid.clone(),
            Session {
                uid,
                scope: scope.clone(),
            },
        );
        let _ = self.events.send(Event::SessionNew {
            sid: sid.clone(),
            uid,
        });
        Ok((sid, runtime))
    }

    async fn ensure_manager(&self, uid: u32, runtime: &std::path::Path) -> anyhow::Result<()> {
        let scope = well_known::sessiond_user_service(uid).to_string();
        let existing = self
            .scoped
            .list(well_known::sessiond_user_root(uid).as_str())
            .await?
            .into_iter()
            .any(|candidate| candidate == scope);
        if existing {
            match self.scoped.target_exists(&scope, "manager").await {
                Ok(true) => return Ok(()),
                Ok(false) | Err(ScopedError::NotFound) => {
                    shutdown_scope(
                        &*self.scoped,
                        &scope,
                        "manager",
                        &self.config.user_service_manager.shutdown,
                    )
                    .await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.create_after_removal(&scope).await?;
        if let Err(error) = self.launcher.start(uid, runtime, &scope).await {
            let _ = self.scoped.kill_scope(&scope).await;
            return Err(error);
        }
        Ok(())
    }

    async fn create_after_removal(&self, scope: &str) -> Result<(), ScopedError> {
        for _ in 0..100 {
            match self.scoped.create(scope).await {
                Ok(()) => return Ok(()),
                Err(ScopedError::AlreadyExists) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ScopedError::Other(format!(
            "timed out waiting for stale scope {scope} removal"
        )))
    }

    async fn has_uid_sessions(&self, uid: u32) -> bool {
        self.state
            .lock()
            .await
            .sessions
            .values()
            .any(|session| session.uid == uid)
    }

    pub async fn list_sessions(&self) -> Vec<(String, u32)> {
        self.state
            .lock()
            .await
            .sessions
            .iter()
            .map(|(sid, session)| (sid.clone(), session.uid))
            .collect()
    }

    /// Durably marks a close and starts teardown after the caller can receive
    /// its reply. Repeated close paths coalesce.
    pub async fn request_close(self: &Arc<Self>, sid: &str) -> anyhow::Result<()> {
        let session = {
            let mut state = self.state.lock().await;
            let Some(session) = state.sessions.get(sid).cloned() else {
                return Ok(());
            };
            if !state.closing.insert(sid.to_owned()) {
                return Ok(());
            }
            session
        };
        if let Err(error) = self.runtime.mark_closing(sid, session.uid).await {
            self.state.lock().await.closing.remove(sid);
            return Err(error);
        }
        let manager = self.clone();
        let sid = sid.to_owned();
        tokio::spawn(async move {
            if let Err(error) = manager.close_worker(&sid, session).await {
                tracing::error!(%sid, %error, "session teardown failed and remains marked");
                manager.state.lock().await.closing.remove(&sid);
            }
        });
        Ok(())
    }

    async fn close_worker(&self, sid: &str, session: Session) -> anyhow::Result<()> {
        let uid_lock = self.uid_lock(session.uid).await;
        let _guard = uid_lock.lock().await;
        shutdown_scope(
            &*self.scoped,
            &session.scope,
            "leader",
            &self.config.session.shutdown,
        )
        .await?;

        {
            let mut state = self.state.lock().await;
            state.sessions.remove(sid);
            state.closing.remove(sid);
        }
        self.runtime.unmark_closing(sid).await?;
        let _ = self.events.send(Event::SessionRemoved {
            sid: sid.to_owned(),
            uid: session.uid,
        });

        if !self.config.linger && !self.authoritative_uid_sessions(session.uid).await? {
            let service = well_known::sessiond_user_service(session.uid).to_string();
            shutdown_scope(
                &*self.scoped,
                &service,
                "manager",
                &self.config.user_service_manager.shutdown,
            )
            .await?;
            self.runtime.remove_runtime(session.uid).await?;
        }
        Ok(())
    }

    async fn authoritative_uid_sessions(&self, uid: u32) -> anyhow::Result<bool> {
        let root = well_known::sessiond_user_session_root(uid).to_string();
        for scope in self.scoped.list(&root).await? {
            if parse_session_scope(&scope).is_none() {
                continue;
            }
            match self.scoped.scope_populated(&scope).await {
                Ok(true) => return Ok(true),
                Ok(false) | Err(ScopedError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(false)
    }

    pub async fn reconcile(self: &Arc<Self>) -> anyhow::Result<()> {
        let scopes = self.scoped.list("sessiond").await?;
        {
            let mut state = self.state.lock().await;
            for scope in &scopes {
                if let Some((uid, sid)) = parse_session_scope(scope) {
                    state.sessions.insert(
                        sid,
                        Session {
                            uid,
                            scope: scope.clone(),
                        },
                    );
                }
            }
        }

        let markers = self.runtime.closing_markers().await?;
        let marked: HashSet<String> = markers.iter().map(|(sid, _)| sid.clone()).collect();
        let sessions = self.list_sessions().await;
        for uid in sessions.iter().map(|(_, uid)| *uid).collect::<HashSet<_>>() {
            self.runtime.ensure_runtime(uid).await?;
        }
        for (sid, _) in &sessions {
            let scope = {
                self.state
                    .lock()
                    .await
                    .sessions
                    .get(sid)
                    .expect("listed session exists")
                    .scope
                    .clone()
            };
            let abandoned = !self
                .scoped
                .target_exists(&scope, "leader")
                .await
                .unwrap_or(false);
            if marked.contains(sid) || abandoned {
                self.request_close(sid).await?;
            }
        }
        let known: HashSet<&str> = sessions.iter().map(|(sid, _)| sid.as_str()).collect();
        for (sid, _) in markers {
            if !known.contains(sid.as_str()) {
                self.runtime.unmark_closing(&sid).await?;
            }
        }

        let users: HashSet<u32> = scopes
            .iter()
            .filter_map(|scope| parse_service_scope(scope))
            .collect();
        for uid in &users {
            if !self.has_uid_sessions(*uid).await && !self.config.linger {
                let service = well_known::sessiond_user_service(*uid).to_string();
                let lock = self.uid_lock(*uid).await;
                let _guard = lock.lock().await;
                shutdown_scope(
                    &*self.scoped,
                    &service,
                    "manager",
                    &self.config.user_service_manager.shutdown,
                )
                .await?;
                self.runtime.remove_runtime(*uid).await?;
            }
        }
        if !self.config.linger {
            for uid in self.runtime.runtime_uids().await? {
                if !users.contains(&uid) && !self.has_uid_sessions(uid).await {
                    self.runtime.remove_runtime(uid).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn session_for_scope(&self, scope: &str) -> Option<String> {
        parse_session_scope(scope).map(|(_, sid)| sid)
    }
}

pub fn parse_session_scope(scope: &str) -> Option<(u32, String)> {
    let parsed = scope_id::ScopeId::parse(scope).ok()?;
    let parts: Vec<_> = parsed.segments().collect();
    if let ["sessiond", "user", uid, "session", sid] = parts.as_slice() {
        let uid = uid.parse().ok()?;
        if sid.len() == 32
            && sid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Some((uid, (*sid).to_owned()));
        }
    }
    None
}

fn parse_service_scope(scope: &str) -> Option<u32> {
    let parsed = scope_id::ScopeId::parse(scope).ok()?;
    let parts: Vec<_> = parsed.segments().collect();
    match parts.as_slice() {
        ["sessiond", "user", uid, "service"] => uid.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeScoped {
        scopes: StdMutex<HashMap<String, Option<String>>>,
    }

    struct ReadyWatch;
    #[async_trait]
    impl crate::scoped::DrainWatch for ReadyWatch {
        async fn wait(&mut self, _: Duration) -> bool {
            true
        }
    }

    #[async_trait]
    impl ScopedApi for FakeScoped {
        async fn create(&self, id: &str) -> Result<(), ScopedError> {
            let mut scopes = self.scopes.lock().unwrap();
            if scopes.insert(id.into(), None).is_some() {
                Err(ScopedError::AlreadyExists)
            } else {
                Ok(())
            }
        }
        async fn move_pid(&self, _: u32, id: &str, target: &str) -> Result<(), ScopedError> {
            let mut scopes = self.scopes.lock().unwrap();
            let value = scopes.get_mut(id).ok_or(ScopedError::NotFound)?;
            *value = Some(target.into());
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, ScopedError> {
            Ok(self
                .scopes
                .lock()
                .unwrap()
                .keys()
                .filter(|id| id.starts_with(prefix))
                .cloned()
                .collect())
        }
        async fn target_exists(&self, id: &str, target: &str) -> Result<bool, ScopedError> {
            self.scopes
                .lock()
                .unwrap()
                .get(id)
                .map(|value| value.as_deref() == Some(target))
                .ok_or(ScopedError::NotFound)
        }
        async fn scope_populated(&self, id: &str) -> Result<bool, ScopedError> {
            self.scopes
                .lock()
                .unwrap()
                .get(id)
                .map(|value| value.is_some())
                .ok_or(ScopedError::NotFound)
        }
        async fn terminate_target(&self, id: &str, _: &str) -> Result<(), ScopedError> {
            self.scopes
                .lock()
                .unwrap()
                .remove(id)
                .map(|_| ())
                .ok_or(ScopedError::NotFound)
        }
        async fn terminate_scope(&self, id: &str) -> Result<(), ScopedError> {
            self.scopes
                .lock()
                .unwrap()
                .remove(id)
                .map(|_| ())
                .ok_or(ScopedError::NotFound)
        }
        async fn kill_scope(&self, id: &str) -> Result<(), ScopedError> {
            self.scopes.lock().unwrap().remove(id);
            Ok(())
        }
        fn watch_drain(&self, _: &str) -> Box<dyn crate::scoped::DrainWatch> {
            Box::new(ReadyWatch)
        }
    }

    #[derive(Default)]
    struct FakeRuntime {
        removed: StdMutex<Vec<u32>>,
        marked: StdMutex<HashMap<String, u32>>,
    }
    #[async_trait]
    impl RuntimeStore for FakeRuntime {
        async fn ensure_runtime(&self, uid: u32) -> anyhow::Result<PathBuf> {
            Ok(PathBuf::from(format!("/run/user/{uid}")))
        }
        async fn remove_runtime(&self, uid: u32) -> anyhow::Result<()> {
            self.removed.lock().unwrap().push(uid);
            Ok(())
        }
        async fn mark_closing(&self, sid: &str, uid: u32) -> anyhow::Result<()> {
            self.marked.lock().unwrap().insert(sid.into(), uid);
            Ok(())
        }
        async fn unmark_closing(&self, sid: &str) -> anyhow::Result<()> {
            self.marked.lock().unwrap().remove(sid);
            Ok(())
        }
        async fn closing_markers(&self) -> anyhow::Result<Vec<(String, u32)>> {
            Ok(self
                .marked
                .lock()
                .unwrap()
                .iter()
                .map(|(a, b)| (a.clone(), *b))
                .collect())
        }
        async fn runtime_uids(&self) -> anyhow::Result<Vec<u32>> {
            Ok(Vec::new())
        }
    }

    struct FakeLauncher {
        scoped: Arc<FakeScoped>,
        starts: StdMutex<u32>,
    }
    #[async_trait]
    impl UserManagerLauncher for FakeLauncher {
        async fn start(&self, _: u32, _: &Path, scope: &str) -> anyhow::Result<()> {
            *self.starts.lock().unwrap() += 1;
            self.scoped.move_pid(1, scope, "manager").await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_sessions_share_manager_and_last_close_removes_runtime() {
        let scoped = Arc::new(FakeScoped::default());
        let runtime = Arc::new(FakeRuntime::default());
        let launcher = Arc::new(FakeLauncher {
            scoped: scoped.clone(),
            starts: StdMutex::new(0),
        });
        let mut config = Config::default();
        config.session.shutdown.scope_timeout = Duration::from_millis(1);
        config.user_service_manager.shutdown.leader_timeout = Duration::from_millis(1);
        let manager = SessionManager::new(scoped, runtime.clone(), launcher.clone(), config);
        let (first, _) = manager.open_session(1000, 10).await.unwrap();
        let (second, _) = manager.open_session(1000, 11).await.unwrap();
        assert_eq!(*launcher.starts.lock().unwrap(), 1);

        let mut events = manager.subscribe();
        manager.request_close(&first).await.unwrap();
        while !matches!(events.recv().await.unwrap(), Event::SessionRemoved { sid, .. } if sid == first)
        {
        }
        assert!(runtime.removed.lock().unwrap().is_empty());
        manager.request_close(&second).await.unwrap();
        while !matches!(events.recv().await.unwrap(), Event::SessionRemoved { sid, .. } if sid == second)
        {
        }
        tokio::task::yield_now().await;
        assert_eq!(runtime.removed.lock().unwrap().as_slice(), [1000]);
    }

    #[test]
    fn only_exact_session_shapes_parse() {
        assert!(
            parse_session_scope("sessiond/user/42/session/019a0000000070008000000000000000")
                .is_some()
        );
        assert!(parse_session_scope("sessiond/user/42/session/not-a-uuid").is_none());
        assert!(
            parse_session_scope("other/user/42/session/019a0000000070008000000000000000").is_none()
        );
    }
}
