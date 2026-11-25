//! One daemon-owned observer, with exact process-instance watches and no discovery loop.
use crate::{Error, Result, inventory::SessionIdentity, scheduler::Scheduler};
use lib_scoped::{Domain, Observer, ProcessIdentity, ScopeIdentity, TargetId, well_known};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
struct Registration {
    sid: String,
    uid: u32,
    scope: ScopeIdentity,
    master: ProcessIdentity,
}
struct State {
    observer: Observer,
    registrations: HashMap<u64, Registration>,
}
pub struct Observation {
    state: Mutex<State>,
}
impl Observation {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                observer: Observer::new()?,
                registrations: HashMap::new(),
            }),
        })
    }
    pub fn arm(&self, domain: &Domain, session: &SessionIdentity) -> Result<()> {
        let root =
            well_known::sessiond_user_session(session.uid, &session.id).expect("validated SID");
        let target = TargetId::parse("master").expect("literal target");
        let generation = domain.scope_identity(&root)?.ok_or_else(|| {
            crate::core::failure(
                lib_sessiond::ErrorCode::SessionNotFound,
                "session disappeared before observation",
            )
        })?;
        let identity = domain
            .read_target_identity(&root, &target)?
            .ok_or_else(|| {
                crate::core::failure(lib_sessiond::ErrorCode::NotReady, "missing master tracking")
            })?;
        let mut state = self.state.lock().expect("observer mutex poisoned");
        if state
            .registrations
            .values()
            .any(|old| old.sid == session.id && old.scope == generation && old.master == identity)
        {
            return Ok(());
        }
        let old = state
            .registrations
            .iter()
            .find(|(_, old)| old.sid == session.id)
            .map(|(token, _)| *token);
        if let Some(token) = old {
            state.observer.remove(token);
            state.registrations.remove(&token);
        }
        let token = state.observer.add(domain.watch_target(&root, &target)?);
        state.registrations.insert(
            token,
            Registration {
                sid: session.id.clone(),
                uid: session.uid,
                scope: generation,
                master: identity,
            },
        );
        Ok(())
    }
    pub fn remove(&self, sid: &str) {
        let mut state = self.state.lock().expect("observer mutex poisoned");
        let tokens: Vec<_> = state
            .registrations
            .iter()
            .filter(|(_, row)| row.sid == sid)
            .map(|(token, _)| *token)
            .collect();
        for token in tokens {
            state.observer.remove(token);
            state.registrations.remove(&token);
        }
    }
    fn wait(&self) -> Result<Vec<u32>> {
        let mut state = self.state.lock().expect("observer mutex poisoned");
        match state.observer.wait(Duration::from_millis(50)) {
            Ok(events) => {
                let mut uids = Vec::new();
                for event in events {
                    if let Some(row) = state.registrations.remove(&event.token) {
                        state.observer.remove(event.token);
                        // Reconciliation revalidates generation, current tracking and
                        // liveness; the event itself never authorizes stale signalling.
                        uids.push(row.uid);
                    }
                }
                Ok(uids)
            }
            Err(lib_scoped::Error::Watch { token, source }) => {
                state.observer.remove(token);
                state.registrations.remove(&token);
                Err(Error::Containment(*source))
            }
            Err(error) => Err(error.into()),
        }
    }
}
pub fn start(
    scheduler: Scheduler,
    stopping: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sessiond-observer".into())
        .spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match scheduler.core().observation.wait() {
                    Ok(uids) => {
                        for uid in uids {
                            scheduler.reconcile(uid);
                        }
                    }
                    Err(error) => tracing::warn!(%error, "master observation error"),
                }
                scheduler.core().reap_workers();
            }
        })
}
