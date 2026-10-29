use crate::scheduler::Scheduler;
use lib_scoped::{
    Domain, Error as ScopedError, Observer, ProcessIdentity, ScopeIdentity, TargetId, TargetStatus,
    well_known,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    uid: u32,
    sid: String,
}
struct Tracked {
    scope: ScopeIdentity,
    leader: Option<ProcessIdentity>,
    token: Option<u64>,
}

/// Start the daemon's one multi-watch observation thread. Initial discovery is
/// read-only: an already-exited/stale leader is recorded but never converted
/// into a close request. Only a transition armed while Running schedules close.
pub fn start(
    scheduler: Scheduler,
    hints: mpsc::Receiver<()>,
    stopping: &'static AtomicBool,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sessiond-observer".into())
        .spawn(move || run(scheduler, hints, stopping))
}
fn run(scheduler: Scheduler, hints: mpsc::Receiver<()>, stopping: &'static AtomicBool) {
    let mut observer = match Observer::new() {
        Ok(observer) => observer,
        Err(error) => {
            tracing::error!(%error, "cannot create containment observer");
            return;
        }
    };
    let mut tracked = HashMap::<Key, Tracked>::new();
    let mut pending_closes = HashMap::<Key, ScopeIdentity>::new();
    while !stopping.load(Ordering::Relaxed) {
        while hints.try_recv().is_ok() {}
        if let Err(error) = discover(&scheduler, &mut observer, &mut tracked) {
            tracing::warn!(%error, "session discovery failed");
        }
        retry_pending(&scheduler, &mut pending_closes);
        match observer.wait(Duration::from_millis(500)) {
            Ok(events) => {
                let domain = Domain::open(&scheduler.core().config().cgroup_root, "sessiond");
                for event in events {
                    let Some(key) = tracked
                        .iter()
                        .find(|(_, state)| state.token == Some(event.token))
                        .map(|(key, _)| key.clone())
                    else {
                        continue;
                    };
                    let current_generation = match &domain {
                        Ok(domain) => match domain.scope_identity(&event.scope) {
                            Ok(generation) => generation,
                            Err(error) => {
                                tracing::warn!(sid = %key.sid, %error, "leader-exit generation check deferred");
                                pending_closes.insert(key, event.scope_identity);
                                continue;
                            }
                        },
                        Err(error) => {
                            tracing::warn!(sid = %key.sid, %error, "leader-exit generation check deferred");
                            pending_closes.insert(key, event.scope_identity);
                            continue;
                        }
                    };
                    if current_generation != Some(event.scope_identity) {
                        continue;
                    }
                    if let Err(error) = scheduler.schedule(&key.sid) {
                        tracing::error!(sid = %key.sid, %error, "leader-exit teardown request deferred");
                        pending_closes.insert(key, event.scope_identity);
                    }
                }
            }
            Err(ScopedError::Watch { token, source }) => {
                tracing::warn!(token, error = %source, "dropping failed containment watch");
                observer.remove(token);
                let failed = tracked
                    .iter()
                    .find(|(_, state)| state.token == Some(token))
                    .map(|(key, _)| key.clone());
                if let Some(key) = failed {
                    tracked.remove(&key);
                }
            }
            Err(error) => tracing::warn!(%error, "containment observation failed"),
        }
    }
}
fn retry_pending(scheduler: &Scheduler, pending: &mut HashMap<Key, ScopeIdentity>) {
    let domain = match Domain::open(&scheduler.core().config().cgroup_root, "sessiond") {
        Ok(domain) => domain,
        Err(ScopedError::DomainNotFound(_)) => {
            pending.clear();
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "cannot revalidate deferred leader-exit requests");
            return;
        }
    };
    pending.retain(|key, expected| {
        let scope = well_known::sessiond_user_session(key.uid, &key.sid)
            .expect("validated observed SID");
        match domain.scope_identity(&scope) {
            Ok(Some(current)) if current == *expected => {}
            Ok(_) => return false,
            Err(error) => {
                tracing::warn!(sid = %key.sid, %error, "cannot revalidate deferred leader-exit request");
                return true;
            }
        }
        match scheduler.schedule(&key.sid) {
            Ok(_) => false,
            Err(error) => {
                tracing::warn!(sid = %key.sid, %error, "leader-exit teardown request still deferred");
                true
            }
        }
    });
}

fn discover(
    scheduler: &Scheduler,
    observer: &mut Observer,
    tracked: &mut HashMap<Key, Tracked>,
) -> lib_sessiond::Result<()> {
    let sessions = scheduler.core().list_sessions()?;
    let domain = match Domain::open(&scheduler.core().config().cgroup_root, "sessiond") {
        Ok(domain) => domain,
        Err(ScopedError::DomainNotFound(_)) => {
            for (_, old) in tracked.drain() {
                if let Some(token) = old.token {
                    observer.remove(token);
                }
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let target = TargetId::parse("leader").expect("literal target");
    let mut present = HashSet::new();
    for session in sessions {
        let key = Key {
            uid: session.uid,
            sid: session.id.clone(),
        };
        present.insert(key.clone());
        let scope = well_known::sessiond_user_session(session.uid, &session.id)
            .expect("validated inventory SID");
        let Some(generation) = domain.scope_identity(&scope)? else {
            continue;
        };
        if tracked
            .get(&key)
            .is_some_and(|old| old.scope == generation && old.leader == session.leader)
        {
            continue;
        }
        if let Some(old) = tracked.remove(&key)
            && let Some(token) = old.token
        {
            observer.remove(token);
        }
        let token = match session.leader {
            Some(identity) => match domain.target_status(&scope, &target)? {
                TargetStatus::Running(current) if current == identity => {
                    Some(observer.add(domain.watch_target(&scope, &target)?))
                }
                // Stale at discovery is not a transition and never authorizes cleanup.
                TargetStatus::Exited(_) | TargetStatus::Untracked | TargetStatus::Running(_) => {
                    None
                }
            },
            None => None,
        };
        tracked.insert(
            key,
            Tracked {
                scope: generation,
                leader: session.leader,
                token,
            },
        );
    }
    let removed = tracked
        .keys()
        .filter(|key| !present.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    for key in removed {
        if let Some(old) = tracked.remove(&key)
            && let Some(token) = old.token
        {
            observer.remove(token);
        }
    }
    Ok(())
}
