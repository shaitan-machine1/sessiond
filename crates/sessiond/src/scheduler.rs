use lib_sessiond::{SessionCore, validate_session_id};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, mpsc};

const WORKERS: usize = 4;
const QUEUE_CAPACITY: usize = 128;
const MAX_WAITERS: usize = 128;
type Completion = std::result::Result<(), String>;
struct State {
    complete: Option<Completion>,
}
pub struct Operation {
    state: Mutex<State>,
    changed: Condvar,
}
impl Operation {
    fn pending() -> Self {
        Self {
            state: Mutex::new(State { complete: None }),
            changed: Condvar::new(),
        }
    }
    fn finish(&self, result: Completion) {
        let mut state = self.state.lock().expect("operation mutex poisoned");
        state.complete = Some(result);
        self.changed.notify_all();
    }
    pub fn wait(&self) -> Completion {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "operation mutex poisoned".to_owned())?;
        while state.complete.is_none() {
            state = self
                .changed
                .wait(state)
                .map_err(|_| "operation mutex poisoned".to_owned())?;
        }
        state.complete.clone().expect("completion checked")
    }
}
struct Work {
    sid: String,
    uid: u32,
    operation: Arc<Operation>,
}
#[derive(Default)]
struct Coordination {
    pending: HashMap<String, Arc<Operation>>,
    active_uids: HashSet<u32>,
    waiting: HashMap<u32, VecDeque<Work>>,
    queued: usize,
}
struct Inner {
    core: Arc<SessionCore>,
    coordination: Mutex<Coordination>,
    sender: mpsc::SyncSender<Work>,
    waiters: Mutex<usize>,
}
#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}
impl Scheduler {
    pub fn new(core: Arc<SessionCore>) -> Self {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let inner = Arc::new(Inner {
            core,
            coordination: Mutex::new(Coordination::default()),
            sender,
            waiters: Mutex::new(0),
        });
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKERS {
            let inner = inner.clone();
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("sessiond-cleanup-{index}"))
                .spawn(move || worker(inner, receiver))
                .expect("spawn cleanup worker");
        }
        Self { inner }
    }
    /// Duplicate requests join pending work even after its session scope has
    /// disappeared. Only one work item per UID reaches the worker pool; queued
    /// requests for one slow UID cannot occupy every cleanup worker.
    pub fn schedule(&self, sid: &str) -> std::result::Result<Option<Arc<Operation>>, String> {
        validate_session_id(sid).map_err(|e| e.to_string())?;
        {
            let coordination = self
                .inner
                .coordination
                .lock()
                .map_err(|_| "cleanup coordination mutex poisoned".to_owned())?;
            if let Some(operation) = coordination.pending.get(sid) {
                return Ok(Some(operation.clone()));
            }
        }
        let Some(session) = self
            .inner
            .core
            .find_session(sid)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let mut coordination = self
            .inner
            .coordination
            .lock()
            .map_err(|_| "cleanup coordination mutex poisoned".to_owned())?;
        if let Some(operation) = coordination.pending.get(sid) {
            return Ok(Some(operation.clone()));
        }
        if coordination.active_uids.contains(&session.uid) && coordination.queued >= QUEUE_CAPACITY
        {
            return Err("cleanup queue is full".into());
        }
        let operation = Arc::new(Operation::pending());
        let work = Work {
            sid: sid.to_owned(),
            uid: session.uid,
            operation: operation.clone(),
        };
        coordination
            .pending
            .insert(sid.to_owned(), operation.clone());
        if coordination.active_uids.insert(session.uid) {
            match self.inner.sender.try_send(work) {
                Ok(()) => Ok(Some(operation)),
                Err(error) => {
                    coordination.active_uids.remove(&session.uid);
                    coordination.pending.remove(sid);
                    Err(match error {
                        mpsc::TrySendError::Full(_) => "cleanup queue is full".into(),
                        mpsc::TrySendError::Disconnected(_) => {
                            "cleanup workers are unavailable".into()
                        }
                    })
                }
            }
        } else {
            coordination
                .waiting
                .entry(session.uid)
                .or_default()
                .push_back(work);
            coordination.queued += 1;
            Ok(Some(operation))
        }
    }
    pub fn acquire_waiter(&self) -> std::result::Result<WaiterPermit, String> {
        let mut waiters = self
            .inner
            .waiters
            .lock()
            .map_err(|_| "waiter mutex poisoned".to_owned())?;
        if *waiters >= MAX_WAITERS {
            return Err("too many blocking close callers".into());
        }
        *waiters += 1;
        Ok(WaiterPermit {
            inner: self.inner.clone(),
        })
    }
    pub fn core(&self) -> &Arc<SessionCore> {
        &self.inner.core
    }
}
pub struct WaiterPermit {
    inner: Arc<Inner>,
}
impl Drop for WaiterPermit {
    fn drop(&mut self) {
        if let Ok(mut waiters) = self.inner.waiters.lock() {
            *waiters = waiters.saturating_sub(1);
        }
    }
}
fn worker(inner: Arc<Inner>, receiver: Arc<Mutex<mpsc::Receiver<Work>>>) {
    loop {
        let work = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(mut work) = work else {
            return;
        };
        loop {
            let result =
                lib_sessiond::daemon_support::execute_close_session(&inner.core, &work.sid)
                    .map(|report| {
                        for warning in report.warnings {
                            tracing::warn!(sid = %work.sid, %warning, "session cleanup warning");
                        }
                    })
                    .map_err(|e| e.to_string());
            if let Err(error) = &result {
                tracing::error!(sid = %work.sid, %error, "session cleanup failed");
            }
            work.operation.finish(result);
            let Some(next) = finish_and_take_next(&inner, &work) else {
                break;
            };
            work = next;
        }
    }
}
fn finish_and_take_next(inner: &Inner, completed: &Work) -> Option<Work> {
    let Ok(mut coordination) = inner.coordination.lock() else {
        return None;
    };
    if coordination
        .pending
        .get(&completed.sid)
        .is_some_and(|current| Arc::ptr_eq(current, &completed.operation))
    {
        coordination.pending.remove(&completed.sid);
    }
    let next = coordination
        .waiting
        .get_mut(&completed.uid)
        .and_then(VecDeque::pop_front);
    if next.is_some() {
        coordination.queued -= 1;
    }
    if coordination
        .waiting
        .get(&completed.uid)
        .is_some_and(VecDeque::is_empty)
    {
        coordination.waiting.remove(&completed.uid);
    }
    if next.is_none() {
        coordination.active_uids.remove(&completed.uid);
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_sessiond::config::Config;
    fn test_inner(core: Arc<SessionCore>) -> Inner {
        let (sender, _receiver) = mpsc::sync_channel(1);
        Inner {
            core,
            coordination: Mutex::new(Coordination::default()),
            sender,
            waiters: Mutex::new(0),
        }
    }

    #[test]
    fn same_uid_followup_stays_with_the_active_worker() {
        let root = tempfile::tempdir().unwrap();
        let core = Arc::new(
            SessionCore::new(Config {
                cgroup_root: root.path().to_owned(),
                ..Config::default()
            })
            .unwrap(),
        );
        let inner = test_inner(core);
        let first = Work {
            sid: "0123456789abcdef0123456789abcdef".into(),
            uid: 1000,
            operation: Arc::new(Operation::pending()),
        };
        let second = Work {
            sid: "1123456789abcdef0123456789abcdef".into(),
            uid: 1000,
            operation: Arc::new(Operation::pending()),
        };
        {
            let mut state = inner.coordination.lock().unwrap();
            state.active_uids.insert(1000);
            state
                .pending
                .insert(first.sid.clone(), first.operation.clone());
            state
                .pending
                .insert(second.sid.clone(), second.operation.clone());
            state.waiting.entry(1000).or_default().push_back(second);
            state.queued = 1;
        }
        let second = finish_and_take_next(&inner, &first).expect("same-UID followup");
        {
            let state = inner.coordination.lock().unwrap();
            assert!(state.active_uids.contains(&1000));
            assert_eq!(state.queued, 0);
            assert!(!state.pending.contains_key(&first.sid));
        }
        assert!(finish_and_take_next(&inner, &second).is_none());
        assert!(
            !inner
                .coordination
                .lock()
                .unwrap()
                .active_uids
                .contains(&1000)
        );
    }

    #[test]
    fn unknown_close_is_immediate_and_invalid_ids_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let core = Arc::new(
            SessionCore::new(Config {
                cgroup_root: root.path().to_owned(),
                ..Config::default()
            })
            .unwrap(),
        );
        let scheduler = Scheduler::new(core);
        assert!(
            scheduler
                .schedule("0123456789abcdef0123456789abcdef")
                .unwrap()
                .is_none()
        );
        assert!(scheduler.schedule("bad").is_err());
    }
}
