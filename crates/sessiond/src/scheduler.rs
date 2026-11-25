//! Fixed execution capacity and a bounded waiting queue. UID lanes are selected
//! before dispatch: workers never queue behind a slow UID's lifecycle lock.
use crate::{
    SessionCore,
    core::{CloseCompletion, failure},
};
use lib_scoped::{ScopeHandle, ScopeIdentity};
use lib_sessiond::{Error, ErrorCode, Result};
use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
const WORKERS: usize = 4;
const QUEUE_CAPACITY: usize = 128;
const MAX_CLOSES: usize = 4096;
pub type Permit = Arc<OwnedSemaphorePermit>;
type Value = Box<dyn Any + Send>;
type Effect = Box<dyn FnOnce(&SessionCore) -> Result<Value> + Send>;
struct Request {
    uid: Option<u32>,
    effect: Effect,
    reply: oneshot::Sender<Result<Value>>,
    _permit: Permit,
}
struct Close {
    uid: u32,
    generation: ScopeIdentity,
    _scope: ScopeHandle,
    deadline: Instant,
    started: bool,
    completion: Arc<CloseCompletion>,
}
#[derive(Default)]
struct State {
    requests: VecDeque<Request>,
    active_uids: HashSet<u32>,
    closes: HashMap<String, Close>,
    reconcile: HashSet<u32>,
    stopping: bool,
    turn: usize,
}
struct Inner {
    core: Arc<SessionCore>,
    state: Mutex<State>,
    changed: Condvar,
    admission: Arc<Semaphore>,
}
#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
    workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}
enum Work {
    Request(Request),
    Close {
        sid: String,
        uid: u32,
        generation: ScopeIdentity,
    },
    Reconcile(u32),
}
impl Work {
    fn uid(&self) -> Option<u32> {
        match self {
            Self::Request(row) => row.uid,
            Self::Close { uid, .. } | Self::Reconcile(uid) => Some(*uid),
        }
    }
}
impl Scheduler {
    pub fn new(core: Arc<SessionCore>) -> Self {
        let inner = Arc::new(Inner {
            core,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            admission: Arc::new(Semaphore::new(QUEUE_CAPACITY + WORKERS)),
        });
        let mut workers = Vec::new();
        for index in 0..WORKERS {
            let inner = inner.clone();
            workers.push(
                std::thread::Builder::new()
                    .name(format!("sessiond-effects-{index}"))
                    .spawn(move || worker(inner))
                    .expect("spawn fixed effect worker"),
            );
        }
        Self {
            inner,
            workers: Arc::new(Mutex::new(workers)),
        }
    }
    pub fn core(&self) -> &Arc<SessionCore> {
        &self.inner.core
    }
    /// Reserve before authentication or other await points. Rejected RPCs never
    /// create detached effects, unlimited authorization waiters or timers.
    pub fn admit(&self) -> Result<Permit> {
        if self
            .inner
            .state
            .lock()
            .expect("scheduler poisoned")
            .stopping
        {
            return Err(Error::new(ErrorCode::Stopping, "sessiond is stopping"));
        }
        self.inner
            .admission
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| Error::new(ErrorCode::Busy, "sessiond request capacity exhausted"))
    }
    pub async fn execute<R: Send + 'static>(
        &self,
        permit: Permit,
        uid: Option<u32>,
        effect: impl FnOnce(&SessionCore) -> crate::Result<R> + Send + 'static,
    ) -> Result<R> {
        let (reply, receiver) = oneshot::channel();
        {
            let mut state = self.inner.state.lock().expect("scheduler poisoned");
            if state.stopping {
                return Err(Error::new(ErrorCode::Stopping, "sessiond is stopping"));
            }
            if state.requests.len() >= QUEUE_CAPACITY {
                return Err(Error::new(
                    ErrorCode::Busy,
                    "sessiond waiting queue is full",
                ));
            }
            state.requests.push_back(Request {
                uid,
                effect: Box::new(move |core| {
                    effect(core)
                        .map(|value| Box::new(value) as Value)
                        .map_err(|e| e.public())
                }),
                reply,
                _permit: permit,
            });
        }
        self.inner.changed.notify_all();
        let value = receiver
            .await
            .map_err(|_| Error::new(ErrorCode::Stopping, "sessiond execution stopped"))??;
        value
            .downcast::<R>()
            .map(|value| *value)
            .map_err(|_| Error::new(ErrorCode::BackendError, "internal reply type mismatch"))
    }
    /// Called by normal lifecycle triggers. A dirty UID is coalesced and retained
    /// even when the public queue is full; failures do not reinsert themselves.
    pub fn reconcile(&self, uid: u32) {
        self.inner
            .state
            .lock()
            .expect("scheduler poisoned")
            .reconcile
            .insert(uid);
        self.inner.changed.notify_all();
    }
    pub fn schedule(
        &self,
        sid: &str,
        immediate: bool,
    ) -> crate::Result<Option<Arc<CloseCompletion>>> {
        self.schedule_at(sid, immediate, Instant::now())
    }
    fn schedule_at(
        &self,
        sid: &str,
        immediate: bool,
        now: Instant,
    ) -> crate::Result<Option<Arc<CloseCompletion>>> {
        crate::inventory::validate_session_id(sid)?;
        let Some(session) = self.core().find_session(sid)? else {
            return Ok(None);
        };
        let (_, _, scope) = self.core().session_scope(sid)?;
        {
            let mut state = self.inner.state.lock().expect("scheduler poisoned");
            if state.closes.get(sid).is_some_and(|close| {
                close.completion.result.borrow().is_some() || close.generation != scope.identity()
            }) {
                if let Some(old) = state.closes.remove(sid)
                    && old.generation != scope.identity()
                {
                    // Its original instance is gone, not a successful removal
                    // of the replacement requested by this new call.
                    old.completion.result.send_replace(Some(Ok(())));
                }
                self.core()
                    .completions
                    .lock()
                    .expect("close registry poisoned")
                    .remove(sid);
            }
            if let Some(close) = state.closes.get_mut(sid) {
                if immediate {
                    close.deadline = now;
                    self.inner.changed.notify_all();
                }
                return Ok(Some(close.completion.clone()));
            }
        }
        let grace = if immediate {
            Duration::ZERO
        } else {
            self.core().config().session.close_grace
        };
        let deadline = now
            .checked_add(grace)
            .ok_or_else(|| failure(ErrorCode::InvalidArgument, "close deadline overflow"))?;
        let mut state = self.inner.state.lock().expect("scheduler poisoned");
        if let Some(close) = state.closes.get_mut(sid) {
            if close.generation != scope.identity() {
                return Err(failure(
                    ErrorCode::SessionNotFound,
                    "session generation changed while scheduling",
                ));
            }
            close.deadline = close.deadline.min(deadline);
            return Ok(Some(close.completion.clone()));
        }
        if state.stopping {
            return Err(failure(ErrorCode::Stopping, "sessiond is stopping"));
        }
        if state.closes.len() >= MAX_CLOSES {
            return Err(failure(
                ErrorCode::LimitExceeded,
                "scheduled-close capacity exhausted",
            ));
        }
        let (result, _) = tokio::sync::watch::channel(None);
        let completion = Arc::new(CloseCompletion {
            generation: scope.identity(),
            result,
        });
        self.core()
            .completions
            .lock()
            .expect("close registry poisoned")
            .insert(sid.to_owned(), completion.clone());
        state.closes.insert(
            sid.to_owned(),
            Close {
                uid: session.uid,
                generation: scope.identity(),
                _scope: scope,
                deadline,
                started: false,
                completion: completion.clone(),
            },
        );
        self.inner.changed.notify_all();
        Ok(Some(completion))
    }
    pub async fn wait(completion: Arc<CloseCompletion>) -> Result<()> {
        let mut receiver = completion.result.subscribe();
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return result;
            }
            receiver
                .changed()
                .await
                .map_err(|_| Error::new(ErrorCode::Stopping, "close completion lost"))?;
        }
    }
    /// Stop both wire admission and effect enqueueing before disconnect/quiescence.
    pub fn stop_admission(&self) {
        self.inner.admission.close();
        self.inner
            .state
            .lock()
            .expect("scheduler poisoned")
            .stopping = true;
        self.inner.changed.notify_all();
    }
    /// Drain accepted work and join ALL workers while the lifetime lock is held.
    pub fn shutdown(&self) {
        self.stop_admission();
        for worker in self
            .workers
            .lock()
            .expect("worker registry poisoned")
            .drain(..)
        {
            worker.join().expect("effect worker panicked");
        }
    }
}
#[cfg(test)]
#[path = "scheduler_tests.rs"]
mod tests;
fn take(inner: &Inner, state: &mut State, now: Instant) -> Option<Work> {
    // Completion may come from reconciliation before service/runtime cleanup.
    // Remove only the scheduling record, never make waiters wait for that cleanup.
    let completed: Vec<_> = state
        .closes
        .iter()
        .filter(|(_, close)| close.completion.result.borrow().is_some())
        .map(|(sid, _)| sid.clone())
        .collect();
    for sid in completed {
        state.closes.remove(&sid);
        inner
            .core
            .completions
            .lock()
            .expect("close registry poisoned")
            .remove(&sid);
    }
    for offset in 0..3 {
        let kind = (state.turn + offset) % 3;
        let selected = match kind {
            0 => state
                .requests
                .iter()
                .position(|request| {
                    request
                        .uid
                        .is_none_or(|uid| !state.active_uids.contains(&uid))
                })
                .and_then(|index| state.requests.remove(index))
                .map(Work::Request),
            1 => {
                let sid = state
                    .closes
                    .iter()
                    .find(|(_, close)| {
                        !close.started
                            && !state.active_uids.contains(&close.uid)
                            && close.deadline <= now
                    })
                    .map(|(sid, _)| sid.clone());
                sid.map(|sid| {
                    let close = state.closes.get_mut(&sid).expect("selected close");
                    close.started = true;
                    Work::Close {
                        sid,
                        uid: close.uid,
                        generation: close.generation,
                    }
                })
            }
            _ => {
                let uid = state
                    .reconcile
                    .iter()
                    .find(|uid| !state.active_uids.contains(uid))
                    .copied();
                uid.map(|uid| {
                    state.reconcile.remove(&uid);
                    Work::Reconcile(uid)
                })
            }
        };
        if let Some(work) = selected {
            state.turn = (kind + 1) % 3;
            if let Some(uid) = work.uid() {
                state.active_uids.insert(uid);
            }
            return Some(work);
        }
    }
    None
}
fn worker(inner: Arc<Inner>) {
    loop {
        let work = {
            let mut state = inner.state.lock().expect("scheduler poisoned");
            loop {
                if let Some(work) = take(&inner, &mut state, Instant::now()) {
                    break work;
                }
                if state.stopping
                    && state.requests.is_empty()
                    && state.active_uids.is_empty()
                    && state.closes.is_empty()
                    && state.reconcile.is_empty()
                {
                    return;
                }
                state = inner
                    .changed
                    .wait_timeout(state, Duration::from_millis(25))
                    .expect("scheduler poisoned")
                    .0;
            }
        };
        let uid = work.uid();
        match work {
            Work::Request(request) => {
                let result = (request.effect)(&inner.core);
                let _ = request.reply.send(result); /* permit remains held until actual completion */
            }
            Work::Close {
                sid,
                uid,
                generation,
            } => match inner.core.close_tree(&sid, Some(generation)) {
                Ok(()) => {
                    inner
                        .state
                        .lock()
                        .expect("scheduler poisoned")
                        .reconcile
                        .insert(uid);
                }
                Err(error) => tracing::error!(%error, sid, "session-tree teardown failed"),
            },
            Work::Reconcile(uid) => {
                if let Err(error) = inner.core.reconcile(uid) {
                    tracing::warn!(%error, uid, "UID reconciliation failed; awaiting a normal trigger");
                }
            }
        }
        if let Some(uid) = uid {
            inner
                .state
                .lock()
                .expect("scheduler poisoned")
                .active_uids
                .remove(&uid);
        }
        inner.changed.notify_all();
    }
}
