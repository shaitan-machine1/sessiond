use super::*;
use crate::config::Config;
use lib_scoped::{Domain, ScopeId};
use std::sync::atomic::{AtomicBool, Ordering};
const SID: &str = "0123456789abcdef0123456789abcdef";
fn fixture(grace: Duration, running: bool) -> (tempfile::TempDir, Domain, Scheduler) {
    let root = tempfile::tempdir().unwrap();
    let domain = Domain::create(root.path(), "sessiond").unwrap();
    for raw in [
        "sessiond/user".to_owned(),
        "sessiond/user/1000".into(),
        "sessiond/user/1000/session".into(),
        format!("sessiond/user/1000/session/{SID}"),
    ] {
        domain.create_scope(&ScopeId::parse(raw).unwrap()).unwrap();
    }
    let mut config = Config {
        cgroup_root: root.path().into(),
        ..Config::default()
    };
    config.session.close_grace = grace;
    let core = Arc::new(SessionCore::new(config).unwrap());
    let scheduler = if running {
        Scheduler::new(core)
    } else {
        Scheduler {
            inner: Arc::new(Inner {
                core,
                state: Mutex::new(State::default()),
                changed: Condvar::new(),
                admission: Arc::new(Semaphore::new(QUEUE_CAPACITY + WORKERS)),
            }),
            workers: Arc::new(Mutex::new(Vec::new())),
        }
    };
    (root, domain, scheduler)
}
#[test]
fn virtual_grace_deadline_is_not_extended_and_wait_holds_no_uid_lane() {
    let (_root, _, scheduler) = fixture(Duration::from_secs(10), false);
    let now = Instant::now();
    let first = scheduler.schedule_at(SID, false, now).unwrap().unwrap();
    let second = scheduler
        .schedule_at(SID, false, now + Duration::from_secs(9))
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let mut state = scheduler.inner.state.lock().unwrap();
    assert!(state.active_uids.is_empty());
    assert_eq!(state.closes[SID].deadline, now + Duration::from_secs(10));
    assert!(
        take(
            &scheduler.inner,
            &mut state,
            now + Duration::from_secs(10) - Duration::from_nanos(1)
        )
        .is_none()
    );
    assert!(matches!(
        take(&scheduler.inner, &mut state, now + Duration::from_secs(10)),
        Some(Work::Close { uid: 1000, .. })
    ));
}
#[test]
fn immediate_close_joins_grace_and_zero_grace_has_no_wait() {
    for grace in [Duration::ZERO, Duration::from_secs(10)] {
        let (_root, _, scheduler) = fixture(grace, false);
        let now = Instant::now();
        let first = scheduler.schedule_at(SID, false, now).unwrap().unwrap();
        let second = scheduler.schedule_at(SID, true, now).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(matches!(
            take(
                &scheduler.inner,
                &mut scheduler.inner.state.lock().unwrap(),
                now
            ),
            Some(Work::Close { .. })
        ));
    }
}
#[test]
fn master_death_does_not_create_a_watch_or_change_the_scheduled_deadline() {
    use std::os::fd::AsRawFd;
    let (root, _, scheduler) = fixture(Duration::from_secs(10), false);
    let directory = std::fs::File::open(
        root.path()
            .join(format!("sessiond/user/1000/session/{SID}")),
    )
    .unwrap();
    let record = format!(
        "v2:{}:{}",
        std::process::id(),
        lib_scoped::read_start_time(std::process::id()).unwrap() + 1
    );
    // SAFETY: deliberately mismatched tracking only on a disposable directory.
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                directory.as_raw_fd(),
                c"user.scoped.target.master".as_ptr(),
                record.as_ptr().cast(),
                record.len(),
                0,
            )
        },
        0
    );
    let now = Instant::now();
    scheduler.schedule_at(SID, false, now).unwrap();
    assert!(
        take(
            &scheduler.inner,
            &mut scheduler.inner.state.lock().unwrap(),
            now
        )
        .is_none()
    );
    assert!(matches!(
        take(
            &scheduler.inner,
            &mut scheduler.inner.state.lock().unwrap(),
            now + Duration::from_secs(10)
        ),
        Some(Work::Close { .. })
    ));
}
#[test]
fn a_finished_failure_can_be_retried_without_waiting_for_an_idle_dispatcher() {
    let (_root, _, scheduler) = fixture(Duration::from_secs(10), false);
    let now = Instant::now();
    let first = scheduler.schedule_at(SID, true, now).unwrap().unwrap();
    first
        .result
        .send_replace(Some(Err(Error::new(ErrorCode::CleanupFailed, "injected"))));
    let second = scheduler.schedule_at(SID, true, now).unwrap().unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(second.result.borrow().is_none());
}
#[test]
fn replacement_requests_do_not_join_an_obsolete_generation_or_reuse_its_inode() {
    let (_root, domain, scheduler) = fixture(Duration::from_secs(10), false);
    let now = Instant::now();
    let old = scheduler.schedule_at(SID, false, now).unwrap().unwrap();
    let id = lib_scoped::well_known::sessiond_user_session(1000, SID).unwrap();
    domain.remove_scope(&id).unwrap();
    domain.create_scope(&id).unwrap();
    let new = scheduler.schedule_at(SID, true, now).unwrap().unwrap();
    assert_ne!(old.generation, new.generation);
    assert!(old.result.borrow().as_ref().unwrap().is_ok());
    assert!(new.result.borrow().is_none());
    let mut state = scheduler.inner.state.lock().unwrap();
    assert!(
        matches!(take(&scheduler.inner,&mut state,now),Some(Work::Close { generation,.. }) if generation == new.generation)
    );
}
#[test]
fn public_admission_and_queue_are_bounded_and_internal_triggers_survive_saturation() {
    use futures_util::FutureExt;
    let (_root, _, scheduler) = fixture(Duration::ZERO, false);
    for _ in 0..QUEUE_CAPACITY {
        assert!(
            scheduler
                .execute(scheduler.admit().unwrap(), Some(1000), |_| Ok(()))
                .now_or_never()
                .is_none()
        );
    }
    let error = scheduler
        .execute(scheduler.admit().unwrap(), None, |_| Ok(()))
        .now_or_never()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Busy);
    let held: Vec<_> = (0..WORKERS).map(|_| scheduler.admit().unwrap()).collect();
    assert_eq!(scheduler.admit().unwrap_err().code, ErrorCode::Busy);
    for _ in 0..100 {
        scheduler.reconcile(1000);
        scheduler.reconcile(2000);
    }
    let mut state = scheduler.inner.state.lock().unwrap();
    state.active_uids.insert(1000);
    assert_eq!(state.requests.len(), QUEUE_CAPACITY);
    assert_eq!(state.reconcile.len(), 2);
    assert!(matches!(
        take(&scheduler.inner, &mut state, Instant::now()),
        Some(Work::Reconcile(2000))
    ));
    assert!(state.reconcile.contains(&1000));
    assert_eq!(state.requests.len(), QUEUE_CAPACITY);
    drop(held);
}
#[tokio::test]
async fn cancelled_reply_retains_its_worker_permit_and_uid_lane_while_other_uids_progress() {
    let (_root, _, scheduler) = fixture(Duration::ZERO, true);
    assert_eq!(scheduler.workers.lock().unwrap().len(), WORKERS);
    let (entered, notification) = std::sync::mpsc::sync_channel(1);
    let (release, gate) = std::sync::mpsc::sync_channel(1);
    let first = scheduler.clone();
    let call = tokio::spawn(async move {
        first
            .execute(first.admit().unwrap(), Some(1000), move |_| {
                entered.send(()).unwrap();
                gate.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::yield_now().await;
    notification.recv_timeout(Duration::from_secs(2)).unwrap();
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    let second = scheduler.clone();
    let waiting = tokio::spawn(async move {
        second
            .execute(second.admit().unwrap(), Some(1000), move |_| {
                flag.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await
    });
    tokio::task::yield_now().await;
    let other = tokio::time::timeout(
        Duration::from_secs(1),
        scheduler.execute(scheduler.admit().unwrap(), Some(2000), |_| Ok(42)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(other, 42);
    let deadline = Instant::now() + Duration::from_secs(1);
    while scheduler
        .inner
        .state
        .lock()
        .unwrap()
        .active_uids
        .contains(&2000)
    {
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert!(!ran.load(Ordering::Relaxed));
    assert!(
        scheduler
            .inner
            .state
            .lock()
            .unwrap()
            .active_uids
            .contains(&1000)
    );
    let held: Vec<_> = (0..QUEUE_CAPACITY + WORKERS - 2)
        .map(|_| scheduler.admit().unwrap())
        .collect();
    assert_eq!(scheduler.admit().unwrap_err().code, ErrorCode::Busy);
    release.send(()).unwrap();
    waiting.await.unwrap().unwrap();
    assert!(ran.load(Ordering::Relaxed));
    drop(held);
    scheduler.shutdown();
    assert_eq!(scheduler.admit().unwrap_err().code, ErrorCode::Stopping);
}
#[tokio::test]
async fn close_waiters_share_actual_result_and_timeout_does_not_cancel_it() {
    let generation = ScopeIdentity {
        device: 1,
        inode: 2,
    };
    let (result, _) = tokio::sync::watch::channel(None);
    let completion = Arc::new(CloseCompletion { generation, result });
    assert!(
        tokio::time::timeout(
            Duration::from_millis(1),
            Scheduler::wait(completion.clone())
        )
        .await
        .is_err()
    );
    let first = tokio::spawn(Scheduler::wait(completion.clone()));
    let second = tokio::spawn(Scheduler::wait(completion.clone()));
    completion.result.send_replace(Some(Err(Error::new(
        ErrorCode::CleanupFailed,
        "actual removal failed",
    ))));
    assert_eq!(
        first.await.unwrap().unwrap_err().code,
        ErrorCode::CleanupFailed
    );
    assert_eq!(
        second.await.unwrap().unwrap_err().code,
        ErrorCode::CleanupFailed
    );
}
