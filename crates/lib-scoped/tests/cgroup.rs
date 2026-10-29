//! Real-kernel tests. Opt in only with an explicitly delegated, disposable
//! cgroup-v2 parent: LIB_SCOPED_TEST_ROOT=/sys/fs/cgroup/... cargo test -p
//! lib-scoped --test cgroup -- --ignored. No production-domain discovery.
use lib_scoped::{Domain, Error, EventKind, Observer, ScopeId, TargetId, TargetStatus};
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture {
    domain: Domain,
    root: PathBuf,
    children: Vec<Child>,
}
impl Fixture {
    fn new() -> Self {
        let parent = PathBuf::from(std::env::var_os("LIB_SCOPED_TEST_ROOT").expect(
            "set LIB_SCOPED_TEST_ROOT to an explicitly delegated disposable cgroup-v2 directory",
        ));
        assert!(
            parent.join("cgroup.controllers").is_file(),
            "test root must be cgroup v2"
        );
        let name = format!(
            "lib-scoped-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = parent.join(&name);
        assert!(!root.exists());
        let domain = Domain::create(&parent, &name).unwrap();
        Self {
            domain,
            root,
            children: Vec::new(),
        }
    }
    fn scope(&self, relative: &str) -> ScopeId {
        ScopeId::parse(format!("{}/{relative}", self.domain.name())).unwrap()
    }
    fn create(&self, relative: &str) -> ScopeId {
        let scope = self.scope(relative);
        self.domain.create_scope(&scope).unwrap();
        scope
    }
    fn process(&mut self, scope: &ScopeId) -> u32 {
        let child = Command::new("sleep")
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        self.children.push(child);
        self.domain.move_process(scope, pid).unwrap();
        pid
    }
    fn drain(&self, scope: &ScopeId) {
        assert!(
            self.domain
                .watch_scope(scope)
                .unwrap()
                .wait_timeout(Duration::from_secs(5))
                .unwrap(),
            "scope {scope} failed to drain"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
        }
        let _ = self.domain.kill_scope(&self.domain.root_id());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut remaining = false;
            for child in &mut self.children {
                if matches!(child.try_wait(), Ok(None)) {
                    remaining = true;
                }
            }
            if !remaining || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Ok(mut scopes) = self.domain.list_scopes(&self.domain.root_id()) {
            scopes.sort_by_key(|scope| std::cmp::Reverse(scope.depth()));
            for scope in scopes {
                let _ = self.domain.remove_scope(&scope);
            }
        }
        // Root belongs exclusively to this fixture. Never recursively remove
        // arbitrary filesystem paths or unrelated containment domains.
        let _ = fs::remove_dir(&self.root);
    }
}
fn target() -> TargetId {
    TargetId::parse("leader").unwrap()
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn tracking_termination_and_nonrecursive_removal() {
    let mut fixture = Fixture::new();
    let session = fixture.create("session");
    let nested = fixture.create("session/unknown");
    let leader = fixture.process(&session);
    fixture.process(&nested);
    assert_eq!(
        fixture.domain.scope_of(leader).unwrap(),
        Some(session.clone())
    );
    assert_eq!(
        fixture
            .domain
            .read_target_identity(&session, &target())
            .unwrap(),
        None
    );
    fixture
        .domain
        .assign_target(&session, &target(), leader)
        .unwrap();
    assert!(matches!(
        fixture.domain.target_status(&session, &target()).unwrap(),
        TargetStatus::Running(_)
    ));
    assert!(fixture.domain.target_exists(&session, &target()).unwrap());
    assert!(fixture.domain.scope_populated(&session).unwrap());
    assert!(fixture.domain.remove_scope(&session).is_err());
    fixture.domain.terminate_scope(&session).unwrap();
    fixture.drain(&session);
    assert!(
        fixture.domain.remove_scope(&session).is_err(),
        "empty child still prevents rmdir"
    );
    fixture.domain.remove_scope(&nested).unwrap();
    fixture.domain.remove_scope(&session).unwrap();
    fixture.domain.remove_scope(&session).unwrap();
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn migration_does_not_mean_exit_and_signalling_checks_membership() {
    let mut fixture = Fixture::new();
    let a = fixture.create("a");
    let b = fixture.create("b");
    let pid = fixture.process(&a);
    fixture.domain.assign_target(&a, &target(), pid).unwrap();
    let mut watch = fixture.domain.watch_target(&a, &target()).unwrap();
    fixture.domain.move_process(&b, pid).unwrap();
    assert!(matches!(
        fixture.domain.target_status(&a, &target()).unwrap(),
        TargetStatus::Running(_)
    ));
    assert!(!fixture.domain.target_exists(&a, &target()).unwrap());
    assert!(matches!(
        fixture.domain.terminate_target(&a, &target()),
        Err(Error::Membership { .. })
    ));
    assert!(!watch.wait_timeout(Duration::ZERO).unwrap());
    fixture.domain.kill_scope(&b).unwrap();
    assert!(watch.wait_timeout(Duration::from_secs(5)).unwrap());
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn assignment_is_exclusive_without_a_userspace_lock() {
    let mut fixture = Fixture::new();
    let scope = fixture.create("a");
    let pid = fixture.process(&scope);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let results = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let domain = &fixture.domain;
                let scope = &scope;
                let barrier = barrier.clone();
                threads.spawn(move || {
                    barrier.wait();
                    domain.assign_target(scope, &target(), pid)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, Error::TargetExists { .. }))
    );
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn target_record_replacement_does_not_rebind_an_existing_watch() {
    let mut fixture = Fixture::new();
    let scope = fixture.create("a");
    let first = fixture.process(&scope);
    fixture
        .domain
        .assign_target(&scope, &target(), first)
        .unwrap();
    let old_identity = fixture
        .domain
        .read_target_identity(&scope, &target())
        .unwrap()
        .unwrap();
    let watch = fixture.domain.watch_target(&scope, &target()).unwrap();
    fixture.domain.remove_target(&scope, &target()).unwrap();
    let second = fixture.process(&scope);
    fixture
        .domain
        .assign_target(&scope, &target(), second)
        .unwrap();
    let mut observer = Observer::new().unwrap();
    observer.add(watch);
    assert!(observer.wait(Duration::ZERO).unwrap().is_empty());
    fixture.children[0].kill().unwrap();
    let events = observer.wait(Duration::from_secs(5)).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::TargetExited);
    assert_eq!(events[0].process_identity, Some(old_identity));
    assert!(matches!(
        fixture.domain.target_status(&scope, &target()).unwrap(),
        TargetStatus::Running(_)
    ));
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn already_frozen_subtrees_recover_by_retrying_termination() {
    let mut fixture = Fixture::new();
    let scope = fixture.create("a");
    let nested = fixture.create("a/nested");
    fixture.process(&nested);
    // Simulate a caller dying after its freeze request, outside the frozen tree.
    fs::write(fixture.root.join("a/cgroup.freeze"), "1").unwrap();
    fixture.domain.terminate_scope(&scope).unwrap();
    fixture.drain(&scope);
    assert_eq!(
        fs::read_to_string(fixture.root.join("a/cgroup.freeze"))
            .unwrap()
            .trim(),
        "0"
    );
}

#[test]
#[ignore = "requires LIB_SCOPED_TEST_ROOT delegated cgroup-v2 directory"]
fn kill_and_removal_do_not_depend_on_valid_target_metadata() {
    let mut fixture = Fixture::new();
    let scope = fixture.create("a");
    let pid = fixture.process(&scope);
    fixture
        .domain
        .assign_target(&scope, &target(), pid)
        .unwrap();
    let name = c"user.scoped.target.leader";
    let path =
        std::ffi::CString::new(fixture.root.join("a").as_os_str().as_encoded_bytes()).unwrap();
    let bad = b"broken";
    // SAFETY: valid C path/name and readable byte buffer.
    assert_eq!(
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                bad.as_ptr().cast(),
                bad.len(),
                0,
            )
        },
        0
    );
    assert!(fixture.domain.target_status(&scope, &target()).is_err());
    fixture.domain.kill_scope(&scope).unwrap();
    fixture.drain(&scope);
    fixture.domain.remove_scope(&scope).unwrap();
}
