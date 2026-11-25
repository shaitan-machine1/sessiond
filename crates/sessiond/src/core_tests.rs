use super::*;
use std::fs;
use std::os::fd::AsRawFd;
use std::time::UNIX_EPOCH;
pub(super) const SID: &str = "0123456789abcdef0123456789abcdef";
pub(super) fn fixture(
    linger: bool,
) -> (
    tempfile::TempDir,
    Domain,
    Arc<SessionCore>,
    tokio::sync::mpsc::Receiver<Signal>,
) {
    let root = tempfile::tempdir().unwrap();
    let domain = Domain::create(root.path(), "sessiond").unwrap();
    for raw in [
        "sessiond/user",
        "sessiond/user/1000",
        "sessiond/user/1000/session",
    ] {
        domain.create_scope(&ScopeId::parse(raw).unwrap()).unwrap();
    }
    domain
        .create_scope(&well_known::sessiond_user_session(1000, SID).unwrap())
        .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let core = SessionCore::with_signals(
        Config {
            cgroup_root: root.path().into(),
            runtime_parent: root.path().join("runtime"),
            state_dir: root.path().join("state"),
            linger,
            ..Config::default()
        },
        sender,
    )
    .unwrap();
    (root, domain, Arc::new(core), receiver)
}
pub(super) fn record(root: &std::path::Path, value: &str) {
    let directory = fs::File::open(root.join(format!("sessiond/user/1000/session/{SID}"))).unwrap();
    // SAFETY: fixture-only directory, static xattr name, initialized record bytes.
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                directory.as_raw_fd(),
                c"user.scoped.target.master".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        0
    );
}
#[test]
fn initializer_age_uses_precise_mtime_and_a_fixed_ten_second_boundary() {
    let now = UNIX_EPOCH + Duration::from_secs(20);
    for (seconds, nanoseconds, expired) in [
        (10, 0, true),
        (10, 1, false),
        (9, 999_999_999, true),
        (21, 0, false),
        (-1, 500_000_000, true),
    ] {
        assert_eq!(
            initializer_expired(
                lib_scoped::Timestamp {
                    seconds,
                    nanoseconds
                },
                now
            )
            .unwrap(),
            expired
        );
    }
    assert!(
        initializer_expired(
            lib_scoped::Timestamp {
                seconds: 0,
                nanoseconds: 1_000_000_000
            },
            now
        )
        .is_err()
    );
}
#[test]
fn validity_hides_partial_roots_and_ready_is_daemon_owned() {
    let (root, _, core, mut signals) = fixture(false);
    assert_eq!(
        core.get_master(SID).unwrap_err().public().code,
        ErrorCode::SessionNotFound
    );
    assert!(core.list_infos().unwrap().is_empty());
    assert!(core.find_session(SID).unwrap().is_some());
    let (_, _, pinned) = core.session_scope(SID).unwrap();
    record(
        root.path(),
        &format!(
            "v2:{}:{}",
            std::process::id(),
            lib_scoped::read_start_time(std::process::id()).unwrap()
        ),
    );
    assert!(core.get_session(SID).is_err());
    pinned
        .replace_attributes(&Attributes::from([("ready".into(), "1".into())]))
        .unwrap();
    let original = core.get_session(SID).unwrap();
    let attributes = Attributes::from([
        ("runtime_dir".into(), "/inert".into()),
        ("sid".into(), "not-an-identity".into()),
        ("XDG_SEAT".into(), "opaque".into()),
    ]);
    core.update_attrs(
        core.session_scope(SID).unwrap().2,
        attributes.clone(),
        vec![],
    )
    .unwrap();
    let mut published = attributes.clone();
    published.insert("ready".into(), "1".into());
    assert_eq!(core.get_attrs(SID).unwrap(), published);
    assert_eq!(core.get_session(SID).unwrap(), original);
    assert!(
        core.update_attrs(
            core.session_scope(SID).unwrap().2,
            Attributes::from([("ready".into(), "0".into())]),
            vec![]
        )
        .is_err()
    );
    assert!(
        core.update_attrs(
            core.session_scope(SID).unwrap().2,
            Attributes::new(),
            vec!["ready".into()]
        )
        .is_err()
    );
    assert!(
        core.update_attrs(
            core.session_scope(SID).unwrap().2,
            attributes.clone(),
            vec!["sid".into()]
        )
        .is_err()
    );
    assert_eq!(core.get_attrs(SID).unwrap(), published);
    core.update_attrs(
        core.session_scope(SID).unwrap().2,
        Attributes::new(),
        vec!["sid".into(), "missing".into()],
    )
    .unwrap();
    assert!(!core.get_attrs(SID).unwrap().contains_key("sid"));
    record(root.path(), "malformed");
    assert!(core.list_infos().is_err());
    assert_eq!(
        core.get_master(SID).unwrap_err().public().code,
        ErrorCode::BackendError
    );
    assert!(core.reconcile(1000).is_err());
    assert!(core.find_session(SID).unwrap().is_some());
    assert!(signals.try_recv().is_err());
}
#[test]
fn dead_or_reused_master_is_hidden_without_triggering_removal() {
    let (root, domain, core, mut signals) = fixture(false);
    let scope = well_known::sessiond_user_session(1000, SID).unwrap();
    domain
        .pin_scope(&scope)
        .unwrap()
        .replace_attributes(&Attributes::from([("ready".into(), "1".into())]))
        .unwrap();
    record(
        root.path(),
        &format!(
            "v2:{}:{}",
            std::process::id(),
            lib_scoped::read_start_time(std::process::id()).unwrap() + 1
        ),
    );
    assert!(core.list_infos().unwrap().is_empty());
    for code in [
        core.get_session(SID).unwrap_err().public().code,
        core.get_attrs(SID).unwrap_err().public().code,
        core.get_master(SID).unwrap_err().public().code,
    ] {
        assert_eq!(code, ErrorCode::SessionNotFound);
    }
    assert!(domain.scope_identity(&scope).unwrap().is_some());
    assert!(signals.try_recv().is_err());
}
#[test]
fn process_lookup_is_instance_checked_and_queries_never_repair() {
    let (root, _, core, _) = fixture(false);
    let start = lib_sessiond::current_process_start_time().unwrap();
    assert_eq!(
        core.session_by_pid(std::process::id(), start + 1)
            .unwrap_err()
            .public()
            .code,
        ErrorCode::ProcessChanged
    );
    assert_eq!(
        core.session_by_pid(std::process::id(), start)
            .unwrap_err()
            .public()
            .code,
        ErrorCode::NoSession
    );
    assert_eq!(
        core.session_by_pid(0, 0).unwrap_err().public().code,
        ErrorCode::InvalidArgument
    );
    let mut child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let pid = child.id();
    let start = lib_scoped::read_start_time(pid).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        core.session_by_pid(pid, start).unwrap_err().public().code,
        ErrorCode::ProcessNotFound
    );
    assert!(!root.path().join("runtime").exists());
}
#[test]
fn recent_or_future_untracked_roots_are_not_cleanup_eligible() {
    let (root, domain, core, mut signals) = fixture(true);
    let id = well_known::sessiond_user_session(1000, SID).unwrap();
    let directory = fs::File::open(root.path().join(id.as_str())).unwrap();
    for time in [
        SystemTime::now(),
        SystemTime::now() + Duration::from_secs(60),
    ] {
        directory
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
        core.reconcile(1000).unwrap();
        assert!(domain.scope_identity(&id).unwrap().is_some());
    }
    assert!(!root.path().join("runtime").exists());
    assert!(signals.try_recv().is_err());
}
#[test]
fn obsolete_generation_close_does_not_touch_a_replacement_or_emit_removal() {
    let (_root, domain, core, mut signals) = fixture(true);
    let id = well_known::sessiond_user_session(1000, SID).unwrap();
    let old = domain.pin_scope(&id).unwrap();
    domain.remove_scope(&id).unwrap();
    domain.create_scope(&id).unwrap();
    let new = domain.pin_scope(&id).unwrap();
    assert_ne!(new.identity(), old.identity());
    core.close_tree(SID, Some(old.identity())).unwrap();
    assert_eq!(domain.scope_identity(&id).unwrap(), Some(new.identity()));
    assert!(signals.try_recv().is_err());
}
#[test]
fn an_admitted_attribute_patch_cannot_follow_a_replacement_generation() {
    let (_root, domain, core, _) = fixture(false);
    let old = core.session_scope(SID).unwrap().2;
    let id = old.id().clone();
    domain.remove_scope(&id).unwrap();
    domain.create_scope(&id).unwrap();
    assert!(
        core.update_attrs(
            old,
            Attributes::from([("key".into(), "value".into())]),
            vec![]
        )
        .is_err()
    );
    assert!(
        core.session_scope(SID)
            .unwrap()
            .2
            .get_attributes()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn absent_tree_close_completion_is_not_shared_resource_cleanup() {
    let (root, domain, core, mut signals) = fixture(false);
    let id = well_known::sessiond_user_session(1000, SID).unwrap();
    let generation = domain.scope_identity(&id).unwrap().unwrap();
    domain.remove_scope(&id).unwrap();
    fs::write(root.path().join("shared-resource-marker"), "keep").unwrap();
    let (result, receiver) = tokio::sync::watch::channel(None);
    core.completions
        .lock()
        .unwrap()
        .insert(SID.into(), Arc::new(CloseCompletion { generation, result }));
    core.close_tree(SID, Some(generation)).unwrap();
    assert!(receiver.borrow().as_ref().unwrap().is_ok());
    assert!(root.path().join("shared-resource-marker").exists());
    assert!(signals.try_recv().is_err());
}
#[test]
#[ignore = "requires root; disposable runtime-only fixture, no real cgroup"]
fn young_invalid_roots_do_not_retain_runtime_or_get_pruned() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (root, domain, core, mut signals) = fixture(false);
    runtime::ensure(&core.config.runtime_parent, 1000, 1000).unwrap();
    core.reconcile(1000).unwrap();
    assert!(!root.path().join("runtime/1000").exists());
    assert!(
        domain
            .scope_identity(&well_known::sessiond_user_session(1000, SID).unwrap())
            .unwrap()
            .is_some()
    );
    assert!(signals.try_recv().is_err());
}
#[test]
#[ignore = "requires root; disposable runtime-only fixture, no real cgroup"]
fn failed_runtime_cleanup_keeps_uid_discoverable_until_confirmed_removal() {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (root, domain, core, _) = fixture(false);
    domain
        .remove_scope(&well_known::sessiond_user_session(1000, SID).unwrap())
        .unwrap();
    runtime::ensure(&core.config.runtime_parent, 1000, 1000).unwrap();
    let runtime = root.path().join("runtime/1000");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(core.reconcile(1000).is_err());
    assert_eq!(core.uids().unwrap(), vec![1000]);
    assert!(runtime.exists());
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    core.reconcile(1000).unwrap();
    assert!(core.uids().unwrap().is_empty());
    assert!(!runtime.exists());
}
