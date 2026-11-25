use lib_scoped::{Attributes, Domain, ScopeId};
use std::os::unix::fs::MetadataExt;

fn fixture() -> (tempfile::TempDir, Domain, ScopeId) {
    let directory = tempfile::tempdir().unwrap();
    let domain = Domain::create(directory.path(), "test").unwrap();
    let id = ScopeId::parse("test/session").unwrap();
    domain.create_scope(&id).unwrap();
    (directory, domain, id)
}

#[test]
fn absent_attributes_are_empty_and_failed_publication_preserves_the_map() {
    let (_directory, domain, id) = fixture();
    let scope = domain.pin_scope(&id).unwrap();
    assert!(scope.get_attributes().unwrap().is_empty());
    assert_eq!(scope.get_attribute("missing").unwrap(), None);
    let map = Attributes::from([("runtime_dir".into(), "opaque".into())]);
    scope.replace_attributes(&map).unwrap();
    assert_eq!(
        scope.get_attribute("runtime_dir").unwrap().as_deref(),
        Some("opaque")
    );
    assert!(
        scope
            .replace_attributes(&Attributes::from([("bad".into(), "x".repeat(4097))]))
            .is_err()
    );
    assert_eq!(scope.get_attributes().unwrap(), map);
    assert!(domain.list_targets(&id).unwrap().is_empty());
    scope.replace_attributes(&Attributes::new()).unwrap();
    assert!(scope.get_attributes().unwrap().is_empty());
}

#[test]
fn removed_and_replaced_scopes_are_not_successful_empty_reads_or_writes() {
    let (_directory, domain, id) = fixture();
    let original = domain.pin_scope(&id).unwrap();
    original
        .replace_attributes(&Attributes::from([("original".into(), "yes".into())]))
        .unwrap();
    domain.remove_scope(&id).unwrap();
    domain.create_scope(&id).unwrap();
    assert!(original.get_attributes().is_err());
    assert!(original.modified_at().is_err());
    assert!(original.replace_attributes(&Attributes::new()).is_err());
    assert!(
        domain
            .pin_scope(&id)
            .unwrap()
            .get_attributes()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn modified_at_is_precise_directory_mtime_and_reads_do_not_refresh_it() {
    let (directory, domain, id) = fixture();
    let scope = domain.pin_scope(&id).unwrap();
    let metadata = directory.path().join(id.as_str()).metadata().unwrap();
    let timestamp = scope.modified_at().unwrap();
    assert_eq!(timestamp.seconds, metadata.mtime());
    assert_eq!(i64::from(timestamp.nanoseconds), metadata.mtime_nsec());
    assert_eq!(
        timestamp.to_system_time(),
        Some(metadata.modified().unwrap())
    );
    assert!(scope.get_attributes().unwrap().is_empty());
    assert_eq!(scope.modified_at().unwrap(), timestamp);
}

#[test]
fn concurrent_readers_only_observe_complete_map_versions() {
    let (_directory, domain, id) = fixture();
    let first = Attributes::from([("a".into(), "first".into()), ("b".into(), "first".into())]);
    let second = Attributes::from([("a".into(), "second".into()), ("b".into(), "second".into())]);
    domain
        .pin_scope(&id)
        .unwrap()
        .replace_attributes(&first)
        .unwrap();
    let reader = domain.pin_scope(&id).unwrap();
    let writer = domain.pin_scope(&id).unwrap();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            for n in 0..1000 {
                writer
                    .replace_attributes(if n % 2 == 0 { &second } else { &first })
                    .unwrap();
            }
        });
        for _ in 0..1000 {
            let map = reader.get_attributes().unwrap();
            assert!(map == first || map == second);
        }
    });
}
