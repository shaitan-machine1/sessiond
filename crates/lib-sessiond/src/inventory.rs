use crate::{Error, Result};
use lib_scoped::{Domain, ProcessIdentity, ScopeId, TargetId, well_known};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub id: String,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub uid: u32,
    /// Recorded identity only. No process-existence/membership probe.
    pub leader: Option<ProcessIdentity>,
}

pub fn validate_session_id(id: &str) -> Result<()> {
    if id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::InvalidSession(id.to_owned()))
    }
}

fn user_roots(domain: &Domain) -> Result<Vec<(u32, ScopeId)>> {
    let mut roots = Vec::new();
    for scope in domain.list_children(&ScopeId::parse("sessiond/user").expect("literal scope"))? {
        let Some(raw) = scope.segments().next_back() else {
            continue;
        };
        if let Ok(uid) = raw.parse::<u32>()
            && uid.to_string() == raw
        {
            roots.push((uid, scope));
        }
    }
    Ok(roots)
}

pub(crate) fn session_roots(domain: &Domain, uid: u32) -> Result<Vec<ScopeId>> {
    // Count every child for retention, even an unexpected/raw-admin-created
    // name that is not a valid session ID. Never infer absence from tracking.
    Ok(domain.list_children(&well_known::sessiond_user_session_root(uid))?)
}

pub(crate) fn list(domain: &Domain) -> Result<Vec<Session>> {
    let mut sessions = Vec::new();
    let leader = TargetId::parse("leader").expect("literal target");
    for (uid, _) in user_roots(domain)? {
        for scope in session_roots(domain, uid)? {
            let id = scope.segments().next_back().expect("validated scope");
            if validate_session_id(id).is_err() {
                continue;
            }
            let recorded = domain.read_target_identity(&scope, &leader)?;
            sessions.push(Session {
                id: id.to_owned(),
                uid,
                leader: recorded,
            });
        }
    }
    sessions.sort_by(|a, b| (a.uid, &a.id).cmp(&(b.uid, &b.id)));
    Ok(sessions)
}

pub(crate) fn find(domain: &Domain, sid: &str) -> Result<Option<SessionIdentity>> {
    validate_session_id(sid)?;
    let mut found = None;
    for (uid, _) in user_roots(domain)? {
        let scope = well_known::sessiond_user_session(uid, sid).expect("validated SID");
        if domain.scope_identity(&scope)?.is_some() {
            if found.is_some() {
                return Err(Error::AmbiguousSession(sid.to_owned()));
            }
            found = Some(SessionIdentity {
                id: sid.to_owned(),
                uid,
            });
        }
    }
    Ok(found)
}

pub(crate) fn enclosing_session(scope: &ScopeId) -> Option<SessionIdentity> {
    let mut parts = scope.segments();
    if parts.next()? != "sessiond" || parts.next()? != "user" {
        return None;
    }
    let raw = parts.next()?;
    let uid: u32 = raw.parse().ok()?;
    if uid.to_string() != raw || parts.next()? != "session" {
        return None;
    }
    let id = parts.next()?;
    validate_session_id(id).ok()?;
    Some(SessionIdentity {
        id: id.to_owned(),
        uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SessionCore, config::Config};
    use std::fs;

    const SID: &str = "0123456789abcdef0123456789abcdef";
    fn fixture() -> (tempfile::TempDir, Domain, SessionCore) {
        let root = tempfile::tempdir().unwrap();
        let domain = Domain::create(root.path(), "sessiond").unwrap();
        let config = Config {
            cgroup_root: root.path().to_owned(),
            state_dir: root.path().join("must-not-touch"),
            ..Config::default()
        };
        (root, domain, SessionCore::new(config).unwrap())
    }
    fn create_session(domain: &Domain, uid: u32, sid: &str) -> ScopeId {
        for raw in [
            "sessiond/user".to_owned(),
            format!("sessiond/user/{uid}"),
            format!("sessiond/user/{uid}/session"),
        ] {
            match domain.create_scope(&ScopeId::parse(raw).unwrap()) {
                Ok(()) => {}
                Err(e) if e.is_already_exists() => {}
                Err(e) => panic!("{e}"),
            }
        }
        let scope = well_known::sessiond_user_session(uid, sid).unwrap();
        domain.create_scope(&scope).unwrap();
        scope
    }
    #[test]
    fn inventory_includes_partial_scopes_and_does_not_touch_lifecycle_state() {
        let (root, domain, core) = fixture();
        let scope = create_session(&domain, 1000, SID);
        domain
            .create_scope(&scope.join("unknown-child").unwrap())
            .unwrap();
        assert_eq!(
            core.list_sessions().unwrap(),
            vec![Session {
                id: SID.into(),
                uid: 1000,
                leader: None
            }]
        );
        assert!(!root.path().join("must-not-touch").exists());
        domain
            .remove_scope(&scope.join("unknown-child").unwrap())
            .unwrap();
        domain.remove_scope(&scope).unwrap();
        assert!(core.list_sessions().unwrap().is_empty());
    }
    #[test]
    fn inventory_does_not_traverse_inside_session_subtrees() {
        let (root, domain, core) = fixture();
        let scope = create_session(&domain, 1000, SID);
        // A raw directory outside the portable identifier syntax must not
        // interfere with inventory of its enclosing session root.
        fs::create_dir(root.path().join(scope.as_str()).join("not portable")).unwrap();
        assert_eq!(core.list_sessions().unwrap().len(), 1);
    }
    #[test]
    fn nested_membership_resolves_session_root_without_leader_tracking() {
        let scope =
            ScopeId::parse(format!("sessiond/user/1000/session/{SID}/nested/worker")).unwrap();
        assert_eq!(
            enclosing_session(&scope),
            Some(SessionIdentity {
                id: SID.into(),
                uid: 1000
            })
        );
        for raw in [
            "sessiond/user/1000/service/nested",
            "sessiond/user/1000/session",
            "other/user/1000/session/x",
            "sessiond/user/01000/session/x",
        ] {
            assert_eq!(enclosing_session(&ScopeId::parse(raw).unwrap()), None);
        }
    }
    #[test]
    fn duplicate_session_ids_are_not_resolved_to_an_arbitrary_uid() {
        let (_root, domain, _core) = fixture();
        create_session(&domain, 1000, SID);
        create_session(&domain, 1001, SID);
        assert!(matches!(
            find(&domain, SID),
            Err(Error::AmbiguousSession(_))
        ));
    }
    #[test]
    fn an_invalid_cgroup_mount_is_not_an_empty_inventory() {
        let root = tempfile::tempdir().unwrap();
        let core = SessionCore::new(Config {
            cgroup_root: root.path().join("missing-mount"),
            ..Config::default()
        })
        .unwrap();
        assert!(core.list_sessions().is_err());
    }
    #[test]
    fn empty_missing_domain_is_read_only_and_ids_are_validated() {
        let root = tempfile::tempdir().unwrap();
        let core = SessionCore::new(Config {
            cgroup_root: root.path().to_owned(),
            ..Config::default()
        })
        .unwrap();
        assert!(core.list_sessions().unwrap().is_empty());
        assert!(!root.path().join("sessiond").exists());
        for raw in ["../bad", "", "ABCDEF0123456789abcdef0123456789ab", "short"] {
            assert!(validate_session_id(raw).is_err());
        }
    }
}
