//! The one per-scope teardown algorithm, shared by session/manager cleanup and
//! manager replacement. Workers supply execution; policy lives here.
use crate::{
    Error, Result,
    config::{ShutdownConfig, ShutdownMode},
};
use lib_scoped::{Domain, ScopeId, ScopeWatch, TargetId, TargetWatch};
use std::time::Duration;

pub(crate) trait ScopeObservation {
    fn empty(&mut self) -> Result<bool>;
    fn wait_empty(&mut self, timeout: Duration) -> Result<bool>;
}
pub(crate) trait TargetObservation {
    fn wait_exited(&mut self, timeout: Duration) -> Result<bool>;
}
pub(crate) trait Backend {
    type Scope: ScopeObservation;
    type Target: TargetObservation;
    fn watch_scope(&self, scope: &ScopeId) -> Result<Self::Scope>;
    fn watch_target(&self, scope: &ScopeId, target: &TargetId) -> Result<Self::Target>;
    fn terminate_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()>;
    fn kill_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()>;
    fn terminate_scope(&self, scope: &ScopeId) -> Result<()>;
    fn kill_scope(&self, scope: &ScopeId) -> Result<()>;
    fn descendants(&self, scope: &ScopeId) -> Result<Vec<ScopeId>>;
    fn remove(&self, scope: &ScopeId) -> Result<()>;
}
impl ScopeObservation for ScopeWatch {
    fn empty(&mut self) -> Result<bool> {
        Ok(ScopeWatch::empty(self)?)
    }
    fn wait_empty(&mut self, timeout: Duration) -> Result<bool> {
        Ok(self.wait_timeout(timeout)?)
    }
}
impl TargetObservation for TargetWatch {
    fn wait_exited(&mut self, timeout: Duration) -> Result<bool> {
        Ok(self.wait_timeout(timeout)?)
    }
}
impl Backend for Domain {
    type Scope = ScopeWatch;
    type Target = TargetWatch;
    fn watch_scope(&self, scope: &ScopeId) -> Result<Self::Scope> {
        Ok(Domain::watch_scope(self, scope)?)
    }
    fn watch_target(&self, scope: &ScopeId, target: &TargetId) -> Result<Self::Target> {
        Ok(Domain::watch_target(self, scope, target)?)
    }
    fn terminate_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()> {
        Ok(Domain::terminate_target(self, scope, target)?)
    }
    fn kill_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()> {
        Ok(Domain::kill_target(self, scope, target)?)
    }
    fn terminate_scope(&self, scope: &ScopeId) -> Result<()> {
        Ok(Domain::terminate_scope(self, scope)?)
    }
    fn kill_scope(&self, scope: &ScopeId) -> Result<()> {
        Ok(Domain::kill_scope(self, scope)?)
    }
    fn descendants(&self, scope: &ScopeId) -> Result<Vec<ScopeId>> {
        Ok(self.list_scopes(scope)?)
    }
    fn remove(&self, scope: &ScopeId) -> Result<()> {
        Ok(self.remove_scope(scope)?)
    }
}

pub(crate) fn shutdown<B: Backend>(
    backend: &B,
    scope: &ScopeId,
    primary: &TargetId,
    config: &ShutdownConfig,
) -> Result<Vec<String>> {
    let mut whole = backend.watch_scope(scope)?;
    let mut warnings = Vec::new();
    if whole.empty()? {
        remove_tree(backend, scope)?;
        return Ok(warnings);
    }
    // Broken/missing tracking, including watch construction failure, cannot
    // prevent an authorized explicit request from operating on the subtree.
    let mut target = match backend.watch_target(scope, primary) {
        Ok(watch) => Some(watch),
        Err(error) => {
            warnings.push(format!(
                "primary target unavailable; using whole-subtree termination: {error}"
            ));
            None
        }
    };
    let scope_already_signalled = target.is_none() || config.mode == ShutdownMode::Scope;
    let graceful = (|| -> Result<bool> {
        if scope_already_signalled {
            backend.terminate_scope(scope)?;
        } else {
            backend.terminate_target(scope, primary)?;
        }
        if let Some(watch) = &mut target
            && !watch.wait_exited(config.leader_timeout)?
        {
            backend.kill_target(scope, primary)?;
        }
        if !scope_already_signalled {
            backend.terminate_scope(scope)?;
        }
        whole.wait_empty(config.scope_timeout)
    })();
    let drained = match graceful {
        Ok(drained) => drained,
        Err(error) => {
            warnings.push(error.to_string());
            false
        }
    };
    if !drained {
        force(backend, scope, &mut whole, config.scope_timeout)
            .map_err(|error| diagnostics(scope, &warnings, error))?;
    }
    remove_tree(backend, scope).map_err(|error| diagnostics(scope, &warnings, error))?;
    Ok(warnings)
}
fn force<B: Backend>(
    backend: &B,
    scope: &ScopeId,
    watch: &mut B::Scope,
    timeout: Duration,
) -> Result<()> {
    backend.kill_scope(scope)?;
    if watch.wait_empty(timeout)? {
        Ok(())
    } else {
        Err(Error::incomplete(
            scope,
            "subtree did not drain after whole-scope kill",
        ))
    }
}
fn diagnostics(scope: &ScopeId, warnings: &[String], error: Error) -> Error {
    if warnings.is_empty() {
        error
    } else {
        Error::incomplete(scope, format!("{}; {error}", warnings.join("; ")))
    }
}
fn remove_tree<B: Backend>(backend: &B, scope: &ScopeId) -> Result<()> {
    let mut descendants = backend.descendants(scope)?;
    descendants.sort_by(|a, b| b.depth().cmp(&a.depth()).then(a.cmp(b)));
    for child in descendants {
        backend.remove(&child)?;
    }
    backend.remove(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    struct State {
        log: Vec<String>,
        empty: bool,
        tracked: bool,
        target_exited: bool,
        drain: VecDeque<bool>,
        fail: Option<&'static str>,
        descendants: Vec<ScopeId>,
    }
    #[derive(Clone)]
    struct Fake(Rc<RefCell<State>>);
    struct Scope(Fake);
    struct Target(Fake);
    impl Fake {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(State {
                log: Vec::new(),
                empty: false,
                tracked: true,
                target_exited: true,
                drain: [true].into(),
                fail: None,
                descendants: vec![
                    ScopeId::parse("test/a/nested").unwrap(),
                    ScopeId::parse("test/a/nested/deep").unwrap(),
                ],
            })))
        }
        fn action(&self, action: &str) -> Result<()> {
            let mut state = self.0.borrow_mut();
            state.log.push(action.to_owned());
            if state.fail == Some(action) {
                Err(Error::incomplete(
                    &ScopeId::parse("test/a").unwrap(),
                    format!("injected {action}"),
                ))
            } else {
                Ok(())
            }
        }
        fn log(&self) -> Vec<String> {
            self.0.borrow().log.clone()
        }
    }
    impl ScopeObservation for Scope {
        fn empty(&mut self) -> Result<bool> {
            self.0.action("query-empty")?;
            Ok(self.0.0.borrow().empty)
        }
        fn wait_empty(&mut self, timeout: Duration) -> Result<bool> {
            self.0
                .action(&format!("wait-empty:{}", timeout.as_secs()))?;
            Ok(self.0.0.borrow_mut().drain.pop_front().unwrap_or(false))
        }
    }
    impl TargetObservation for Target {
        fn wait_exited(&mut self, timeout: Duration) -> Result<bool> {
            self.0
                .action(&format!("wait-exited:{}", timeout.as_secs()))?;
            Ok(self.0.0.borrow().target_exited)
        }
    }
    impl Backend for Fake {
        type Scope = Scope;
        type Target = Target;
        fn watch_scope(&self, _: &ScopeId) -> Result<Scope> {
            self.action("watch-scope")?;
            Ok(Scope(self.clone()))
        }
        fn watch_target(&self, _: &ScopeId, _: &TargetId) -> Result<Target> {
            self.action("watch-target")?;
            if self.0.borrow().tracked {
                Ok(Target(self.clone()))
            } else {
                Err(Error::incomplete(
                    &ScopeId::parse("test/a").unwrap(),
                    "missing/corrupt tracking",
                ))
            }
        }
        fn terminate_target(&self, _: &ScopeId, _: &TargetId) -> Result<()> {
            self.action("term-target")
        }
        fn kill_target(&self, _: &ScopeId, _: &TargetId) -> Result<()> {
            self.action("kill-target")
        }
        fn terminate_scope(&self, _: &ScopeId) -> Result<()> {
            self.action("term-scope")
        }
        fn kill_scope(&self, _: &ScopeId) -> Result<()> {
            self.action("kill-scope")
        }
        fn descendants(&self, _: &ScopeId) -> Result<Vec<ScopeId>> {
            self.action("list")?;
            Ok(self.0.borrow().descendants.clone())
        }
        fn remove(&self, scope: &ScopeId) -> Result<()> {
            self.action(&format!("remove:{scope}"))
        }
    }
    fn run(fake: &Fake, mode: ShutdownMode) -> Result<Vec<String>> {
        shutdown(
            fake,
            &ScopeId::parse("test/a").unwrap(),
            &TargetId::parse("leader").unwrap(),
            &ShutdownConfig {
                mode,
                leader_timeout: Duration::from_secs(7),
                scope_timeout: Duration::from_secs(11),
            },
        )
    }
    #[test]
    fn leader_mode_signals_target_then_subtree_and_removes_deepest_first() {
        let fake = Fake::new();
        assert!(run(&fake, ShutdownMode::Leader).unwrap().is_empty());
        assert_eq!(
            fake.log(),
            [
                "watch-scope",
                "query-empty",
                "watch-target",
                "term-target",
                "wait-exited:7",
                "term-scope",
                "wait-empty:11",
                "list",
                "remove:test/a/nested/deep",
                "remove:test/a/nested",
                "remove:test/a"
            ]
        );
    }
    #[test]
    fn scope_mode_does_not_repeat_termination_and_target_timeout_has_no_extra_wait() {
        let fake = Fake::new();
        fake.0.borrow_mut().target_exited = false;
        run(&fake, ShutdownMode::Scope).unwrap();
        let log = fake.log();
        assert_eq!(log.iter().filter(|s| *s == "term-scope").count(), 1);
        assert_eq!(
            log.iter().filter(|s| s.starts_with("wait-exited")).count(),
            1
        );
        assert!(
            log.windows(3)
                .any(|s| s == ["wait-exited:7", "kill-target", "wait-empty:11"])
        );
    }
    #[test]
    fn every_termination_error_immediately_escalates() {
        for (mode, action) in [
            (ShutdownMode::Leader, "term-target"),
            (ShutdownMode::Scope, "term-scope"),
            (ShutdownMode::Leader, "term-scope"),
        ] {
            let fake = Fake::new();
            fake.0.borrow_mut().fail = Some(action);
            assert!(!run(&fake, mode).unwrap().is_empty());
            let log = fake.log();
            let index = log.iter().position(|s| s == action).unwrap();
            assert_eq!(log[index + 1], "kill-scope");
            assert_eq!(log[index + 2], "wait-empty:11");
        }
    }
    #[test]
    fn missing_tracking_goes_straight_to_subtree_and_scope_wait() {
        let fake = Fake::new();
        fake.0.borrow_mut().tracked = false;
        assert!(!run(&fake, ShutdownMode::Leader).unwrap().is_empty());
        let log = fake.log();
        assert!(
            !log.iter()
                .any(|s| s == "term-target" || s.starts_with("wait-exited"))
        );
        assert_eq!(log.iter().filter(|s| *s == "term-scope").count(), 1);
    }
    #[test]
    fn forced_kill_requires_an_additional_successful_drain_wait() {
        let fake = Fake::new();
        fake.0.borrow_mut().drain = [false, true].into();
        run(&fake, ShutdownMode::Scope).unwrap();
        assert!(
            fake.log()
                .windows(3)
                .any(|s| s == ["wait-empty:11", "kill-scope", "wait-empty:11"])
        );
        let fake = Fake::new();
        fake.0.borrow_mut().drain = [false, false].into();
        assert!(run(&fake, ShutdownMode::Scope).is_err());
        assert!(!fake.log().iter().any(|s| s.starts_with("remove:")));
    }
    #[test]
    fn empty_scope_skips_signalling_and_query_errors_never_prove_drain() {
        let fake = Fake::new();
        fake.0.borrow_mut().empty = true;
        run(&fake, ShutdownMode::Leader).unwrap();
        assert!(
            !fake
                .log()
                .iter()
                .any(|s| s.starts_with("term-") || s.starts_with("kill-"))
        );
        let fake = Fake::new();
        fake.0.borrow_mut().fail = Some("query-empty");
        assert!(run(&fake, ShutdownMode::Leader).is_err());
        assert!(!fake.log().iter().any(|s| s.starts_with("remove:")));
    }
    #[test]
    fn failed_kill_and_removal_remain_failures() {
        let fake = Fake::new();
        fake.0.borrow_mut().target_exited = false;
        fake.0.borrow_mut().fail = Some("kill-target");
        run(&fake, ShutdownMode::Leader).unwrap();
        assert!(
            fake.log()
                .windows(2)
                .any(|s| s == ["kill-target", "kill-scope"])
        );
        let fake = Fake::new();
        fake.0.borrow_mut().drain = [false].into();
        fake.0.borrow_mut().fail = Some("kill-scope");
        assert!(run(&fake, ShutdownMode::Scope).is_err());
        let fake = Fake::new();
        fake.0.borrow_mut().fail = Some("remove:test/a/nested/deep");
        assert!(run(&fake, ShutdownMode::Leader).is_err());
        assert!(!fake.log().iter().any(|s| s == "remove:test/a"));
    }
}
