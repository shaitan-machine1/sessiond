use lib_sessiond::{bus::Client, Attributes, SessionInfo};
use pamsm::{pam_module, LogLvl, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::time::Duration;

#[derive(Debug)]
struct Failure {
    status: PamError,
    message: String,
}
impl From<PamError> for Failure {
    fn from(status: PamError) -> Self {
        Self {
            status,
            message: format!("PAM environment operation failed: {status}"),
        }
    }
}
impl From<lib_sessiond::Error> for Failure {
    fn from(error: lib_sessiond::Error) -> Self {
        Self {
            status: PamError::SESSION_ERR,
            message: error.to_string(),
        }
    }
}
trait Environment {
    fn contains(&self, name: &str) -> Result<bool, Failure> {
        Ok(self.get(name)?.is_some())
    }
    fn get(&self, name: &str) -> Result<Option<String>, Failure>;
    fn put(&self, record: &str) -> Result<(), Failure>;
}
struct PamEnvironment<'a>(&'a Pam);
impl Environment for PamEnvironment<'_> {
    fn contains(&self, name: &str) -> Result<bool, Failure> {
        Ok(self.0.getenv(name)?.is_some())
    }
    fn get(&self, name: &str) -> Result<Option<String>, Failure> {
        self.0
            .getenv(name)?
            .map(|value| {
                value.to_str().map(str::to_owned).map_err(|_| Failure {
                    status: PamError::SESSION_ERR,
                    message: format!("non-UTF8 {name}"),
                })
            })
            .transpose()
    }
    fn put(&self, record: &str) -> Result<(), Failure> {
        self.0.putenv(record).map_err(Into::into)
    }
}
trait Readiness {
    fn ensure(&self) -> lib_sessiond::Result<SessionInfo>;
    fn update(&self, sid: &str, attrs: &Attributes) -> lib_sessiond::Result<()>;
}
impl Readiness for Client {
    fn ensure(&self) -> lib_sessiond::Result<SessionInfo> {
        self.ensure_session_ready()
    }
    fn update(&self, sid: &str, attrs: &Attributes) -> lib_sessiond::Result<()> {
        self.update_session_attrs(sid, attrs, &[])
    }
}
fn timeout(args: &[String]) -> Result<Duration, Failure> {
    let mut timeout = Duration::from_secs(30);
    for arg in args {
        let value = arg.strip_prefix("timeout=").ok_or_else(|| Failure {
            status: PamError::SERVICE_ERR,
            message: format!("unknown readiness option: {arg}"),
        })?;
        timeout = humantime::parse_duration(value).map_err(|e| Failure {
            status: PamError::SERVICE_ERR,
            message: e.to_string(),
        })?;
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(Failure {
                status: PamError::SERVICE_ERR,
                message: "timeout must be in (0, 1 hour]".into(),
            });
        }
    }
    Ok(timeout)
}
fn perform<T: Readiness>(
    env: &impl Environment,
    connect: impl FnOnce() -> Result<T, Failure>,
) -> Result<(), Failure> {
    // Sanitize before option parsing, bus setup, readiness or attribute work.
    // Do not unset an absent variable: PAM may report BAD_ITEM for that case.
    if env.contains("XDG_RUNTIME_DIR")? {
        env.put("XDG_RUNTIME_DIR")?;
    }
    let client = connect()?;
    let info = client.ensure()?;
    if let Some(seat) = env.get("XDG_SEAT")? {
        client.update(&info.sid, &Attributes::from([("XDG_SEAT".into(), seat)]))?;
    }
    env.put(&format!("XDG_RUNTIME_DIR={}", info.runtime_dir))?;
    Ok(())
}
struct Ready;
impl PamServiceModule for Ready {
    fn open_session(pam: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        match perform(&PamEnvironment(&pam), || {
            Ok(Client::system(timeout(&args)?)?)
        }) {
            Ok(()) => PamError::SUCCESS,
            Err(error) => {
                let _ = pam.syslog(
                    LogLvl::ERR,
                    &format!("pam_sessiond_ready: {}", error.message.replace('\0', "\\0")),
                );
                error.status
            }
        }
    }
    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}
pam_module!(Ready);

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Env {
        values: RefCell<Attributes>,
        fail_put: bool,
        fail_publish: bool,
    }
    impl Environment for Env {
        fn get(&self, name: &str) -> Result<Option<String>, Failure> {
            Ok(self.values.borrow().get(name).cloned())
        }
        fn put(&self, record: &str) -> Result<(), Failure> {
            if self.fail_put || (self.fail_publish && record.starts_with("XDG_RUNTIME_DIR=")) {
                return Err(PamError::BUF_ERR.into());
            }
            if let Some((name, value)) = record.split_once('=') {
                self.values.borrow_mut().insert(name.into(), value.into());
            } else {
                self.values.borrow_mut().remove(record);
            }
            Ok(())
        }
    }
    struct Transport {
        fail_ready: bool,
        fail_attrs: bool,
    }
    impl Readiness for Transport {
        fn ensure(&self) -> lib_sessiond::Result<SessionInfo> {
            if self.fail_ready {
                return Err(lib_sessiond::Error::new(
                    lib_sessiond::ErrorCode::ReadinessFailed,
                    "injected failure",
                ));
            }
            Ok(SessionInfo {
                sid: "0123456789abcdef0123456789abcdef".into(),
                uid: 1000,
                runtime_dir: "/validated/runtime/1000".into(),
            })
        }
        fn update(&self, _: &str, attrs: &Attributes) -> lib_sessiond::Result<()> {
            assert_eq!(
                attrs,
                &Attributes::from([("XDG_SEAT".into(), "supplied-seat".into())])
            );
            if self.fail_attrs {
                return Err(lib_sessiond::Error::new(
                    lib_sessiond::ErrorCode::BackendError,
                    "attribute failure",
                ));
            }
            Ok(())
        }
    }
    fn env() -> Env {
        Env {
            values: RefCell::new(Attributes::from([
                ("XDG_RUNTIME_DIR".into(), "/stale/supplied".into()),
                ("XDG_SESSION_ID".into(), "actual-core-sid".into()),
                ("XDG_SEAT".into(), "supplied-seat".into()),
                ("UNRELATED".into(), "keep".into()),
            ])),
            fail_put: false,
            fail_publish: false,
        }
    }
    #[test]
    fn runtime_is_cleared_before_connection_and_sid_is_never_rolled_back() {
        let env = env();
        let result: Result<(), Failure> = perform::<Transport>(&env, || {
            assert!(env.get("XDG_RUNTIME_DIR").unwrap().is_none());
            Err(PamError::SESSION_ERR.into())
        });
        assert!(result.is_err());
        assert_eq!(
            env.get("XDG_SESSION_ID").unwrap().as_deref(),
            Some("actual-core-sid")
        );
        assert_eq!(env.get("UNRELATED").unwrap().as_deref(), Some("keep"));
    }
    #[test]
    fn readiness_and_attribute_failures_do_not_restore_supplied_runtime() {
        for (fail_ready, fail_attrs) in [(true, false), (false, true)] {
            let env = env();
            assert!(perform(&env, || Ok(Transport {
                fail_ready,
                fail_attrs
            }))
            .is_err());
            assert!(env.get("XDG_RUNTIME_DIR").unwrap().is_none());
        }
        let env = env();
        perform(&env, || {
            Ok(Transport {
                fail_ready: false,
                fail_attrs: false,
            })
        })
        .unwrap();
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").unwrap().as_deref(),
            Some("/validated/runtime/1000")
        );
    }
    #[test]
    fn publication_failure_leaves_runtime_absent_without_undoing_core_identity() {
        let mut env = env();
        env.fail_publish = true;
        let error = perform(&env, || {
            Ok(Transport {
                fail_ready: false,
                fail_attrs: false,
            })
        })
        .unwrap_err();
        assert_eq!(error.status, PamError::BUF_ERR);
        assert!(env.get("XDG_RUNTIME_DIR").unwrap().is_none());
        assert_eq!(
            env.get("XDG_SESSION_ID").unwrap().as_deref(),
            Some("actual-core-sid")
        );
    }
    #[test]
    fn inability_to_sanitize_is_an_actual_error_and_never_connects() {
        let mut env = env();
        env.fail_put = true;
        let error = perform::<Transport>(&env, || panic!("must not connect after failed unset"))
            .unwrap_err();
        assert_eq!(error.status, PamError::BUF_ERR);
        assert_eq!(
            env.get("XDG_RUNTIME_DIR").unwrap().as_deref(),
            Some("/stale/supplied")
        );
    }
}
