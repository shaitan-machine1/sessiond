use lib_sessiond::{bus::Client, open_session_with_options, OpenOptions};
use nix::unistd::User;
use pamsm::{pam_module, LogLvl, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::time::Duration;

struct Options {
    local: OpenOptions,
    timeout: Duration,
}
fn options(args: &[String]) -> Result<Options, String> {
    let mut local = OpenOptions::default();
    let mut timeout = Duration::from_secs(30);
    for arg in args {
        if let Some(root) = arg.strip_prefix("cgroup_root=") {
            local.cgroup_root = root.into();
            if !local.cgroup_root.is_absolute() || root.contains('\0') {
                return Err("cgroup_root must be absolute and NUL-free".into());
            }
        } else if let Some(value) = arg.strip_prefix("timeout=") {
            timeout = humantime::parse_duration(value).map_err(|e| e.to_string())?;
            if timeout.is_zero() || timeout > Duration::from_secs(3600) {
                return Err("timeout must be in (0, 1 hour]".into());
            }
        } else {
            return Err(format!("unknown core option: {arg}"));
        }
    }
    Ok(Options { local, timeout })
}
fn failed(pam: &Pam, status: PamError, message: impl std::fmt::Display) -> PamError {
    let message = message.to_string().replace('\0', "\\0");
    let _ = pam.syslog(LogLvl::ERR, &format!("pam_sessiond_core: {message}"));
    status
}
struct Core;
impl PamServiceModule for Core {
    fn open_session(pam: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let mut options = match options(&args) {
            Ok(options) => options,
            Err(error) => return failed(&pam, PamError::SERVICE_ERR, error),
        };
        match pam.getenv("XDG_SEAT") {
            Ok(Some(seat)) => match seat.to_str() {
                Ok(seat) => {
                    options
                        .local
                        .initial_attributes
                        .insert("XDG_SEAT".into(), seat.into());
                }
                Err(e) => return failed(&pam, PamError::SESSION_ERR, e),
            },
            Ok(None) => {}
            Err(e) => return failed(&pam, PamError::SESSION_ERR, e),
        }
        let user = match pam.get_user(None) {
            Ok(Some(user)) => match user.to_str() {
                Ok(user) => user,
                Err(error) => return failed(&pam, PamError::USER_UNKNOWN, error),
            },
            Ok(None) => return failed(&pam, PamError::USER_UNKNOWN, "PAM_USER is unset"),
            Err(error) => return failed(&pam, error, error),
        };
        let uid = match User::from_name(user) {
            Ok(Some(user)) => user.uid.as_raw(),
            Ok(None) => return failed(&pam, PamError::USER_UNKNOWN, "PAM_USER has no account"),
            Err(error) => return failed(&pam, PamError::USER_UNKNOWN, error),
        };
        let opened = match open_session_with_options(uid, &options.local) {
            Ok(opened) => opened,
            Err(error) => return failed(&pam, PamError::SESSION_ERR, error),
        };
        match pam.putenv(&format!("XDG_SESSION_ID={}", opened.sid)) {
            Ok(()) => PamError::SUCCESS,
            Err(error) => failed(&pam, error, "cannot publish authoritative XDG_SESSION_ID"),
        }
    }
    fn close_session(pam: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let options = match options(&args) {
            Ok(options) => options,
            Err(error) => return failed(&pam, PamError::SERVICE_ERR, error),
        };
        let result =
            Client::system(options.timeout).and_then(|client| client.schedule_close_session());
        match result {
            Ok(()) => PamError::SUCCESS,
            Err(error) => failed(&pam, PamError::SESSION_ERR, error),
        }
    }
}
pam_module!(Core);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimal_local_options_reject_legacy_lifecycle_configuration() {
        let options = options(&[
            "cgroup_root=/explicit/disposable".into(),
            "timeout=2s".into(),
        ])
        .unwrap();
        assert_eq!(
            options.local.cgroup_root.to_str(),
            Some("/explicit/disposable")
        );
        assert_eq!(options.timeout, Duration::from_secs(2));
        for arg in [
            "config=/etc/sessiond.conf",
            "fail_open",
            "cgroup_root=relative",
            "timeout=0s",
            "timeout=overflow",
        ] {
            assert!(super::options(&[arg.into()]).is_err());
        }
    }
}
