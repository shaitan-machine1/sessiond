use lib_sessiond::SessionCore;
use lib_sessiond::bus::{BusLifecycleEvents, Client};
use lib_sessiond::config::Config;
use libc::{LOG_ERR, LOG_WARNING, c_char, c_int, c_void};
use nix::unistd::User;
use pam_ffi::{PAM_SESSION_ERR, PAM_SUCCESS, PamHandle};
use std::ffi::{CStr, CString};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DATA_KEY: &CStr = c"pam_sessiond.sid";
const CONFIG_PATH: &str = "/etc/sessiond.conf";
#[derive(Default)]
struct Options {
    fail_open: bool,
    timeout: Option<Duration>,
    config: Option<PathBuf>,
}
impl Options {
    unsafe fn parse(argc: c_int, argv: *const *const c_char) -> Self {
        let mut options = Self::default();
        if argc <= 0 || argv.is_null() {
            return options;
        }
        for index in 0..argc as isize {
            // SAFETY: PAM provides argc valid pointers in argv.
            let value = unsafe { *argv.offset(index) };
            if value.is_null() {
                continue;
            }
            // SAFETY: PAM module options are NUL-terminated strings.
            let value = unsafe { CStr::from_ptr(value) }.to_string_lossy();
            if value == "fail_open" {
                options.fail_open = true;
            } else if let Some(raw) = value.strip_prefix("timeout=") {
                options.timeout = humantime::parse_duration(raw).ok();
            } else if let Some(raw) = value.strip_prefix("config=") {
                let path = PathBuf::from(raw);
                if path.is_absolute() {
                    options.config = Some(path);
                }
            }
        }
        options
    }
}
struct Failure {
    status: c_int,
    message: String,
}
impl Failure {
    fn new(status: c_int, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}
fn emit_message(message: &str, mut logger: impl FnMut(&str)) {
    logger(message);
}
unsafe fn log_at(pamh: *mut PamHandle, priority: c_int, message: &str) {
    // SAFETY: PAM supplies a live, non-null handle to every module entry point.
    if let Some(handle) = unsafe { pamh.as_ref() } {
        emit_message(message, |m| pam_ffi::syslog(handle, priority, m));
    }
}
unsafe extern "C" fn cleanup_sid(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: pam_sm_open_session stored exactly one Box<String> here.
        drop(unsafe { Box::from_raw(data.cast::<String>()) });
    }
}
fn core(options: &Options, events: bool) -> Result<SessionCore, String> {
    let path = options
        .config
        .as_deref()
        .unwrap_or_else(|| Path::new(CONFIG_PATH));
    let mut config = if path.exists() {
        Config::load(path).map_err(|e| format!("load {}: {e}", path.display()))?
    } else {
        Config::default()
    };
    if let Some(timeout) = options.timeout {
        config.session.open_timeout = timeout;
        config.user_service_manager.ready_timeout = timeout;
    }
    let core = SessionCore::new(config).map_err(|e| e.to_string())?;
    Ok(if events {
        core.with_events(BusLifecycleEvents::system())
    } else {
        core
    })
}
unsafe fn restore_environment(pamh: *mut PamHandle, values: &[(&str, Option<String>)]) {
    for (name, value) in values {
        let assignment = match value {
            Some(value) => CString::new(format!("{name}={value}")),
            None => CString::new(*name),
        };
        if let Ok(assignment) = assignment {
            // SAFETY: pam_putenv copies this valid string; restoration is best effort.
            let _ = unsafe { pam_ffi::put_env(pamh, &assignment) };
        }
    }
}
unsafe fn open_inner(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: caller is Linux-PAM and supplies a live handle/options array.
    let options = unsafe { Options::parse(argc, argv) };
    let result = (|| -> Result<(), Failure> {
        // SAFETY: live PAM handle from the module entry point.
        let username = unsafe { pam_ffi::get_user(pamh) }.map_err(|status| {
            Failure::new(
                status,
                format!("pam_get_user failed with PAM status {status}"),
            )
        })?;
        let user = User::from_name(&username)
            .map_err(|e| Failure::new(PAM_SESSION_ERR, format!("look up user {username:?}: {e}")))?
            .ok_or_else(|| {
                Failure::new(
                    pam_ffi::PAM_USER_UNKNOWN,
                    format!("user {username:?} does not exist"),
                )
            })?;
        let opened = core(&options, true)
            .map_err(|e| Failure::new(PAM_SESSION_ERR, e))?
            .open_session(user.uid.as_raw())
            .map_err(|e| Failure::new(PAM_SESSION_ERR, e.to_string()))?;
        for warning in &opened.warnings {
            // SAFETY: forwarded live PAM handle.
            unsafe { log_at(pamh, LOG_WARNING, warning) };
        }
        let runtime = opened
            .runtime
            .to_str()
            .ok_or_else(|| Failure::new(PAM_SESSION_ERR, "runtime path is not UTF-8"))?;
        let environment = [
            ("XDG_RUNTIME_DIR", runtime),
            ("XDG_SESSION_ID", opened.id.as_str()),
        ];
        let previous = environment.map(|(name, _)| {
            let c_name = CString::new(name).expect("literal environment name");
            // SAFETY: live PAM handle and a valid environment name.
            (name, unsafe { pam_ffi::get_env(pamh, &c_name) })
        });
        for (published, (name, value)) in environment.into_iter().enumerate() {
            let assignment = CString::new(format!("{name}={value}")).map_err(|_| {
                Failure::new(
                    PAM_SESSION_ERR,
                    format!("invalid NUL-containing {name} value"),
                )
            })?;
            // SAFETY: live PAM handle; pam_putenv copies the string.
            if let Err(status) = unsafe { pam_ffi::put_env(pamh, &assignment) } {
                // Publication failure never requests active teardown: optional
                // PAM may allow the already-contained login host to continue.
                unsafe { restore_environment(pamh, &previous[..published]) };
                return Err(Failure::new(
                    status,
                    format!("pam_putenv failed for {name} with PAM status {status}"),
                ));
            }
        }
        let data = Box::into_raw(Box::new(opened.id)).cast::<c_void>();
        // This is convenience only. Close resolves containment independently.
        if let Err(status) = unsafe { pam_ffi::set_data(pamh, DATA_KEY, data, cleanup_sid) } {
            // SAFETY: PAM rejected ownership transfer.
            drop(unsafe { Box::from_raw(data.cast::<String>()) });
            unsafe { restore_environment(pamh, &previous) };
            return Err(Failure::new(
                status,
                format!("pam_set_data failed with PAM status {status}"),
            ));
        }
        Ok(())
    })();
    match result {
        Ok(()) => PAM_SUCCESS,
        Err(failure) => {
            unsafe { log_at(pamh, LOG_ERR, &failure.message) };
            if options.fail_open {
                PAM_SUCCESS
            } else {
                failure.status
            }
        }
    }
}
unsafe fn close_inner(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: caller is Linux-PAM and supplies a live handle/options array.
    let options = unsafe { Options::parse(argc, argv) };
    let result = (|| -> Result<(), String> {
        let session = core(&options, false)?
            .session_for_process(std::process::id())
            .map_err(|e| e.to_string())?;
        let Some(session) = session else {
            return Ok(());
        };
        let timeout = options.timeout.unwrap_or(Duration::from_secs(30));
        Client::system(timeout)
            .map_err(|e| e.to_string())?
            .schedule_close_session(&session.id)
            .map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => PAM_SUCCESS,
        Err(error) => {
            unsafe { log_at(pamh, LOG_ERR, &error) };
            if options.fail_open {
                PAM_SUCCESS
            } else {
                PAM_SESSION_ERR
            }
        }
    }
}

/// Linux-PAM session-open entry point.
/// # Safety
/// PAM must supply a live `pamh` and an `argv` array containing `argc`
/// NUL-terminated option strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match std::panic::catch_unwind(AssertUnwindSafe(|| unsafe { open_inner(pamh, argc, argv) })) {
        Ok(status) => status,
        Err(_) => {
            unsafe {
                log_at(
                    pamh,
                    LOG_ERR,
                    "panic while opening a session through pam_sessiond",
                )
            };
            PAM_SESSION_ERR
        }
    }
}
/// Linux-PAM session-close entry point.
/// # Safety
/// PAM must supply the same live transaction handle and a valid option array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        close_inner(pamh, argc, argv)
    })) {
        Ok(status) => status,
        Err(_) => {
            unsafe {
                log_at(
                    pamh,
                    LOG_ERR,
                    "panic while closing a session through pam_sessiond",
                )
            };
            PAM_SESSION_ERR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_message_reaches_logger_unchanged() {
        let mut logged = String::new();
        emit_message("sessiond scheduled close unavailable", |message| {
            logged = message.to_owned()
        });
        assert_eq!(logged, "sessiond scheduled close unavailable");
    }
}
