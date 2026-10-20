use libc::{c_char, c_int, c_void};
use nix::unistd::User;
use pam_ffi::{PAM_SESSION_ERR, PAM_SUCCESS, PamHandle};
use std::ffi::{CStr, CString};
use std::panic::AssertUnwindSafe;
use std::time::Duration;

const DATA_KEY: &CStr = c"pam_sessiond.sid";

#[zbus::proxy(
    interface = "org.decoupling.sessiond1.Manager",
    default_service = "org.decoupling.sessiond1",
    default_path = "/org/decoupling/sessiond1"
)]
trait Sessiond {
    fn open_session(&self, uid: u32) -> zbus::Result<(String, String)>;
    fn close_session(&self, sid: &str) -> zbus::Result<()>;
}

#[derive(Default)]
struct Options {
    fail_open: bool,
    timeout: Option<Duration>,
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
            }
        }
        options
    }
}

unsafe extern "C" fn cleanup_sid(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: pam_sm_open_session stored exactly one Box<String> here.
        drop(unsafe { Box::from_raw(data.cast::<String>()) });
    }
}

fn run_async<T>(future: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(future)
}

async fn open(uid: u32, timeout: Duration) -> Result<(String, String), String> {
    tokio::time::timeout(timeout, async {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| error.to_string())?;
        SessiondProxy::new(&connection)
            .await
            .map_err(|error| error.to_string())?
            .open_session(uid)
            .await
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "OpenSession timed out".to_owned())?
}

async fn close(sid: &str, timeout: Duration) -> Result<(), String> {
    tokio::time::timeout(timeout, async {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| error.to_string())?;
        SessiondProxy::new(&connection)
            .await
            .map_err(|error| error.to_string())?
            .close_session(sid)
            .await
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "CloseSession timed out".to_owned())?
}

unsafe fn open_inner(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: caller is Linux-PAM and supplies a live handle/options array.
    let options = unsafe { Options::parse(argc, argv) };
    let result = (|| -> Result<(), c_int> {
        // SAFETY: live PAM handle from the module entry point.
        let username = unsafe { pam_ffi::get_user(pamh) }?;
        let user = User::from_name(&username)
            .map_err(|_| PAM_SESSION_ERR)?
            .ok_or(pam_ffi::PAM_USER_UNKNOWN)?;
        let timeout = options.timeout.unwrap_or(Duration::from_secs(30));
        let (sid, runtime) = run_async(open(user.uid.as_raw(), timeout)).map_err(|error| {
            eprintln!("pam_sessiond: {error}");
            PAM_SESSION_ERR
        })?;

        let environment = [
            format!("XDG_RUNTIME_DIR={runtime}"),
            format!("XDG_SESSION_ID={sid}"),
            format!("DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"),
        ];
        for value in environment {
            let value = CString::new(value).map_err(|_| PAM_SESSION_ERR)?;
            // SAFETY: live PAM handle; pam_putenv copies the string.
            if let Err(status) = unsafe { pam_ffi::put_env(pamh, &value) } {
                let _ = run_async(close(&sid, timeout));
                return Err(status);
            }
        }

        let data = Box::into_raw(Box::new(sid)).cast::<c_void>();
        // SAFETY: transfers Box ownership to PAM and matching cleanup function.
        if let Err(status) = unsafe { pam_ffi::set_data(pamh, DATA_KEY, data, cleanup_sid) } {
            // SAFETY: PAM rejected ownership transfer.
            let sid = unsafe { Box::from_raw(data.cast::<String>()) };
            let _ = run_async(close(&sid, timeout));
            return Err(status);
        }
        Ok(())
    })();
    match result {
        Ok(()) => PAM_SUCCESS,
        Err(_) if options.fail_open => PAM_SUCCESS,
        Err(status) => status,
    }
}

unsafe fn close_inner(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: caller is Linux-PAM and supplies a live handle/options array.
    let options = unsafe { Options::parse(argc, argv) };
    // SAFETY: data was stored under this key by open_session, if present.
    let data = match unsafe { pam_ffi::get_data(pamh, DATA_KEY) } {
        Ok(data) if !data.is_null() => data,
        _ => return PAM_SUCCESS,
    };
    // SAFETY: matching Box<String> remains owned by PAM for this transaction.
    let sid = unsafe { &*data.cast::<String>() };
    let timeout = options.timeout.unwrap_or(Duration::from_secs(30));
    match run_async(close(sid, timeout)) {
        Ok(()) => PAM_SUCCESS,
        Err(error) if options.fail_open => {
            eprintln!("pam_sessiond: {error}");
            PAM_SUCCESS
        }
        Err(error) => {
            eprintln!("pam_sessiond: {error}");
            PAM_SESSION_ERR
        }
    }
}

/// Linux-PAM session-open entry point.
///
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
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: forwards Linux-PAM's module arguments.
        unsafe { open_inner(pamh, argc, argv) }
    }))
    .unwrap_or(PAM_SESSION_ERR)
}

/// Linux-PAM session-close entry point.
///
/// # Safety
/// PAM must supply the same live transaction handle and a valid option array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: forwards Linux-PAM's module arguments.
        unsafe { close_inner(pamh, argc, argv) }
    }))
    .unwrap_or(PAM_SESSION_ERR)
}
