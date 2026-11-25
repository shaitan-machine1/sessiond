//! C ownership boundary. Ordinary failures return errors; unexpected panics abort.
#![allow(clippy::missing_safety_doc)] // The installed header documents the shared pointer contract.
use crate::{
    Attributes, Error, ErrorCode, OpenOptions, Result, SessionInfo,
    bus::{Bus, Client, Event},
};
use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::time::Duration;

#[repr(C)]
pub struct CError {
    pub code: u32,
    pub message: *mut c_char,
    pub remote_name: *mut c_char,
}
#[repr(C)]
pub struct CSession {
    pub sid: *mut c_char,
    pub uid: u32,
    pub runtime_dir: *mut c_char,
}
#[repr(C)]
pub struct CSessions {
    pub items: *mut CSession,
    pub length: usize,
}
#[repr(C)]
pub struct CAttribute {
    pub name: *mut c_char,
    pub value: *mut c_char,
}
#[repr(C)]
pub struct CAttributes {
    pub items: *mut CAttribute,
    pub length: usize,
}
#[repr(C)]
pub struct CEvent {
    pub kind: u32,
    pub sid: *mut c_char,
    pub uid: u32,
}

fn string(value: String) -> *mut c_char {
    // Diagnostics escape NUL; ordinary strings are validated at conversion.
    CString::new(value.replace('\0', "\\0"))
        .expect("NUL escaped")
        .into_raw()
}
unsafe fn input<'a>(value: *const c_char) -> Result<&'a str> {
    if value.is_null() {
        return Err(Error::new(ErrorCode::InvalidArgument, "null string"));
    }
    // SAFETY: the caller promises a readable NUL-terminated string.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "non-UTF-8 input"))
}
unsafe fn client<'a>(value: *mut Client) -> Result<&'a mut Client> {
    // SAFETY: caller serializes access to a live client returned by client_new.
    unsafe { value.as_mut() }.ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "null client"))
}
unsafe fn output<T>(target: *mut *mut T, value: T) -> Result<()> {
    if target.is_null() {
        return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
    }
    // SAFETY: caller supplies writable output storage.
    unsafe { *target = Box::into_raw(Box::new(value)) };
    Ok(())
}
unsafe fn finish(error: *mut *mut CError, operation: impl FnOnce() -> Result<()>) -> u32 {
    if !error.is_null() {
        // SAFETY: writable error output or NULL.
        unsafe { *error = ptr::null_mut() };
    }
    match operation() {
        Ok(()) => 0,
        Err(failure) => {
            let code = failure.code as u32;
            if !error.is_null() {
                let value = CError {
                    code,
                    message: string(failure.message),
                    remote_name: failure.remote_name.map_or(ptr::null_mut(), string),
                };
                // SAFETY: writable error output.
                unsafe { *error = Box::into_raw(Box::new(value)) };
            }
            code
        }
    }
}
fn session(info: SessionInfo) -> CSession {
    CSession {
        sid: string(info.sid),
        uid: info.uid,
        runtime_dir: string(info.runtime_dir),
    }
}
unsafe fn release_string(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: exactly one matching CString allocation from this library.
        drop(unsafe { CString::from_raw(value) });
    }
}
fn boxed_slice<T>(values: Vec<T>) -> (*mut T, usize) {
    let mut values = values.into_boxed_slice();
    let result = (values.as_mut_ptr(), values.len());
    std::mem::forget(values);
    result
}
unsafe fn release_slice<T>(items: *mut T, length: usize) -> Box<[T]> {
    // SAFETY: matching pointer/length produced by boxed_slice, including empty slices.
    unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(items, length)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_client_new(
    address: *const c_char,
    timeout_ms: u64,
    result: *mut *mut Client,
    error: *mut *mut CError,
) -> u32 {
    // SAFETY: all pointer inputs obey the installed header's shared contract.
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            let bus = if address.is_null() {
                Bus::System
            } else {
                Bus::Address(input(address)?.to_owned())
            };
            output(result, Client::new(bus, Duration::from_millis(timeout_ms))?)
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_client_free(value: *mut Client) {
    if !value.is_null() {
        drop(unsafe { Box::from_raw(value) });
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_open_session(
    uid: u32,
    root: *const c_char,
    result: *mut *mut CSession,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            let options = if root.is_null() {
                OpenOptions::default()
            } else {
                OpenOptions {
                    cgroup_root: input(root)?.into(),
                }
            };
            let opened = crate::open_session_with_options(uid, &options)?;
            output(
                result,
                CSession {
                    sid: string(opened.sid),
                    uid: opened.uid,
                    runtime_dir: ptr::null_mut(),
                },
            )
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_current_process_start_time(
    result: *mut u64,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            let result = result
                .as_mut()
                .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "null start-time output"))?;
            *result = crate::current_process_start_time()?;
            Ok(())
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_list_sessions(
    value: *mut Client,
    result: *mut *mut CSessions,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            let (items, length) = boxed_slice(
                client(value)?
                    .list_sessions()?
                    .into_iter()
                    .map(session)
                    .collect(),
            );
            output(result, CSessions { items, length })
        })
    }
}
macro_rules! session_call {
    ($function:ident, $method:ident, sid) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $function(
            value: *mut Client,
            sid: *const c_char,
            result: *mut *mut CSession,
            error: *mut *mut CError,
        ) -> u32 {
            unsafe {
                finish(error, || {
                    if result.is_null() {
                        return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
                    }
                    *result = ptr::null_mut();
                    output(result, session(client(value)?.$method(input(sid)?)?))
                })
            }
        }
    };
}
session_call!(sessiond_get_session, get_session, sid);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_get_session_by_pid(
    value: *mut Client,
    pid: u32,
    start_time: u64,
    result: *mut *mut CSession,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            output(
                result,
                session(client(value)?.get_session_by_pid(pid, start_time)?),
            )
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_get_session_master_pid(
    value: *mut Client,
    sid: *const c_char,
    pid: *mut u32,
    start_time: *mut u64,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if pid.is_null() || start_time.is_null() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "null identity output",
                ));
            }
            let (found_pid, found_start) = client(value)?.get_session_master_pid(input(sid)?)?;
            *pid = found_pid;
            *start_time = found_start;
            Ok(())
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_get_session_attrs(
    value: *mut Client,
    sid: *const c_char,
    result: *mut *mut CAttributes,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            let (items, length) = boxed_slice(
                client(value)?
                    .get_session_attrs(input(sid)?)?
                    .into_iter()
                    .map(|(name, value)| CAttribute {
                        name: string(name),
                        value: string(value),
                    })
                    .collect(),
            );
            output(result, CAttributes { items, length })
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_ensure_session_ready(
    value: *mut Client,
    result: *mut *mut CSession,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null result output"));
            }
            *result = ptr::null_mut();
            output(result, session(client(value)?.ensure_session_ready()?))
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_update_session_attrs(
    value: *mut Client,
    sid: *const c_char,
    set: *const CAttribute,
    set_length: usize,
    remove: *const *const c_char,
    remove_length: usize,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if set_length > 128 || remove_length > 128 {
                return Err(Error::new(
                    ErrorCode::LimitExceeded,
                    "too many patch entries",
                ));
            }
            if (set_length != 0 && set.is_null()) || (remove_length != 0 && remove.is_null()) {
                return Err(Error::new(ErrorCode::InvalidArgument, "null patch entries"));
            }
            let entries = if set_length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(set, set_length)
            };
            let removals = if remove_length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(remove, remove_length)
            };
            let mut map = Attributes::new();
            for entry in entries {
                if map
                    .insert(
                        input(entry.name)?.to_owned(),
                        input(entry.value)?.to_owned(),
                    )
                    .is_some()
                {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "duplicate patch key",
                    ));
                }
            }
            let names: Vec<String> = removals
                .iter()
                .map(|p| input(*p).map(str::to_owned))
                .collect::<Result<_>>()?;
            client(value)?.update_session_attrs(input(sid)?, &map, &names)
        })
    }
}
macro_rules! close_call {
    ($function:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $function(
            value: *mut Client,
            sid: *const c_char,
            error: *mut *mut CError,
        ) -> u32 {
            unsafe { finish(error, || client(value)?.$method(input(sid)?)) }
        }
    };
}
close_call!(sessiond_schedule_close_session, schedule_close_session);
close_call!(sessiond_close_session, close_session);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_subscribe(value: *mut Client, error: *mut *mut CError) -> u32 {
    unsafe { finish(error, || client(value)?.subscribe()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_next_event(
    value: *mut Client,
    wait_ms: u64,
    result: *mut *mut CEvent,
    error: *mut *mut CError,
) -> u32 {
    unsafe {
        finish(error, || {
            if result.is_null() {
                return Err(Error::new(ErrorCode::InvalidArgument, "null event output"));
            }
            *result = ptr::null_mut();
            let Some(event) = client(value)?.next_event(Duration::from_millis(wait_ms))? else {
                return Ok(());
            };
            let (kind, sid, uid) = match event {
                Event::SessionNew { sid, uid } => (1, string(sid), uid),
                Event::SessionRemoved { sid, uid } => (2, string(sid), uid),
                Event::OwnerReplaced => (3, ptr::null_mut(), 0),
                Event::Overflow => (4, ptr::null_mut(), 0),
            };
            output(result, CEvent { kind, sid, uid })
        })
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_error_free(value: *mut CError) {
    if !value.is_null() {
        let value = unsafe { Box::from_raw(value) };
        unsafe {
            release_string(value.message);
            release_string(value.remote_name);
        }
    }
}
unsafe fn release_session(value: &CSession) {
    unsafe {
        release_string(value.sid);
        release_string(value.runtime_dir);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_session_free(value: *mut CSession) {
    if !value.is_null() {
        let value = unsafe { Box::from_raw(value) };
        unsafe {
            release_session(&value);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_sessions_free(value: *mut CSessions) {
    if !value.is_null() {
        let value = unsafe { Box::from_raw(value) };
        let items = unsafe { release_slice(value.items, value.length) };
        for item in items.iter() {
            unsafe {
                release_session(item);
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_attributes_free(value: *mut CAttributes) {
    if !value.is_null() {
        let value = unsafe { Box::from_raw(value) };
        let items = unsafe { release_slice(value.items, value.length) };
        for item in items.iter() {
            unsafe {
                release_string(item.name);
                release_string(item.value);
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sessiond_event_free(value: *mut CEvent) {
    if !value.is_null() {
        let value = unsafe { Box::from_raw(value) };
        unsafe {
            release_string(value.sid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unexpected_panics_abort_only_the_disposable_ffi_host() {
        use std::os::unix::process::ExitStatusExt;
        extern "C" fn boundary() {
            // SAFETY: optional error output; intentionally panic INSIDE the same
            // wrapper as real C exports, never in the parent test process.
            unsafe { finish(ptr::null_mut(), || panic!("intentional FFI boundary test")) };
        }
        if std::env::var_os("SESSIOND_TEST_FFI_PANIC_CHILD").is_some() {
            // SAFETY: suppress core files only in this disposable child.
            unsafe {
                libc::setrlimit(
                    libc::RLIMIT_CORE,
                    &libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    },
                );
            }
            boundary();
            unreachable!();
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ffi::tests::unexpected_panics_abort_only_the_disposable_ffi_host",
            ])
            .env("SESSIOND_TEST_FFI_PANIC_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGABRT));
    }
    #[test]
    fn invalid_inputs_return_owned_errors_and_null_results() {
        let mut error = ptr::null_mut();
        let mut result = ptr::null_mut();
        unsafe {
            assert_eq!(
                sessiond_get_session(
                    ptr::null_mut(),
                    c"0123456789abcdef0123456789abcdef".as_ptr(),
                    &mut result,
                    &mut error
                ),
                ErrorCode::InvalidArgument as u32
            );
            assert!(result.is_null());
            assert!(!error.is_null());
            sessiond_error_free(error);
            let mut start = 0;
            assert_eq!(
                sessiond_current_process_start_time(&mut start, &mut error),
                0
            );
            assert!(error.is_null());
            assert!(start > 0);
            sessiond_session_free(ptr::null_mut());
            sessiond_sessions_free(ptr::null_mut());
            sessiond_attributes_free(ptr::null_mut());
            sessiond_event_free(ptr::null_mut());
        }
    }
}
