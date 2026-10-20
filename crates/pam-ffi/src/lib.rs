//! Minimal hand-written Linux-PAM FFI shared by the Phase 1 PAM components.

use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::ptr;

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_OPEN_ERR: c_int = 1;
pub const PAM_SESSION_ERR: c_int = 14;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_CONV_ERR: c_int = 19;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

pub type ConversationFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
pub struct PamConversation {
    pub conv: Option<ConversationFn>,
    pub appdata_ptr: *mut c_void,
}

pub type CleanupFn = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConversation,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_open_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_close_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<CleanupFn>,
    ) -> c_int;
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
}

/// # Safety
/// `pamh` must be a live PAM handle supplied to a PAM module entry point.
pub unsafe fn get_user(pamh: *mut PamHandle) -> Result<String, c_int> {
    let mut user = ptr::null();
    // SAFETY: PAM owns the handle and returned string for the transaction.
    let status = unsafe { pam_get_user(pamh, &mut user, ptr::null()) };
    if status != PAM_SUCCESS || user.is_null() {
        return Err(if status == PAM_SUCCESS {
            PAM_USER_UNKNOWN
        } else {
            status
        });
    }
    // SAFETY: successful pam_get_user returns a transaction-owned C string;
    // copy it before returning to keep no borrowed PAM storage.
    Ok(unsafe { CStr::from_ptr(user) }
        .to_string_lossy()
        .into_owned())
}

/// # Safety
/// `pamh` must be live. Linux-PAM copies the supplied environment string.
pub unsafe fn put_env(pamh: *mut PamHandle, value: &CStr) -> Result<(), c_int> {
    // SAFETY: the handle and NUL-terminated value satisfy pam_putenv.
    let status = unsafe { pam_putenv(pamh, value.as_ptr()) };
    if status == PAM_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// # Safety
/// `pamh` must be live; `data` and `cleanup` must obey PAM's ownership rules.
pub unsafe fn set_data(
    pamh: *mut PamHandle,
    key: &CStr,
    data: *mut c_void,
    cleanup: CleanupFn,
) -> Result<(), c_int> {
    // SAFETY: the caller transfers the data pointer to PAM on success.
    let status = unsafe { pam_set_data(pamh, key.as_ptr(), data, Some(cleanup)) };
    if status == PAM_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// # Safety
/// `pamh` must be live. Returned data remains owned by PAM.
pub unsafe fn get_data(pamh: *mut PamHandle, key: &CStr) -> Result<*const c_void, c_int> {
    let mut data = ptr::null();
    // SAFETY: output storage and handle satisfy pam_get_data.
    let status = unsafe { pam_get_data(pamh, key.as_ptr(), &mut data) };
    if status == PAM_SUCCESS {
        Ok(data)
    } else {
        Err(status)
    }
}

unsafe extern "C" fn reject_conversation(
    _count: c_int,
    _messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    _data: *mut c_void,
) -> c_int {
    if !responses.is_null() {
        // SAFETY: PAM provided writable output storage.
        unsafe { *responses = ptr::null_mut() };
    }
    PAM_CONV_ERR
}

pub struct Transaction {
    handle: *mut PamHandle,
    // Linux-PAM may retain the conversation pointer until pam_end.
    _conversation: Box<PamConversation>,
    last_status: c_int,
    opened: bool,
}

impl Transaction {
    pub fn start(service: &str, user: &str) -> Result<Self, c_int> {
        let service = CString::new(service).map_err(|_| PAM_OPEN_ERR)?;
        let user = CString::new(user).map_err(|_| PAM_USER_UNKNOWN)?;
        let conversation = Box::new(PamConversation {
            conv: Some(reject_conversation),
            appdata_ptr: ptr::null_mut(),
        });
        let mut handle = ptr::null_mut();
        // SAFETY: strings remain valid for the call and the boxed conversation
        // remains stable until the matching pam_end in Drop.
        let status =
            unsafe { pam_start(service.as_ptr(), user.as_ptr(), &*conversation, &mut handle) };
        if status != PAM_SUCCESS {
            return Err(status);
        }
        Ok(Self {
            handle,
            _conversation: conversation,
            last_status: PAM_SUCCESS,
            opened: false,
        })
    }

    pub fn open_session(&mut self) -> Result<(), c_int> {
        // SAFETY: handle was returned by pam_start and remains live.
        let status = unsafe { pam_open_session(self.handle, 0) };
        self.last_status = status;
        if status == PAM_SUCCESS {
            self.opened = true;
            Ok(())
        } else {
            Err(status)
        }
    }

    pub fn close_session(&mut self) -> Result<(), c_int> {
        if !self.opened {
            return Ok(());
        }
        // SAFETY: the session was opened on this live handle.
        let status = unsafe { pam_close_session(self.handle, 0) };
        self.last_status = status;
        self.opened = false;
        if status == PAM_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.opened {
            // SAFETY: best-effort close on the live PAM handle.
            unsafe { pam_close_session(self.handle, 0) };
        }
        // SAFETY: each successful pam_start must have one pam_end.
        unsafe { pam_end(self.handle, self.last_status) };
    }
}
