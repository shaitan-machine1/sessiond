//! Worker-local application-side PAM ownership, using audited pam-sys 0.5.6.
//! The raw API declares pam_start's output as const; ownership is still mutable
//! PAM state per Linux-PAM's ABI. Never share this transaction between threads.
use pam_sys::{PamConversation, PamHandle, PamMessage, PamResponse, raw};
use std::ffi::CString;
use std::ptr;
extern "C" fn reject(
    _: i32,
    _: *mut *mut PamMessage,
    responses: *mut *mut PamResponse,
    _: *mut libc::c_void,
) -> i32 {
    if !responses.is_null() {
        // SAFETY: Linux-PAM provided writable response output storage.
        unsafe { *responses = ptr::null_mut() };
    }
    19 // PAM_CONV_ERR: the private stack must not prompt for credentials.
}
pub struct Transaction {
    handle: *mut PamHandle,
    _conversation: Box<PamConversation>,
    opened: bool,
    status: i32,
}
impl Transaction {
    pub fn start(service: &str, user: &str) -> Result<Self, i32> {
        let service = CString::new(service).map_err(|_| 1)?;
        let user = CString::new(user).map_err(|_| 10)?;
        let conversation = Box::new(PamConversation {
            conv: Some(reject),
            data_ptr: ptr::null_mut(),
        });
        let mut handle = ptr::null();
        // SAFETY: valid C strings, boxed conversation stays stable until pam_end.
        let status =
            unsafe { raw::pam_start(service.as_ptr(), user.as_ptr(), &*conversation, &mut handle) };
        if status != 0 {
            return Err(status);
        }
        Ok(Self {
            handle: handle.cast_mut(),
            _conversation: conversation,
            opened: false,
            status,
        })
    }
    pub fn open_session(&mut self) -> Result<(), i32> {
        // SAFETY: a successful pam_start owns this still-live transaction.
        self.status = unsafe { raw::pam_open_session(self.handle, 0) };
        self.opened = self.status == 0;
        if self.opened {
            Ok(())
        } else {
            Err(self.status)
        }
    }
    pub fn close_session(&mut self) -> Result<(), i32> {
        if !self.opened {
            return Ok(());
        }
        // SAFETY: paired close of this transaction's opened private session.
        self.status = unsafe { raw::pam_close_session(self.handle, 0) };
        self.opened = false;
        if self.status == 0 {
            Ok(())
        } else {
            Err(self.status)
        }
    }
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if self.opened {
            // SAFETY: best-effort close on the worker-owned live transaction.
            self.status = unsafe { raw::pam_close_session(self.handle, 0) };
        }
        // SAFETY: exactly one pam_end for a successful pam_start.
        unsafe { raw::pam_end(self.handle, self.status) };
    }
}
