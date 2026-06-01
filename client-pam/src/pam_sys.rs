//! Safe wrappers around auto-generated Linux-PAM FFI bindings.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::indexing_slicing
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use ffi::{
    PAM_BUF_ERR, PAM_CONV_ERR, PAM_ERROR_MSG, PAM_IGNORE, PAM_PERM_DENIED, PAM_SERVICE,
    PAM_SUCCESS, PAM_SYSTEM_ERR, PAM_TEXT_INFO, PAM_USER, PAM_USER_UNKNOWN,
};

pub type PamHandle = ffi::pam_handle_t;

/// Retrieve the PAM service name (e.g. `"sudo"`, `"polkit-1"`, `"sddm"`)
/// from the active authentication context.
pub unsafe fn get_service_name(pamh: *mut PamHandle) -> Option<String> {
    if pamh.is_null() {
        return None;
    }
    let mut item: *const c_void = std::ptr::null();
    let ret = ffi::pam_get_item(pamh, PAM_SERVICE, &mut item);

    if ret == PAM_SUCCESS && !item.is_null() {
        CStr::from_ptr(item as *const c_char)
            .to_str()
            .ok()
            .map(|s| s.to_owned())
    } else {
        None
    }
}

/// Retrieve the username from the PAM context.
///
/// Falls back to `PAM_RUSER` (remote user) when `PAM_USER` is null.
pub unsafe fn get_user(pamh: *mut PamHandle) -> Result<String, c_int> {
    if pamh.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    let mut item: *const c_void = std::ptr::null();
    let mut ret = ffi::pam_get_item(pamh, PAM_USER, &mut item);

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    if item.is_null() {
        ret = ffi::pam_get_item(pamh, ffi::PAM_RUSER, &mut item);
        if ret != PAM_SUCCESS {
            return Err(ret);
        }
        if item.is_null() {
            return Err(PAM_USER_UNKNOWN);
        }
    }

    let user_cstr = CStr::from_ptr(item as *const c_char);
    user_cstr
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| PAM_USER_UNKNOWN)
}

/// Set the username in the PAM context.
///
/// `pam_set_item` duplicates string items internally, so the caller
/// does not need to keep the passed pointer alive after this call.
#[allow(dead_code)]
pub unsafe fn set_user(pamh: *mut PamHandle, username: &str) -> Result<(), c_int> {
    if pamh.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    let username_cstring = CString::new(username).map_err(|_| PAM_USER_UNKNOWN)?;
    let ret = ffi::pam_set_item(pamh, PAM_USER, username_cstring.as_ptr() as *const c_void);

    if ret == PAM_SUCCESS {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Retrieve the PAM conversation function pointer.
pub unsafe fn get_conv(pamh: *mut PamHandle) -> Result<*const ffi::pam_conv, c_int> {
    if pamh.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    let mut item: *const c_void = std::ptr::null();
    let ret = ffi::pam_get_item(pamh, ffi::PAM_CONV, &mut item);

    if ret != PAM_SUCCESS {
        return Err(ret);
    }
    if item.is_null() {
        return Err(PAM_CONV_ERR);
    }
    Ok(item as *const ffi::pam_conv)
}

/// Send a message to the user via the PAM conversation function.
///
/// Allocates a `pam_message` / `pam_response` pair on the stack and
/// calls the conversation callback.  Any response memory allocated by
/// `libpam` is freed with `libc::free`.
pub unsafe fn send_message(pamh: *mut PamHandle, msg_style: c_int, msg: &str) -> Result<(), c_int> {
    let conv_ptr = get_conv(pamh)?;
    let conv = &*conv_ptr;

    let conv_fn = match conv.conv {
        Some(f) => f,
        None => return Err(PAM_CONV_ERR),
    };

    let msg_cstring = CString::new(msg).map_err(|_| PAM_BUF_ERR)?;

    let pam_msg = ffi::pam_message {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };

    let msg_ptr = &pam_msg as *const ffi::pam_message;
    let msg_array = &msg_ptr as *const *const ffi::pam_message;
    let mut resp: *mut ffi::pam_response = std::ptr::null_mut();

    let ret = conv_fn(
        1,
        msg_array as *mut *const ffi::pam_message,
        &mut resp as *mut *mut ffi::pam_response,
        conv.appdata_ptr,
    );

    if !resp.is_null() {
        if !(*resp).resp.is_null() {
            libc::free((*resp).resp as *mut c_void);
        }
        libc::free(resp as *mut c_void);
    }

    if ret == PAM_SUCCESS {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Prompt the user for input via the PAM conversation function.
///
/// Returns the response string if the user provided one, or `None` if
/// the response was empty.
#[allow(dead_code)]
pub unsafe fn prompt_user(
    pamh: *mut PamHandle,
    msg_style: c_int,
    msg: &str,
) -> Result<Option<String>, c_int> {
    let conv_ptr = get_conv(pamh)?;
    let conv = &*conv_ptr;

    let conv_fn = match conv.conv {
        Some(f) => f,
        None => return Err(PAM_CONV_ERR),
    };

    let msg_cstring = CString::new(msg).map_err(|_| PAM_BUF_ERR)?;

    let pam_msg = ffi::pam_message {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };

    let msg_ptr = &pam_msg as *const ffi::pam_message;
    let msg_array = &msg_ptr as *const *const ffi::pam_message;
    let mut resp: *mut ffi::pam_response = std::ptr::null_mut();

    let ret = conv_fn(
        1,
        msg_array as *mut *const ffi::pam_message,
        &mut resp as *mut *mut ffi::pam_response,
        conv.appdata_ptr,
    );

    if ret != PAM_SUCCESS {
        if !resp.is_null() {
            if !(*resp).resp.is_null() {
                libc::free((*resp).resp as *mut c_void);
            }
            libc::free(resp as *mut c_void);
        }
        return Err(ret);
    }

    let result = if !resp.is_null() {
        unsafe {
            let response_ref: &mut ffi::pam_response = &mut *resp;
            let out = if !response_ref.resp.is_null() {
                let resp_cstr = CStr::from_ptr(response_ref.resp);
                let s = resp_cstr.to_str().ok().map(|s| s.to_string());
                libc::free(response_ref.resp as *mut c_void);
                response_ref.resp = std::ptr::null_mut();
                s
            } else {
                None
            };
            libc::free(resp as *mut c_void);
            out
        }
    } else {
        None
    };

    Ok(result)
}

/// Safe wrapper for PAM conversation operations.
///
/// Provides a Rust-idiomatic interface to PAM conversation functions
/// with proper lifetime management, eliminating the need for `unsafe`
/// blocks when sending messages to users.
///
/// # Example
///
/// ```no_run
/// # use client_pam::pam_sys::{PamHandle, PamConversation};
/// # unsafe fn example(pamh: *mut PamHandle) -> Result<(), i32> {
/// let pam_conv = PamConversation::new(pamh)?;
/// pam_conv.try_info("Processing your request...");
/// pam_conv.try_error("An error occurred");
/// # Ok(())
/// # }
/// ```
pub struct PamConversation<'a> {
    pamh: *mut PamHandle,
    _phantom: std::marker::PhantomData<&'a mut PamHandle>,
}

impl<'a> PamConversation<'a> {
    /// Create a new `PamConversation` wrapper.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `pamh` is a valid, non-null PAM handle
    /// - The PAM handle remains valid for the lifetime `'a`
    /// - The PAM handle is not used concurrently from other threads
    pub unsafe fn new(pamh: *mut PamHandle) -> Result<Self, c_int> {
        let _ = get_conv(pamh)?;

        Ok(Self {
            pamh,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Send an informational message to the user.
    pub fn info(&self, message: &str) -> Result<(), c_int> {
        unsafe { send_message(self.pamh, PAM_TEXT_INFO, message) }
    }

    /// Send an error message to the user.
    #[allow(dead_code)]
    pub fn error(&self, message: &str) -> Result<(), c_int> {
        unsafe { send_message(self.pamh, PAM_ERROR_MSG, message) }
    }

    /// Prompt the user for hidden input (e.g. password).
    #[allow(dead_code)]
    pub fn prompt_hidden(&self, prompt: &str) -> Result<Option<String>, c_int> {
        unsafe { prompt_user(self.pamh, ffi::PAM_PROMPT_ECHO_OFF, prompt) }
    }

    /// Prompt the user for visible input (e.g. username).
    #[allow(dead_code)]
    pub fn prompt_visible(&self, prompt: &str) -> Result<Option<String>, c_int> {
        unsafe { prompt_user(self.pamh, ffi::PAM_PROMPT_ECHO_ON, prompt) }
    }

    /// Try to send an informational message, logging any errors.
    ///
    /// Convenience method that never fails — useful for non-critical
    /// user feedback.
    pub fn try_info(&self, message: &str) {
        if let Err(e) = self.info(message) {
            tracing::warn!("Failed to send info message to user: PAM error code {}", e);
        }
    }

    /// Try to send an error message, logging any errors.
    ///
    /// Convenience method that never fails — useful for non-critical
    /// user feedback.
    #[allow(dead_code)]
    pub fn try_error(&self, message: &str) {
        if let Err(e) = self.error(message) {
            tracing::warn!("Failed to send error message to user: PAM error code {}", e);
        }
    }
}
