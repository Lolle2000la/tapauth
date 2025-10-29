//! Raw PAM FFI bindings
//!
//! This module provides minimal, safe bindings to the PAM (Pluggable Authentication Modules) C API.
//! We implement our own bindings instead of using pam-bindings to avoid known issues with
//! that crate and pamtester.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// PAM return codes
pub const PAM_SUCCESS: c_int = 0;
#[allow(dead_code)]
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_IGNORE: c_int = 25;

// PAM item types
pub const PAM_USER: c_int = 2;
pub const PAM_RUSER: c_int = 8;
pub const PAM_CONV: c_int = 5;

// PAM message styles
#[allow(dead_code)]
pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
#[allow(dead_code)]
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

/// Opaque PAM handle structure
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

/// PAM message structure
#[repr(C)]
#[allow(dead_code)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// PAM response structure
#[repr(C)]
#[allow(dead_code)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

/// PAM conversation function pointer
#[allow(dead_code)]
pub type PamConvFunc = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

/// PAM conversation structure
#[repr(C)]
#[allow(dead_code)]
pub struct PamConv {
    pub conv: Option<PamConvFunc>,
    pub appdata_ptr: *mut c_void,
}

extern "C" {
    /// Get a PAM item
    pub fn pam_get_item(
        pamh: *const PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    /// Set a PAM item
    #[allow(dead_code)]
    pub fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
}

/// Safe wrapper to get username from PAM
#[allow(dead_code)]
pub unsafe fn get_user(pamh: *mut PamHandle) -> Result<String, c_int> {
    let mut item: *const c_void = std::ptr::null();
    let ret = pam_get_item(pamh, PAM_USER, &mut item);

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    if item.is_null() {
        // Try RUSER (remote user) as fallback
        let ret = pam_get_item(pamh, PAM_RUSER, &mut item);
        if ret != PAM_SUCCESS {
            return Err(ret);
        }
        if item.is_null() {
            return Err(PAM_USER_UNKNOWN);
        }
    }

    let user_cstr = CStr::from_ptr(item as *const c_char);
    Ok(user_cstr
        .to_str()
        .map_err(|_| PAM_USER_UNKNOWN)?
        .to_string())
}

/// Safe wrapper to set username in PAM
#[allow(dead_code)]
pub unsafe fn set_user(pamh: *mut PamHandle, username: &str) -> Result<(), c_int> {
    let username_cstring = CString::new(username).map_err(|_| PAM_USER_UNKNOWN)?;
    let ret = pam_set_item(pamh, PAM_USER, username_cstring.as_ptr() as *const c_void);

    if ret == PAM_SUCCESS {
        // Leak the CString so PAM can keep using it
        std::mem::forget(username_cstring);
        Ok(())
    } else {
        Err(ret)
    }
}

/// Get the PAM conversation function
pub unsafe fn get_conv(pamh: *mut PamHandle) -> Result<*const PamConv, c_int> {
    let mut item: *const c_void = std::ptr::null();
    let ret = pam_get_item(pamh, PAM_CONV, &mut item);

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    if item.is_null() {
        return Err(PAM_CONV_ERR);
    }

    Ok(item as *const PamConv)
}

/// Send a message to the user via PAM conversation
pub unsafe fn send_message(pamh: *mut PamHandle, msg_style: c_int, msg: &str) -> Result<(), c_int> {
    let conv_ptr = get_conv(pamh)?;
    let conv = &*conv_ptr;

    let conv_fn = match conv.conv {
        Some(f) => f,
        None => return Err(PAM_CONV_ERR),
    };

    // Create the message
    let msg_cstring = CString::new(msg).map_err(|_| PAM_BUF_ERR)?;
    let pam_msg = PamMessage {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };

    // Create message array (pointer to pointer as per Linux-PAM convention)
    let msg_ptr = &pam_msg as *const PamMessage;
    let msg_array = &msg_ptr as *const *const PamMessage;

    // Call conversation function
    let mut resp: *mut PamResponse = std::ptr::null_mut();
    let ret = conv_fn(
        1,
        msg_array as *mut *const PamMessage,
        &mut resp as *mut *mut PamResponse,
        conv.appdata_ptr,
    );

    // Free response if allocated - PAM library expects us to free this
    if !resp.is_null() {
        let response = Box::from_raw(resp);
        if !response.resp.is_null() {
            // Free the string - it was allocated by the conversation function
            drop(CString::from_raw(response.resp));
        }
    }

    if ret == PAM_SUCCESS {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Prompt the user and get a response via PAM conversation
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

    // Create the message
    let msg_cstring = CString::new(msg).map_err(|_| PAM_BUF_ERR)?;
    let pam_msg = PamMessage {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };

    // Create message array (pointer to pointer as per Linux-PAM convention)
    let msg_ptr = &pam_msg as *const PamMessage;
    let msg_array = &msg_ptr as *const *const PamMessage;

    // Call conversation function
    let mut resp: *mut PamResponse = std::ptr::null_mut();
    let ret = conv_fn(
        1,
        msg_array as *mut *const PamMessage,
        &mut resp as *mut *mut PamResponse,
        conv.appdata_ptr,
    );

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    // Get response if provided
    let result = if !resp.is_null() {
        let response = Box::from_raw(resp);
        if !response.resp.is_null() {
            let resp_cstr = CStr::from_ptr(response.resp);
            let response_str = resp_cstr.to_str().ok().map(|s| s.to_string());
            // Free the string that was allocated by the conversation function
            drop(CString::from_raw(response.resp));
            response_str
        } else {
            None
        }
    } else {
        None
    };

    Ok(result)
}

/// Safe wrapper for PAM conversation operations
///
/// This provides a safe, Rust-idiomatic interface to PAM conversation functions.
/// It ensures proper lifetime management and eliminates the need for unsafe blocks
/// when sending messages to users.
///
/// # Example
///
/// ```no_run
/// # use client_pam::pam_sys::{PamHandle, PamConversation};
/// # unsafe fn example(pamh: *mut PamHandle) -> Result<(), i32> {
/// // Create a safe conversation wrapper
/// let pam_conv = PamConversation::new(pamh)?;
///
/// // Send messages safely without unsafe blocks
/// pam_conv.try_info("Processing your request...");
/// pam_conv.try_error("An error occurred");
///
/// // Or handle errors explicitly
/// if let Err(e) = pam_conv.info("Important message") {
///     eprintln!("Failed to send message: {}", e);
/// }
/// # Ok(())
/// # }
/// ```
pub struct PamConversation<'a> {
    pamh: *mut PamHandle,
    _phantom: std::marker::PhantomData<&'a mut PamHandle>,
}

impl<'a> PamConversation<'a> {
    /// Create a new PamConversation wrapper
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `pamh` is a valid PAM handle
    /// - The PAM handle remains valid for the lifetime 'a
    /// - The PAM handle is not used concurrently from other threads
    pub unsafe fn new(pamh: *mut PamHandle) -> Result<Self, c_int> {
        // Verify that a conversation function is available
        let _ = get_conv(pamh)?;

        Ok(Self {
            pamh,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Send an informational message to the user
    pub fn info(&self, message: &str) -> Result<(), c_int> {
        unsafe { send_message(self.pamh, PAM_TEXT_INFO, message) }
    }

    /// Send an error message to the user
    pub fn error(&self, message: &str) -> Result<(), c_int> {
        unsafe { send_message(self.pamh, PAM_ERROR_MSG, message) }
    }

    /// Prompt the user for input without echoing (like password)
    #[allow(dead_code)]
    pub fn prompt_hidden(&self, prompt: &str) -> Result<Option<String>, c_int> {
        unsafe { prompt_user(self.pamh, PAM_PROMPT_ECHO_OFF, prompt) }
    }

    /// Prompt the user for input with echoing (like username)
    #[allow(dead_code)]
    pub fn prompt_visible(&self, prompt: &str) -> Result<Option<String>, c_int> {
        unsafe { prompt_user(self.pamh, PAM_PROMPT_ECHO_ON, prompt) }
    }

    /// Try to send an informational message, logging any errors
    ///
    /// This is a convenience method that won't fail if the message can't be sent.
    /// Useful for non-critical user feedback.
    pub fn try_info(&self, message: &str) {
        if let Err(e) = self.info(message) {
            tracing::warn!("Failed to send info message to user: PAM error code {}", e);
        }
    }

    /// Try to send an error message, logging any errors
    ///
    /// This is a convenience method that won't fail if the message can't be sent.
    /// Useful for non-critical user feedback.
    pub fn try_error(&self, message: &str) {
        if let Err(e) = self.error(message) {
            tracing::warn!("Failed to send error message to user: PAM error code {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify PAM constants are correct
        assert_eq!(PAM_SUCCESS, 0);
        assert_eq!(PAM_AUTH_ERR, 7);
        assert_eq!(PAM_USER_UNKNOWN, 10);
    }
}
