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
    pam_get_authtok, PAM_AUTHINFO_UNAVAIL, PAM_AUTHTOK, PAM_AUTH_ERR, PAM_BUF_ERR, PAM_CONV_ERR,
    PAM_ERROR_MSG, PAM_PERM_DENIED, PAM_SERVICE, PAM_SUCCESS, PAM_SYSTEM_ERR, PAM_TEXT_INFO,
    PAM_USER, PAM_USER_UNKNOWN,
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
/// A null `PAM_USER` is `PAM_USER_UNKNOWN`, never a substitution: the module
/// authenticates the account libpam set for this stack, and a name taken from
/// another item would raise a phone prompt for an account the stack will not
/// authenticate (and would key the verdict cache on it).
pub unsafe fn get_user(pamh: *mut PamHandle) -> Result<String, c_int> {
    if pamh.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    let mut item: *const c_void = std::ptr::null();
    let ret = ffi::pam_get_item(pamh, PAM_USER, &mut item);

    if ret != PAM_SUCCESS {
        return Err(ret);
    }

    // SAFETY: `pam_get_item` succeeded, so a non-null `item` is the C string
    // libpam holds for `PAM_USER`; a null one means the item is unset.
    let item = if item.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(item as *const c_char) })
    };
    user_from_item(item)
}

/// The value interpretation of [`get_user`], split out so it is testable
/// without a PAM handle: an absent item is [`PAM_USER_UNKNOWN`], and a present
/// one must be UTF-8.
///
/// There is deliberately no second item to fall back to: the only input is
/// `PAM_USER`.
fn user_from_item(item: Option<&CStr>) -> Result<String, c_int> {
    let item = item.ok_or(PAM_USER_UNKNOWN)?;
    item.to_str()
        .map(str::to_owned)
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

/// The pre-collected token read, as a value the handoff can be given.
///
/// The read is the one effect `mechanism::handoff` performs on the PAM handle,
/// so it is passed in through `transaction::HostIo` like every other effect: a
/// test can then count it instead of inferring it from the absence of a
/// conversation.
pub(crate) type ReadAuthtok = unsafe fn(*mut PamHandle) -> (c_int, *const c_char);

/// Read `PAM_AUTHTOK` for the pre-collected handoff.
///
/// Exactly the call the handoff used to make inline: `pam_get_authtok` on this
/// thread, with no prompt, and whatever token libpam produces. The code and the
/// token are returned as-is; deciding that a null token means "nothing was
/// collected" belongs to the handoff.
///
/// # Safety
///
/// `pamh` must be the live handle libpam passed to this thread's
/// `pam_authenticate`, and the conversation behind it belongs to this thread.
pub(crate) unsafe fn read_authtok_for_handoff(pamh: *mut PamHandle) -> (c_int, *const c_char) {
    let mut authtok: *const c_char = std::ptr::null();
    let res = pam_get_authtok(pamh, PAM_AUTHTOK, &mut authtok, std::ptr::null());
    (res, authtok)
}

/// Send a message to the user via the PAM conversation function.
///
/// Allocates a `pam_message` on the stack and calls the conversation
/// callback.  The `pam_response` is allocated by the conversation
/// function (`malloc`) and freed here with `libc::free`.
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

    /// Build a conversation wrapper without a PAM handle, for unit tests.
    ///
    /// `send_message`/`prompt_user` call `get_conv`, which already rejects a
    /// null handle with `PAM_SYSTEM_ERR`, so `info`/`try_info`/`error` are
    /// clean no-ops here. Only the return-code logic that takes a
    /// `&PamConversation` can be exercised this way.
    #[cfg(test)]
    pub unsafe fn dummy() -> Self {
        Self {
            pamh: std::ptr::null_mut(),
            _phantom: std::marker::PhantomData,
        }
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// A null `PAM_USER` is `PAM_USER_UNKNOWN`, and nothing else is consulted.
    ///
    /// The defect this catches: the retired fallback that read the remote-user
    /// item and returned *that* as the username when `PAM_USER` was unset. That
    /// string became the daemon request's `username`, the verdict cache's key and
    /// the locale lookup's NSS name, so a stack with `PAM_USER` unset and the
    /// remote-user item pointed at another account raised a phone prompt for an
    /// account the stack would not authenticate. `user_from_item` has no second
    /// item to consult, so the substitution cannot be reintroduced here without
    /// changing this signature.
    #[test]
    fn null_user_does_not_fall_back_to_ruser() {
        assert_eq!(user_from_item(None), Err(PAM_USER_UNKNOWN));

        // The other direction, which the removal must not break: a set
        // `PAM_USER` is returned as-is, whatever else the handle carries.
        let user = CString::new("alice").unwrap();
        assert_eq!(
            user_from_item(Some(user.as_c_str())),
            Ok("alice".to_owned())
        );

        // Non-UTF-8 stays a lookup failure rather than a lossy name.
        let raw: &CStr = c"\xff";
        assert_eq!(user_from_item(Some(raw)), Err(PAM_USER_UNKNOWN));
    }
}
