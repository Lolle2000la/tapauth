//! Raw PAM FFI bindings
//!
//! This module provides minimal, safe bindings to the PAM (Pluggable Authentication Modules) C API.
//! We implement our own bindings instead of using pam-bindings to avoid known issues with
//! that crate and pamtester.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// PAM return codes
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_PERM_DENIED: c_int = 6;

// PAM item types
pub const PAM_USER: c_int = 2;
pub const PAM_RUSER: c_int = 8;

/// Opaque PAM handle structure
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

/// PAM message structure
#[repr(C)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// PAM response structure
#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

/// PAM conversation function pointer
pub type PamConvFunc = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

/// PAM conversation structure
#[repr(C)]
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
    pub fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
}

/// Safe wrapper to get username from PAM
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
