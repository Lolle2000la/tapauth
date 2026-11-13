//! Safe wrappers around auto-generated Linux-PAM FFI bindings.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// reason: generated bindings; the `include!`d file is bindgen output, so its
// C naming, unused items and indexing are not ours to fix.
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

/// The `PAM_SERVICE` name (e.g. `"sudo"`, `"polkit-1"`, `"sddm"`), when it is
/// set and UTF-8.
///
/// # Safety
///
/// `pamh` must be the handle libpam passed to this thread's
/// `pam_sm_authenticate` and must outlive the call: the item read is libpam's
/// own NUL-terminated string, valid while the handle lives.
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

/// The username from the PAM context.
///
/// A null `PAM_USER` is `PAM_USER_UNKNOWN`, never a substitution: the module
/// authenticates the account libpam set for this stack, and a name taken from
/// another item would raise a phone prompt for an account the stack will not
/// authenticate (and would key the verdict cache on it).
///
/// # Safety
///
/// `pamh` must be the handle libpam passed to this thread's
/// `pam_sm_authenticate`, and the `PAM_USER` item behind it is libpam's, valid
/// while the handle lives.
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
/// without a PAM handle: an absent item is [`PAM_USER_UNKNOWN`], a present one
/// must be UTF-8, and `PAM_USER` is the only input — there is no second item to
/// fall back to.
fn user_from_item(item: Option<&CStr>) -> Result<String, c_int> {
    let item = item.ok_or(PAM_USER_UNKNOWN)?;
    item.to_str()
        .map(str::to_owned)
        .map_err(|_| PAM_USER_UNKNOWN)
}

/// The conversation function libpam holds for this handle.
///
/// # Safety
///
/// `pamh` must be the handle libpam passed to this thread's
/// `pam_sm_authenticate`. The `PAM_CONV` item it returns really is a
/// `struct pam_conv` that libpam owns, valid while the handle lives.
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

/// The pre-collected token read, injected through `transaction::HostIo` like every
/// other effect so a test can count it instead of inferring it from a missing
/// conversation.
pub(crate) type ReadAuthtok = unsafe fn(*mut PamHandle) -> (c_int, *const c_char);

/// Read `PAM_AUTHTOK` for the pre-collected handoff: `pam_get_authtok` on this
/// thread, no prompt, whatever token libpam produces. The code and the token are
/// returned as-is; treating a null token as "nothing was collected" is the
/// handoff's decision.
///
/// # Safety
///
/// `pamh` must be the live handle libpam passed to this thread's
/// `pam_sm_authenticate`, and the conversation behind it belongs to this thread.
pub(crate) unsafe fn read_authtok_for_handoff(pamh: *mut PamHandle) -> (c_int, *const c_char) {
    let mut authtok: *const c_char = std::ptr::null();
    let res = pam_get_authtok(pamh, PAM_AUTHTOK, &mut authtok, std::ptr::null());
    (res, authtok)
}

/// Send a message to the user through the conversation function.
///
/// # Safety
///
/// `pamh` must be the live handle libpam passed to this thread's
/// `pam_sm_authenticate`, so the conversation it carries is callable on this
/// thread. The callback mallocs the `pam_response` and nothing else frees it: this
/// function owns it and frees the response and its buffer.
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

/// A checked conversation: `new` proves the handle carries a usable one, and
/// `'a` keeps it borrowed for every `info`/`error`.
pub struct PamConversation<'a> {
    pamh: *mut PamHandle,
    _phantom: std::marker::PhantomData<&'a mut PamHandle>,
}

impl<'a> PamConversation<'a> {
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `pamh` is a valid, non-null PAM handle
    /// - The PAM handle remains valid for the lifetime `'a`
    /// - The PAM handle is not used concurrently from other threads
    pub unsafe fn new(pamh: *mut PamHandle) -> Result<Self, c_int> {
        get_conv(pamh)?;

        Ok(Self {
            pamh,
            _phantom: std::marker::PhantomData,
        })
    }

    /// A handle-less conversation for unit tests.
    ///
    /// `send_message` starts at `get_conv`, which rejects a null handle with
    /// `PAM_SYSTEM_ERR`, so `info`/`error` fail harmlessly and `try_info`/`try_error`
    /// only log; such a test exercises the return-code logic, not the conversation.
    #[cfg(test)]
    pub unsafe fn dummy() -> Self {
        Self {
            pamh: std::ptr::null_mut(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Send an informational message to the user.
    pub fn info(&self, message: &str) -> Result<(), c_int> {
        // SAFETY: `pamh` is a handle `new` validated, or null, which `get_conv`
        // rejects before it is used.
        unsafe { send_message(self.pamh, PAM_TEXT_INFO, message) }
    }

    /// Send an error message to the user.
    pub fn error(&self, message: &str) -> Result<(), c_int> {
        // SAFETY: as `info`.
        unsafe { send_message(self.pamh, PAM_ERROR_MSG, message) }
    }

    /// [`info`](Self::info), logging the failure instead of returning it.
    pub fn try_info(&self, message: &str) {
        if let Err(e) = self.info(message) {
            tracing::warn!("Failed to send info message to user: PAM error code {}", e);
        }
    }

    /// [`error`](Self::error), logging the failure instead of returning it.
    pub fn try_error(&self, message: &str) {
        if let Err(e) = self.error(message) {
            tracing::warn!("Failed to send error message to user: PAM error code {}", e);
        }
    }
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
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
    /// Catches a fallback to another item (the retired remote-user read): the name becomes the
    /// daemon request's `username`, the verdict cache's key and the locale lookup's NSS name, so
    /// it would prompt the phone for an account the stack will not authenticate.
    #[test]
    fn null_user_does_not_fall_back_to_ruser() {
        assert_eq!(user_from_item(None), Err(PAM_USER_UNKNOWN));

        let user = CString::new("alice").unwrap();
        assert_eq!(
            user_from_item(Some(user.as_c_str())),
            Ok("alice".to_owned())
        );

        let raw: &CStr = c"\xff";
        assert_eq!(user_from_item(Some(raw)), Err(PAM_USER_UNKNOWN));
    }
}
