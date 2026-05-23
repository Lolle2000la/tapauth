//! JNI object array construction helpers.

use jni::objects::{JClass, JObject};
use jni::sys::jobjectArray;
use jni::JNIEnv;

use super::conversions::{string_to_jstring, vec_to_jbytearray};
use super::exceptions::{throw_illegal_state, throw_out_of_memory};

/// Get the Java byte array class `[B`.
///
/// ## Returns
///
/// `Some(JClass)` on success, `None` if class lookup fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` and returns `None` if the class cannot be found.
pub fn byte_array_class<'local>(env: &mut JNIEnv<'local>) -> Option<JClass<'local>> {
    match env.find_class("[B") {
        Ok(cls) => Some(cls),
        Err(err) => {
            throw_illegal_state(env, format!("failed to find byte array class: {err}"));
            None
        }
    }
}

/// Create a new Java `Object[]` array.
///
/// ## Arguments
///
/// * `len` - Array length
/// * `class_sig` - JNI class signature (e.g., `"[B"` for `byte[]`, `"java/lang/Object"`)
///
/// ## Returns
///
/// `Some(jobjectArray)` on success, `None` if allocation fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` if class lookup fails.
/// Throws `OutOfMemoryError` if array allocation fails.
pub fn new_object_array(env: &mut JNIEnv, len: i32, class_sig: &str) -> Option<jobjectArray> {
    let class = match env.find_class(class_sig) {
        Ok(cls) => cls,
        Err(err) => {
            throw_illegal_state(env, format!("failed to find class {class_sig}: {err}"));
            return None;
        }
    };

    match env.new_object_array(len, class, JObject::null()) {
        Ok(array) => Some(array.into_raw()),
        Err(err) => {
            throw_out_of_memory(env, format!("failed to create object array: {err}"));
            None
        }
    }
}

/// Set an element in a Java `Object[]` array.
///
/// ## Returns
///
/// `Some(())` on success, `None` if setting fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` and returns `None` if the element cannot be set.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn set_object_array_element<'local, O>(
    env: &mut JNIEnv<'local>,
    array: jobjectArray,
    index: i32,
    value: &O,
) -> Option<()>
where
    O: AsRef<JObject<'local>>,
{
    use jni::objects::JObjectArray;
    let array_obj = unsafe { JObjectArray::from_raw(array) };
    match env.set_object_array_element(&array_obj, index, value) {
        Ok(()) => Some(()),
        Err(err) => {
            throw_illegal_state(env, format!("failed to set array element: {err}"));
            None
        }
    }
}

/// Create a two-element `Object[]` containing `[byte[], byte[]]`.
///
/// Used for returning keypair tuples.
///
/// ## Returns
///
/// `Some(jobjectArray)` on success, `None` if any allocation fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` or `OutOfMemoryError` on failure.
pub fn make_keypair_array(
    env: &mut JNIEnv,
    private_key: &[u8],
    public_key: &[u8],
) -> Option<jobjectArray> {
    let private_array = vec_to_jbytearray(env, private_key)?;
    let public_array = vec_to_jbytearray(env, public_key)?;

    let result_array = new_object_array(env, 2, "[B")?;
    set_object_array_element(env, result_array, 0, &private_array)?;
    set_object_array_element(env, result_array, 1, &public_array)?;

    Some(result_array)
}

/// Create a two-element `Object[]` containing `[byte[], String]`.
///
/// Used for returning (bytes, string) tuples from parsing functions.
///
/// ## Returns
///
/// `Some(jobjectArray)` on success, `None` if any allocation fails.
///
/// ## Errors
///
/// Throws `IllegalStateException` or `OutOfMemoryError` on failure.
pub fn make_bytes_string_array(
    env: &mut JNIEnv,
    bytes: &[u8],
    string: &str,
) -> Option<jobjectArray> {
    let byte_array = vec_to_jbytearray(env, bytes)?;
    let java_string_raw = string_to_jstring(env, string)?;
    let java_string = unsafe { JObject::from_raw(java_string_raw) };

    let result_array = new_object_array(env, 2, "java/lang/Object")?;
    set_object_array_element(env, result_array, 0, &byte_array)?;
    set_object_array_element(env, result_array, 1, &java_string)?;

    Some(result_array)
}
