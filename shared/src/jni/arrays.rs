//! JNI object array construction helpers.

use jni::objects::{JClass, JObject};
use jni::strings::JNIString;
use jni::sys::jobjectArray;
use jni::{EnvUnowned as JNIEnv, Outcome};

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
    match env
        .with_env(|env| env.find_class(jni::jni_str!("[B")))
        .into_outcome()
    {
        Outcome::Ok(cls) => Some(cls),
        Outcome::Err(err) => {
            throw_illegal_state(env, format!("failed to find byte array class: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_state(env, "failed to find byte array class: panic".to_string());
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
    let class_sig_jni = JNIString::new(class_sig);
    let class = match env
        .with_env(|env| env.find_class(&class_sig_jni))
        .into_outcome()
    {
        Outcome::Ok(cls) => cls,
        Outcome::Err(err) => {
            throw_illegal_state(env, format!("failed to find class {class_sig}: {err}"));
            return None;
        }
        Outcome::Panic(_) => {
            throw_illegal_state(env, format!("failed to find class {class_sig}: panic"));
            return None;
        }
    };

    match env
        .with_env(|env| env.new_object_array(len, class, JObject::null()))
        .into_outcome()
    {
        Outcome::Ok(array) => Some(array.into_raw()),
        Outcome::Err(err) => {
            throw_out_of_memory(env, format!("failed to create object array: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_out_of_memory(env, "failed to create object array: panic".to_string());
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
    let index = match usize::try_from(index) {
        Ok(index) => index,
        Err(_) => {
            throw_illegal_state(env, format!("invalid array index: {index}"));
            return None;
        }
    };
    match env
        .with_env(|env| {
            let array_obj = unsafe { JObjectArray::<JObject>::from_raw(env, array) };
            array_obj.set_element(env, index, value)
        })
        .into_outcome()
    {
        Outcome::Ok(()) => Some(()),
        Outcome::Err(err) => {
            throw_illegal_state(env, format!("failed to set array element: {err}"));
            None
        }
        Outcome::Panic(_) => {
            throw_illegal_state(env, "failed to set array element: panic".to_string());
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
    let java_string = string_to_jstring(env, string)?;

    let result_array = new_object_array(env, 2, "java/lang/Object")?;
    set_object_array_element(env, result_array, 0, &byte_array)?;
    set_object_array_element(env, result_array, 1, &java_string)?;

    Some(result_array)
}
