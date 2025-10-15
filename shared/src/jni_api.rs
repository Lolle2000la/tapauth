use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::crypto;

/// JNI wrapper for generating the Short Authentication String (SAS).
#[no_mangle]
pub extern "system" fn Java_com_tapauth_JniBridge_getSas(
    mut env: JNIEnv,
    _class: JClass,
    psk_hex: JString,
) -> jstring {
    let psk_hex: String = match env.get_string(&psk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 input: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk = match hex::decode(psk_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let sas = match crypto::generate_sas(&psk) {
        Ok(value) => value,
        Err(err) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", err.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(sas) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}
