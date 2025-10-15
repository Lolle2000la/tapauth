use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::crypto;

/// JNI wrapper for generating the Short Authentication String (SAS).
#[no_mangle]
pub extern "system" fn Java_com_tapauth_JniBridge_getSas(
    mut env: JNIEnv,
    _class: JClass,
    client_pub_key_hex: JString,
    server_pub_key_hex: JString,
) -> jstring {
    let client_pk_hex: String = env.get_string(&client_pub_key_hex).unwrap().into();
    let server_pk_hex: String = env.get_string(&server_pub_key_hex).unwrap().into();

    let client_pk = hex::decode(client_pk_hex).unwrap();
    let server_pk = hex::decode(server_pk_hex).unwrap();

    let sas = crypto::generate_sas(&client_pk, &server_pk).unwrap();

    let output = env.new_string(sas).expect("Couldn't create java string!");
    output.into_raw()
}
