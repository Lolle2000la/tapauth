use std::io::Result;
use std::process::Command;

/// Proto3 `optional` (explicit field presence) was experimental before protoc
/// 3.15 and requires this flag. Ubuntu 22.04 (jammy) still ships protoc 3.12.4,
/// where compiling `proto/ipc.proto` fails without it. The flag is deprecated
/// from 3.15 onwards (it is implied and eventually rejected), so it must only
/// be passed to older protoc versions.
const PROTO3_OPTIONAL_FLAG: &str = "--experimental_allow_proto3_optional";

/// Returns `true` when the active `protoc` predates proto3 `optional` support
/// (i.e. is older than 3.15) and therefore needs the experimental flag.
fn protoc_needs_proto3_optional_flag() -> bool {
    println!("cargo:rerun-if-env-changed=PROTOC");

    let protoc = std::env::var("PROTOC").unwrap_or_else(|_| "protoc".to_string());

    let output = match Command::new(&protoc).arg("--version").output() {
        Ok(output) => output,
        // Let prost-build report the real "protoc not found" error.
        Err(_) => return false,
    };

    // `protoc --version` prints e.g. "libprotoc 3.12.4" (older releases may use
    // stderr). Fall back to the standard output/error streams.
    let mut version_output = String::from_utf8_lossy(&output.stdout).into_owned();
    version_output.push_str(&String::from_utf8_lossy(&output.stderr));

    let Some(version) = version_output.split_whitespace().last() else {
        return false;
    };

    let mut parts = version.split('.');
    let Some(major) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
        return false;
    };
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);

    (major, minor) < (3, 15)
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../proto/auth_protocol.proto");
    println!("cargo:rerun-if-changed=../proto/ipc.proto");

    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    if protoc_needs_proto3_optional_flag() {
        config.protoc_arg(PROTO3_OPTIONAL_FLAG);
    }

    config.compile_protos(
        &["../proto/auth_protocol.proto", "../proto/ipc.proto"],
        &["../proto/"],
    )?;

    Ok(())
}
