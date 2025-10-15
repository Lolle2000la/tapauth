fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/auth_protocol.proto");
    prost_build::compile_protos(&["../proto/auth_protocol.proto"], &["../proto/"])?;
    Ok(())
}
