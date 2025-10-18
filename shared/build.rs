use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../proto/auth_protocol.proto");
    
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["../proto/auth_protocol.proto"], &["../proto/"])?;
    
    Ok(())
}
