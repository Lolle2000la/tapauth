// Build script for integration tests - generates protobuf code

fn main() {
    // Point to the IPC proto file
    let ipc_proto = "../proto/ipc.proto";
    
    prost_build::Config::new()
        .compile_protos(&[ipc_proto], &["../proto"])
        .expect("Failed to compile IPC protobuf definitions for tests");
    
    // Rebuild if proto file changes
    println!("cargo:rerun-if-changed={}", ipc_proto);
}
