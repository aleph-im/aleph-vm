//! Compile the frozen supervisor contract from the repository's proto/
//! directory. The .proto file is the single source of truth shared with the
//! Python bindings (src/aleph/vm/supervisor_interface/wire/_pb); it is
//! compiled in place, never copied.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let repo_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("crate must live at rust/crates/supervisor-proto")
        .to_path_buf();
    let proto = repo_root.join("proto/supervisor.proto");
    let include = repo_root.join("proto");

    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &[include])?;
    Ok(())
}
