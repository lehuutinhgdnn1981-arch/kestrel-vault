//! Build script for KESTREL Vault.
//!
//! This script invokes the Tauri build process which handles
//! native resource compilation and preparation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tauri_build::build();
    Ok(())
}
