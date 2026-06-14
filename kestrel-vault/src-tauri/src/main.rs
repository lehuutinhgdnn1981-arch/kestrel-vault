//! KESTREL Vault - Main Entry Point
//!
//! This is the binary entry point for the KESTREL Vault application.
//! It delegates to the library's `run()` function which handles
//! Tauri application initialization and lifecycle.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    kestrel_vault::run()?;
    Ok(())
}
