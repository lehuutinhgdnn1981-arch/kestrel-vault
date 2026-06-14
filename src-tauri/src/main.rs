//! KESTREL Vault - Main Entry Point
//!
//! This is the binary entry point for the KESTREL Vault application.
//! It delegates to the library's `run()` function which handles
//! Tauri application initialization and lifecycle.

// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    kestrel_vault::run()?;
    Ok(())
}
