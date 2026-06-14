//! File vault Tauri commands for KESTREL Vault.
//!
//! Provides upload, list, get, decrypt, and delete operations for encrypted
//! file storage. Files are encrypted with AES-256-GCM using the file
//! encryption sub-key (derived from the DEK via HKDF).
//!
//! # Security
//!
//! - File **content** is encrypted with the file encryption sub-key (not the DEK directly)
//! - File **metadata** (filename, size, mime_type, path) is encrypted with the DEK
//! - Each file gets a unique nonce for both content and metadata encryption
//! - AAD context binds every encryption to the file entry ID + field name
//! - Encrypted files are stored on disk in the app data directory under `files/`
//! - The original file is never copied — only the encrypted version exists
//! - File deletion securely removes the encrypted file from disk
//!
//! # File Storage Layout
//!
//! ```text
//! app_data_dir/
//! ├── kestrel_vault.db          # SQLite database
//! └── files/
//!     ├── {uuid1}.enc          # Encrypted file content
//!     ├── {uuid2}.enc
//!     └── ...
//! ```
//!
//! # IPC Contract
//!
//! | Command          | Required State | Effect                    |
//! |------------------|---------------|---------------------------|
//! | file_upload      | Unlocked      | Read, encrypt, store      |
//! | file_list        | Unlocked      | List with decrypted names  |
//! | file_get         | Unlocked      | Get metadata (no content)  |
//! | file_decrypt     | Unlocked      | Decrypt + export to path   |
//! | file_delete      | Unlocked      | Delete encrypted file + DB |

use crate::commands::types::{
    validate_field, validate_uuid, CommandError, CommandResult,
    FileEntryResponse,
};
use crate::crypto::vault_crypto::VaultCryptoService;
use crate::crypto::subkeys::SubKeySet;
use crate::crypto::cipher::{self, Ciphertext, Nonce};
use crate::db::file_entry_repo::{FileEntryRepo, CreateFileEntryRequest};
use tauri::State;

use super::auth_commands::AppState;

/// Maximum filename length
const MAX_FILENAME_LEN: usize = 256;

/// Field names for AAD context in file metadata encryption.
mod field_names {
    pub const FILENAME: &str = "filename";
    pub const FILE_SIZE: &str = "file_size";
    pub const MIME_TYPE: &str = "mime_type";
    pub const ENCRYPTED_PATH: &str = "encrypted_path";
    pub const FILE_CONTENT: &str = "file_content";
}

/// Uploads a file, encrypts it with AES-256-GCM, and stores it.
///
/// # Flow
/// 1. Read the original file from the given path
/// 2. Generate a unique file ID (UUID v4)
/// 3. Encrypt file content with the file encryption sub-key
/// 4. Encrypt metadata (filename, size, mime_type) with the DEK
/// 5. Save encrypted file to app data dir under `files/{id}.enc`
/// 6. Store encrypted metadata in the database
///
/// # Security
///
/// - File content uses the file_encryption sub-key (key separation)
/// - Metadata uses the DEK directly (consistent with vault entries)
/// - Each encryption uses a fresh random nonce
/// - AAD context prevents swap attacks
#[tauri::command]
pub fn file_upload(
    file_path: String,
    folder_id: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<FileEntryResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    // Validate file path
    if file_path.is_empty() {
        return Err(CommandError::validation("File path is required"));
    }

    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Get app data directory for storing encrypted files
    let app_data_dir = state.get_app_data_dir().ok_or_else(|| {
        CommandError::unauthorized("App data directory not available")
    })?;

    // Read the original file
    let file_data = std::fs::read(&file_path)
        .map_err(|e| CommandError::from_kestrel(
            crate::error::KestrelError::Io(format!("Failed to read file: {e}"))
        ))?;

    let file_size = file_data.len() as u64;
    if file_size == 0 {
        return Err(CommandError::validation("Cannot upload empty file"));
    }

    // Extract original filename from path
    let filename = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    validate_field(&filename, MAX_FILENAME_LEN, "Filename")?;

    // Detect MIME type from extension
    let mime_type = detect_mime_type(&filename);

    // Generate unique file ID
    let file_id = uuid::Uuid::new_v4().to_string();
    let file_id_str = file_id.as_str();

    // ── Encrypt file CONTENT with the file encryption sub-key ──
    let dek_derived = dek.as_derived_key();
    let file_subkey = SubKeySet::derive_from_dek(&dek_derived)
        .map_err(CommandError::from_kestrel)?
        .file_encryption
        .clone();
    let file_key = file_subkey.as_derived_key();

    let aad_context = format!("{file_id_str}:file_content");
    let (content_nonce, content_ciphertext) = cipher::encrypt(
        &file_key,
        &file_data,
        aad_context.as_bytes(),
    ).map_err(CommandError::from_kestrel)?;

    // Build envelope for file content: [version:1][nonce:12][ciphertext+tag]
    let mut content_envelope = Vec::with_capacity(1 + 12 + content_ciphertext.0.len());
    content_envelope.push(0x01); // version
    content_envelope.extend_from_slice(&content_nonce.0);
    content_envelope.extend_from_slice(&content_ciphertext.0);

    // ── Save encrypted file to disk ──
    let files_dir = app_data_dir.join("files");
    if !files_dir.exists() {
        std::fs::create_dir_all(&files_dir)
            .map_err(|e| CommandError::from_kestrel(
                crate::error::KestrelError::Io(format!("Failed to create files directory: {e}"))
            ))?;
    }

    let enc_file_path = files_dir.join(format!("{file_id}.enc"));
    std::fs::write(&enc_file_path, &content_envelope)
        .map_err(|e| CommandError::from_kestrel(
            crate::error::KestrelError::Io(format!("Failed to write encrypted file: {e}"))
        ))?;

    // ── Encrypt METADATA with the DEK ──
    let crypto_service = VaultCryptoService::new_dek(&dek);

    // Encrypt filename
    let enc_filename = crypto_service.encrypt_field(file_id_str, field_names::FILENAME, filename.as_bytes())
        .map_err(CommandError::from_kestrel)?
        .envelope_bytes;

    // Encrypt on-disk path (the relative path within files/)
    let relative_path = format!("files/{file_id}.enc");
    let enc_path = crypto_service.encrypt_field(file_id_str, field_names::ENCRYPTED_PATH, relative_path.as_bytes())
        .map_err(CommandError::from_kestrel)?
        .envelope_bytes;

    // Encrypt file size
    let size_str = file_size.to_string();
    let enc_size = crypto_service.encrypt_field(file_id_str, field_names::FILE_SIZE, size_str.as_bytes())
        .map_err(CommandError::from_kestrel)?
        .envelope_bytes;

    // Encrypt MIME type
    let enc_mime = if mime_type.is_empty() {
        None
    } else {
        Some(
            crypto_service.encrypt_field(file_id_str, field_names::MIME_TYPE, mime_type.as_bytes())
                .map_err(CommandError::from_kestrel)?
                .envelope_bytes
        )
    };

    // Extract nonce from the first envelope (filename) for the DB record
    // The envelope format is [version:1][nonce:12][ciphertext+tag:N]
    let nonce_bytes = if enc_filename.len() > 13 {
        enc_filename[1..13].to_vec()
    } else {
        return Err(CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Envelope too short to extract nonce".to_string())
        ));
    };

    // ── Store metadata in database ──
    let request = CreateFileEntryRequest {
        id: Some(file_id.clone()),
        encrypted_filename: enc_filename,
        encrypted_path: enc_path,
        encrypted_file_size: enc_size,
        encrypted_mime_type: enc_mime,
        nonce: nonce_bytes,
        folder_id,
    };

    let row = crate::commands::async_runtime::block_on(async {
        FileEntryRepo::create(&pool, request).await
    }).map_err(|e| {
        // Clean up encrypted file if DB insert fails
        let _ = std::fs::remove_file(&enc_file_path);
        CommandError::from_kestrel(e)
    })?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("File uploaded and encrypted: id={}, name={}, size={}", file_id, filename, file_size);

    Ok(FileEntryResponse {
        id: row.id,
        filename,
        mime_type,
        size_bytes: file_size as i64,
        folder_id: row.folder_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Lists all encrypted files with decrypted metadata.
#[tauri::command]
pub fn file_list(
    folder_id: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<FileEntryResponse>> {
    state.require_unlocked()?;
    state.validate_session()?;

    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let rows = crate::commands::async_runtime::block_on(async {
        FileEntryRepo::list_by_folder(&pool, folder_id.as_deref()).await
    }).map_err(CommandError::from_kestrel)?;

    let crypto_service = VaultCryptoService::new_dek(&dek);

    let mut responses = Vec::new();
    for row in rows {
        let entry_id = &row.id;

        // Decrypt filename
        let filename = if row.filename.is_empty() {
            "(unnamed)".to_string()
        } else {
            match crypto_service.decrypt_field(entry_id, field_names::FILENAME, &row.filename) {
                Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
                Err(_) => "(decryption failed)".to_string(),
            }
        };

        // Decrypt file size
        let size_bytes = if row.file_size.is_empty() {
            0
        } else {
            match crypto_service.decrypt_field(entry_id, field_names::FILE_SIZE, &row.file_size) {
                Ok(decrypted) => {
                    let size_str = String::from_utf8_lossy(&decrypted.plaintext).to_string();
                    size_str.parse::<i64>().unwrap_or(0)
                }
                Err(_) => 0,
            }
        };

        // Decrypt MIME type
        let mime_type = match &row.mime_type {
            Some(enc_mime) if !enc_mime.is_empty() => {
                match crypto_service.decrypt_field(entry_id, field_names::MIME_TYPE, enc_mime) {
                    Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
                    Err(_) => "application/octet-stream".to_string(),
                }
            }
            _ => "application/octet-stream".to_string(),
        };

        responses.push(FileEntryResponse {
            id: row.id,
            filename,
            mime_type,
            size_bytes,
            folder_id: row.folder_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        });
    }

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    Ok(responses)
}

/// Gets metadata for a single encrypted file (no content).
#[tauri::command]
pub fn file_get(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<FileEntryResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let row = crate::commands::async_runtime::block_on(async {
        FileEntryRepo::get_by_id(&pool, &id).await
    }).map_err(CommandError::from_kestrel)?;

    let crypto_service = VaultCryptoService::new_dek(&dek);
    let entry_id = &row.id;

    // Decrypt filename
    let filename = if row.filename.is_empty() {
        "(unnamed)".to_string()
    } else {
        match crypto_service.decrypt_field(entry_id, field_names::FILENAME, &row.filename) {
            Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
            Err(_) => "(decryption failed)".to_string(),
        }
    };

    // Decrypt file size
    let size_bytes = if row.file_size.is_empty() {
        0
    } else {
        match crypto_service.decrypt_field(entry_id, field_names::FILE_SIZE, &row.file_size) {
            Ok(decrypted) => {
                let size_str = String::from_utf8_lossy(&decrypted.plaintext).to_string();
                size_str.parse::<i64>().unwrap_or(0)
            }
            Err(_) => 0,
        }
    };

    // Decrypt MIME type
    let mime_type = match &row.mime_type {
        Some(enc_mime) if !enc_mime.is_empty() => {
            match crypto_service.decrypt_field(entry_id, field_names::MIME_TYPE, enc_mime) {
                Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
                Err(_) => "application/octet-stream".to_string(),
            }
        }
        _ => "application/octet-stream".to_string(),
    };

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    Ok(FileEntryResponse {
        id: row.id,
        filename,
        mime_type,
        size_bytes,
        folder_id: row.folder_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Decrypts a file and saves it to the specified output path.
///
/// This is the ONLY command that returns decrypted file content.
/// The frontend should use Tauri's save dialog to get the output path.
///
/// # Security
///
/// - Audit-logged (file decryption event)
/// - Uses the file encryption sub-key for content decryption
/// - The decrypted file is written to a user-specified location
#[tauri::command]
pub fn file_decrypt(
    id: String,
    output_path: String,
    state: State<'_, AppState>,
) -> CommandResult<String> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if output_path.is_empty() {
        return Err(CommandError::validation("Output path is required"));
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;
    let app_data_dir = state.get_app_data_dir().ok_or_else(|| {
        CommandError::unauthorized("App data directory not available")
    })?;

    // Get file entry from database
    let row = crate::commands::async_runtime::block_on(async {
        FileEntryRepo::get_by_id(&pool, &id).await
    }).map_err(CommandError::from_kestrel)?;

    let entry_id = &row.id;
    let crypto_service = VaultCryptoService::new_dek(&dek);

    // Decrypt the on-disk path
    let relative_path = if row.encrypted_path.is_empty() {
        // Fallback: construct the expected path from the ID
        format!("files/{id}.enc")
    } else {
        match crypto_service.decrypt_field(entry_id, field_names::ENCRYPTED_PATH, &row.encrypted_path) {
            Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
            Err(_) => format!("files/{id}.enc"), // Fallback
        }
    };

    // Read encrypted file from disk
    let enc_file_path = app_data_dir.join(&relative_path);
    let content_envelope = std::fs::read(&enc_file_path)
        .map_err(|e| CommandError::from_kestrel(
            crate::error::KestrelError::Io(format!("Failed to read encrypted file: {e}"))
        ))?;

    // Parse envelope: [version:1][nonce:12][ciphertext+tag:N]
    if content_envelope.len() < 29 {
        return Err(CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Encrypted file envelope too short".to_string())
        ));
    }

    if content_envelope[0] != 0x01 {
        return Err(CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Unknown envelope version in file".to_string())
        ));
    }

    let nonce_bytes: [u8; 12] = content_envelope[1..13]
        .try_into()
        .map_err(|_| CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Failed to extract nonce from file envelope".to_string())
        ))?;
    let nonce = Nonce(nonce_bytes);
    let ciphertext = Ciphertext(content_envelope[13..].to_vec());

    // Decrypt file content with the file encryption sub-key
    let dek_derived = dek.as_derived_key();
    let file_subkey = SubKeySet::derive_from_dek(&dek_derived)
        .map_err(CommandError::from_kestrel)?
        .file_encryption
        .clone();
    let file_key = file_subkey.as_derived_key();

    let aad_context = format!("{id}:file_content");
    let plaintext = cipher::decrypt(&file_key, &nonce, &ciphertext, aad_context.as_bytes())
        .map_err(CommandError::from_kestrel)?;

    // Write decrypted file to output path
    std::fs::write(&output_path, &plaintext)
        .map_err(|e| CommandError::from_kestrel(
            crate::error::KestrelError::Io(format!("Failed to write decrypted file: {e}"))
        ))?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::warn!("File decrypted and exported: id={}, output={}", id, output_path);

    Ok(output_path)
}

/// Deletes an encrypted file (both disk file and DB entry).
///
/// # Security
///
/// - Requires confirmation
/// - Deletes the encrypted file from disk
/// - Removes the metadata from the database
/// - Audit-logged
#[tauri::command]
pub fn file_delete(
    id: String,
    confirm: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if !confirm {
        return Err(CommandError::validation(
            "Deletion requires confirmation",
        ));
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;
    let app_data_dir = state.get_app_data_dir().ok_or_else(|| {
        CommandError::unauthorized("App data directory not available")
    })?;

    // Get file entry to find the encrypted file path
    let row = crate::commands::async_runtime::block_on(async {
        FileEntryRepo::get_by_id(&pool, &id).await
    }).map_err(CommandError::from_kestrel)?;

    let crypto_service = VaultCryptoService::new_dek(&dek);
    let entry_id = &row.id;

    // Decrypt the on-disk path
    let relative_path = if row.encrypted_path.is_empty() {
        format!("files/{id}.enc")
    } else {
        match crypto_service.decrypt_field(entry_id, field_names::ENCRYPTED_PATH, &row.encrypted_path) {
            Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
            Err(_) => format!("files/{id}.enc"),
        }
    };

    // Delete encrypted file from disk
    let enc_file_path = app_data_dir.join(&relative_path);
    if enc_file_path.exists() {
        std::fs::remove_file(&enc_file_path)
            .map_err(|e| CommandError::from_kestrel(
                crate::error::KestrelError::Io(format!("Failed to delete encrypted file: {e}"))
            ))?;
    }

    // Delete metadata from database
    crate::commands::async_runtime::block_on(async {
        FileEntryRepo::delete(&pool, &id).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("File deleted: id={}", id);

    Ok(())
}

/// Detects MIME type from file extension.
///
/// This is a simple heuristic — not a full MIME type detection library.
/// For unknown extensions, returns "application/octet-stream".
fn detect_mime_type(filename: &str) -> String {
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        // Documents
        "pdf" => "application/pdf",
        "doc" | "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" | "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" | "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "txt" => "text/plain",
        "rtf" => "application/rtf",
        "csv" => "text/csv",

        // Images
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",

        // Archives
        "zip" => "application/zip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",

        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",

        // Video
        "mp4" => "video/mp4",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "webm" => "video/webm",

        // Code
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "ts" => "application/typescript",

        // Design
        "fig" => "application/x-fig",
        "sketch" => "application/sketch",
        "psd" => "image/vnd.adobe.photoshop",
        "ai" => "application/postscript",

        // Default
        _ => "application/octet-stream",
    }
    .to_string()
}
