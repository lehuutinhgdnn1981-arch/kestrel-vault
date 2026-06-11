//! Folder organization for KESTREL Vault.
//!
//! Provides hierarchical folder structures for organizing
//! vault entries. Folders support nesting via parent references.
//!
//! # Security
//!
//! Folder names are stored in the database but are never included
//! in audit logs or error messages to prevent information leakage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A folder for organizing vault entries.
///
/// Folders support a tree structure through the `parent_id` field.
/// A folder with `parent_id = None` is a root-level folder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Folder {
    /// Unique identifier for this folder.
    pub id: Uuid,
    /// Display name for the folder.
    pub name: String,
    /// Parent folder ID. `None` for root-level folders.
    pub parent_id: Option<Uuid>,
    /// Timestamp when this folder was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this folder was last modified.
    pub updated_at: DateTime<Utc>,
}

impl Folder {
    /// Creates a new root-level folder.
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Folder {
            id: Uuid::new_v4(),
            name,
            parent_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a new subfolder within the given parent.
    pub fn new_child(name: String, parent_id: Uuid) -> Self {
        let now = Utc::now();
        Folder {
            id: Uuid::new_v4(),
            name,
            parent_id: Some(parent_id),
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns true if this is a root-level folder.
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }
}

/// A tree node representing a folder and its children.
///
/// Used for building and traversing the folder hierarchy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderNode {
    /// The folder at this level.
    pub folder: Folder,
    /// Child folders (subfolders).
    pub children: Vec<FolderNode>,
}

/// Builds a folder tree from a flat list of folders.
///
/// # Arguments
///
/// * `folders` - A flat list of all folders
///
/// # Returns
///
/// A list of root `FolderNode`s, each potentially containing
/// nested children.
///
/// # TODO (Phase 2)
///
/// - Implement folder tree building algorithm
/// - Add cycle detection
/// - Add depth limits
pub fn build_folder_tree(_folders: &[Folder]) -> Result<Vec<FolderNode>, crate::error::KestrelError> {
    // TODO: Implement in Phase 2
    // 1. Index folders by ID
    // 2. For each root folder, recursively build children
    // 3. Detect and reject circular references
    // 4. Return tree structure
    Ok(Vec::new())
}

/// Moves a folder to a new parent.
///
/// # Security
///
/// Prevents circular references by checking that the new parent
/// is not a descendant of the folder being moved.
///
/// # TODO (Phase 2)
///
/// - Implement circular reference detection
/// - Add transaction support for atomic moves
pub fn move_folder(
    _folder_id: Uuid,
    _new_parent_id: Option<Uuid>,
) -> Result<(), crate::error::KestrelError> {
    // TODO: Implement in Phase 2
    // 1. Load the folder
    // 2. Check for circular references
    // 3. Update the parent_id
    // 4. Update the timestamp
    Err(crate::error::KestrelError::Vault(
        "Folder move not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_root_folder() {
        let folder = Folder::new("Personal".to_string());
        assert!(folder.is_root());
        assert_eq!(folder.name, "Personal");
    }

    #[test]
    fn create_child_folder() {
        let parent = Folder::new("Personal".to_string());
        let child = Folder::new_child("Banking".to_string(), parent.id);
        assert!(!child.is_root());
        assert_eq!(child.parent_id, Some(parent.id));
    }

    #[test]
    fn folder_has_uuid() {
        let folder = Folder::new("Test".to_string());
        assert!(!folder.id.is_nil());
    }
}
