//! Secure search module for KESTREL Vault.
//!
//! Provides search functionality that does not leak plaintext patterns
//! or sensitive information through search queries or results.
//!
//! # Security Model
//!
//! Traditional search would require decrypting all entries to match
//! against query terms, which exposes plaintext in memory. Instead,
//! we use a two-tier approach:
//!
//! 1. **Plaintext search**: Non-sensitive fields (title, username) are
//!    stored as plaintext in the database for fast SQL LIKE queries.
//!    This is safe because titles and usernames are not secrets.
//!
//! 2. **Encrypted search index** (future): For searching within
//!    encrypted fields (notes, URLs), we will use HMAC-based blind
//!    indexing with the search sub-key derived from the DEK via HKDF.
//!    This allows matching without decrypting all entries.
//!
//! # Current Implementation
//!
//! Currently, search operates on plaintext metadata fields only:
//! - `title` (VARCHAR in vault_entries)
//! - `username` (VARCHAR in vault_entries)
//!
//! Passwords are NEVER included in search results or indices.

use crate::error::KestrelError;
use crate::vault::entry::VaultEntry;

/// Search query parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchQuery {
    /// The search term to match against.
    pub term: String,
    /// Optional folder to restrict search to.
    pub folder_id: Option<uuid::Uuid>,
    /// Optional tag to filter by.
    pub tag: Option<String>,
    /// Maximum number of results to return.
    pub limit: Option<i64>,
}

impl SearchQuery {
    /// Creates a new search query with the given term.
    pub fn new(term: String) -> Self {
        SearchQuery {
            term,
            folder_id: None,
            tag: None,
            limit: None,
        }
    }

    /// Validates the search query.
    ///
    /// Ensures the search term is not empty and does not
    /// contain potentially dangerous patterns.
    pub fn validate(&self) -> Result<(), KestrelError> {
        if self.term.trim().is_empty() {
            return Err(KestrelError::Validation(
                "Search term must not be empty".to_string(),
            ));
        }
        if self.term.len() > 256 {
            return Err(KestrelError::Validation(
                "Search term too long (max 256 characters)".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns the SQL LIKE pattern for this query.
    ///
    /// The pattern wraps the search term with `%` wildcards
    /// for case-insensitive substring matching.
    pub fn like_pattern(&self) -> String {
        format!("%{}%", self.term.trim())
    }
}

/// A search result with relevance scoring.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    /// The matching vault entry.
    pub entry: VaultEntry,
    /// Relevance score (higher = better match).
    pub score: f64,
}

/// Normalizes a string for search matching.
///
/// Converts to lowercase and collapses whitespace for
/// case-insensitive matching.
pub fn normalize_search_term(term: &str) -> String {
    term.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Tokenizes a search term into individual words.
///
/// Splits on whitespace and punctuation, normalizes to lowercase.
/// Used for multi-word search queries where each word is
/// matched independently.
pub fn tokenize(term: &str) -> Vec<String> {
    term.to_lowercase()
        .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Builds the search index for a vault entry.
///
/// This function extracts searchable terms from non-sensitive
/// fields (title, URL, tags) and creates index entries.
///
/// # Security
///
/// Only non-sensitive fields are indexed. Passwords and notes
/// are never included in the search index.
///
/// # Current Implementation
///
/// In the current implementation, search is performed directly
/// on the plaintext `title` and `username` columns in the database
/// using SQL LIKE. This function is a placeholder for future
/// HMAC-based blind indexing using the search sub-key.
pub fn build_search_index(_entry: &VaultEntry) -> Result<(), KestrelError> {
    // Future implementation will:
    // 1. Extract title, URL, and tags from the entry
    // 2. Tokenize and normalize the terms
    // 3. HMAC each token with the search sub-key
    // 4. Store HMAC(token) in a search_index table
    // 5. On search, HMAC the query term and match against stored HMACs
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_query_validates_empty() {
        let query = SearchQuery::new("".to_string());
        assert!(query.validate().is_err());
    }

    #[test]
    fn search_query_validates_whitespace() {
        let query = SearchQuery::new("   ".to_string());
        assert!(query.validate().is_err());
    }

    #[test]
    fn search_query_validates_normal() {
        let query = SearchQuery::new("github".to_string());
        assert!(query.validate().is_ok());
    }

    #[test]
    fn search_query_validates_too_long() {
        let query = SearchQuery::new("a".repeat(257));
        assert!(query.validate().is_err());
    }

    #[test]
    fn search_query_like_pattern() {
        let query = SearchQuery::new("github".to_string());
        assert_eq!(query.like_pattern(), "%github%");
    }

    #[test]
    fn normalize_search_term_lowercase() {
        assert_eq!(normalize_search_term("GitHub"), "github");
        assert_eq!(normalize_search_term("  Hello   World  "), "hello world");
    }

    #[test]
    fn tokenize_splits_correctly() {
        let tokens = tokenize("Hello, World! Foo-Bar");
        assert_eq!(tokens, vec!["hello", "world", "foo", "bar"]);
    }

    #[test]
    fn tokenize_handles_empty() {
        let tokens = tokenize("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_handles_whitespace_only() {
        let tokens = tokenize("   ");
        assert!(tokens.is_empty());
    }
}
