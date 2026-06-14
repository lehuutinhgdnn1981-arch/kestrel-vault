//! Threat scanner module for KESTREL Vault.
//!
//! Provides security analysis tools for evaluating password strength,
//! checking against known breach databases, and scanning for
//! vulnerabilities in the user's vault.
//!
//! # Design Principles
//!
//! - **Offline-first**: All analysis is performed locally
//! - **No network calls**: Passwords never leave the device
//! - **Hash-based lookup**: Breach checks use SHA-256 hashes
//! - **Local breach database**: Embedded database of known breached passwords
//!
//! # Submodules
//!
//! - `password_strength`: Entropy calculation and pattern detection
//! - `breach_check`: Local breach database lookup
//! - `vulnerability`: Vault-wide vulnerability assessment

pub mod breach_check;
pub mod password_strength;
pub mod vulnerability;

use serde::{Deserialize, Serialize};

/// Overall threat level for a security finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    /// No security concerns detected.
    None,
    /// Minor concern, may want to address eventually.
    Low,
    /// Moderate concern, should be addressed soon.
    Medium,
    /// Significant concern, should be addressed promptly.
    High,
    /// Critical concern, must be addressed immediately.
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::None => write!(f, "none"),
            ThreatLevel::Low => write!(f, "low"),
            ThreatLevel::Medium => write!(f, "medium"),
            ThreatLevel::High => write!(f, "high"),
            ThreatLevel::Critical => write!(f, "critical"),
        }
    }
}

/// A security scan result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    /// The threat level identified.
    pub threat_level: ThreatLevel,
    /// Human-readable description of the finding.
    pub description: String,
    /// Suggested remediation action.
    pub recommendation: String,
    /// Additional details about the finding.
    pub details: serde_json::Value,
}

impl ScanResult {
    /// Creates a new scan result.
    pub fn new(
        threat_level: ThreatLevel,
        description: String,
        recommendation: String,
    ) -> Self {
        ScanResult {
            threat_level,
            description,
            recommendation,
            details: serde_json::Value::Null,
        }
    }

    /// Creates a scan result indicating no issues found.
    pub fn ok() -> Self {
        ScanResult {
            threat_level: ThreatLevel::None,
            description: "No issues found".to_string(),
            recommendation: String::new(),
            details: serde_json::Value::Null,
        }
    }
}
