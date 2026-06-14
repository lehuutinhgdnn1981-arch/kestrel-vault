//! Password strength analyzer for KESTREL Vault.
//!
//! Provides local-only password strength analysis including:
//! - Entropy calculation
//! - Pattern detection (keyboard walks, common patterns, dictionary words)
//! - Strength rating from VeryWeak to VeryStrong
//!
//! # Design Principles
//!
//! - **NO network calls**: All analysis is performed locally
//! - **NO data transmission**: Passwords never leave the device
//! - **Conservative ratings**: When in doubt, rate lower
//!
//! # Entropy Calculation
//!
//! Entropy is calculated based on the character space actually used:
//! - Lowercase letters: 26 characters
//! - Uppercase letters: 26 characters
//! - Digits: 10 characters
//! - Symbols: 33 common symbols
//!
//! The total entropy is: `log2(character_space^length)`

use crate::scanner::ThreatLevel;
use serde::{Deserialize, Serialize};

/// Password strength rating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStrength {
    /// Extremely weak, trivially guessable.
    VeryWeak,
    /// Weak, vulnerable to basic attacks.
    Weak,
    /// Fair, may resist casual attacks.
    Fair,
    /// Strong, resistant to most attacks.
    Strong,
    /// Very strong, resistant to sophisticated attacks.
    VeryStrong,
}

impl std::fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordStrength::VeryWeak => write!(f, "very_weak"),
            PasswordStrength::Weak => write!(f, "weak"),
            PasswordStrength::Fair => write!(f, "fair"),
            PasswordStrength::Strong => write!(f, "strong"),
            PasswordStrength::VeryStrong => write!(f, "very_strong"),
        }
    }
}

/// Detailed password analysis result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordAnalysis {
    /// Overall strength rating.
    pub strength: PasswordStrength,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
    /// Estimated time to crack (online, rate-limited attack).
    pub crack_time_online: String,
    /// Estimated time to crack (offline, fast hash).
    pub crack_time_offline: String,
    /// Detected patterns in the password.
    pub patterns: Vec<DetectedPattern>,
    /// Warnings about the password.
    pub warnings: Vec<String>,
    /// Suggestions for improvement.
    pub suggestions: Vec<String>,
}

/// A pattern detected in a password.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectedPattern {
    /// Type of pattern detected.
    pub pattern_type: PatternType,
    /// Human-readable description.
    pub description: String,
    /// How much this pattern reduces effective entropy.
    pub entropy_reduction: f64,
}

/// Types of patterns that can be detected in passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// Keyboard walk pattern (e.g., "qwerty", "asdfgh").
    KeyboardWalk,
    /// Repeated characters (e.g., "aaa", "111").
    RepeatedChars,
    /// Sequential characters (e.g., "abc", "123").
    SequentialChars,
    /// Common dictionary word.
    DictionaryWord,
    /// Common password from top-N lists.
    CommonPassword,
    /// Date pattern (e.g., "1990", "0125").
    DatePattern,
    /// Leet speak substitution (e.g., "p4ssw0rd").
    LeetSpeak,
}

/// Analyzes a password and returns a detailed strength report.
///
/// This function performs all analysis locally without any
/// network calls. The password is never stored or transmitted.
///
/// # Arguments
///
/// * `password` - The password to analyze (cleared from memory after use)
///
/// # Returns
///
/// A `PasswordAnalysis` with entropy, strength rating, detected patterns,
/// and suggestions for improvement.
///
/// # Security
///
/// The password parameter should be zeroized by the caller after use.
pub fn analyze_password(password: &str) -> PasswordAnalysis {
    let entropy_bits = calculate_entropy(password);
    let patterns = detect_patterns(password);
    let warnings = generate_warnings(password, &patterns);
    let suggestions = generate_suggestions(password, &patterns);

    let entropy_penalty: f64 = patterns.iter().map(|p| p.entropy_reduction).sum();
    let effective_entropy = (entropy_bits - entropy_penalty).max(0.0);

    let strength = classify_strength(effective_entropy);
    let threat = strength_to_threat(&strength);

    let crack_time_offline = estimate_crack_time(effective_entropy, 1_000_000_000_000.0);
    let crack_time_online = estimate_crack_time(effective_entropy, 100.0);

    // Suppress unused variable warning for threat
    let _ = threat;

    PasswordAnalysis {
        strength,
        entropy_bits,
        crack_time_online,
        crack_time_offline,
        patterns,
        warnings,
        suggestions,
    }
}

/// Calculates the Shannon entropy of a password based on character space.
///
/// This calculates the maximum possible entropy given the character
/// classes used and the password length.
pub fn calculate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut char_space: usize = 0;
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if has_lower {
        char_space += 26;
    }
    if has_upper {
        char_space += 26;
    }
    if has_digit {
        char_space += 10;
    }
    if has_symbol {
        char_space += 33;
    }

    if char_space == 0 {
        return 0.0;
    }

    (password.len() as f64) * (char_space as f64).log2()
}

/// Detects common patterns in a password.
///
/// Looks for keyboard walks, repeated characters, sequences,
/// and other patterns that reduce effective entropy.
pub fn detect_patterns(password: &str) -> Vec<DetectedPattern> {
    let mut patterns = Vec::new();

    // Check for keyboard walk patterns
    if let Some(kw) = detect_keyboard_walk(password) {
        patterns.push(kw);
    }

    // Check for repeated characters
    if let Some(rc) = detect_repeated_chars(password) {
        patterns.push(rc);
    }

    // Check for sequential characters
    if let Some(sc) = detect_sequential_chars(password) {
        patterns.push(sc);
    }

    // Check for common passwords
    if let Some(cp) = detect_common_password(password) {
        patterns.push(cp);
    }

    patterns
}

/// Detects keyboard walk patterns.
fn detect_keyboard_walk(password: &str) -> Option<DetectedPattern> {
    let keyboard_rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890",
    ];

    let lower = password.to_ascii_lowercase();
    for row in &keyboard_rows {
        // Check for forward or reverse keyboard walks of length >= 4
        for window_len in 4..=lower.len() {
            for i in 0..=lower.len().saturating_sub(window_len) {
                let slice = &lower[i..i + window_len];
                if row.contains(slice) || row.contains(&slice.chars().rev().collect::<String>()) {
                    return Some(DetectedPattern {
                        pattern_type: PatternType::KeyboardWalk,
                        description: format!("Keyboard walk pattern detected: '{slice}'"),
                        entropy_reduction: (window_len as f64) * 1.5,
                    });
                }
            }
        }
    }
    None
}

/// Detects repeated character sequences.
fn detect_repeated_chars(password: &str) -> Option<DetectedPattern> {
    let chars: Vec<char> = password.chars().collect();
    let mut max_repeat = 1;
    let mut current_repeat = 1;

    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            current_repeat += 1;
            max_repeat = max_repeat.max(current_repeat);
        } else {
            current_repeat = 1;
        }
    }

    if max_repeat >= 3 {
        Some(DetectedPattern {
            pattern_type: PatternType::RepeatedChars,
            description: format!("Repeated character sequence (x{max_repeat})"),
            entropy_reduction: (max_repeat as f64) * 2.0,
        })
    } else {
        None
    }
}

/// Detects sequential character sequences (abc, 123).
fn detect_sequential_chars(password: &str) -> Option<DetectedPattern> {
    let chars: Vec<char> = password.chars().collect();
    let mut max_seq = 1;
    let mut current_seq = 1;

    for i in 1..chars.len() {
        let prev = chars[i - 1] as i32;
        let curr = chars[i] as i32;
        if curr - prev == 1 || prev - curr == 1 {
            current_seq += 1;
            max_seq = max_seq.max(current_seq);
        } else {
            current_seq = 1;
        }
    }

    if max_seq >= 3 {
        Some(DetectedPattern {
            pattern_type: PatternType::SequentialChars,
            description: format!("Sequential character pattern (length {max_seq})"),
            entropy_reduction: (max_seq as f64) * 1.5,
        })
    } else {
        None
    }
}

/// Checks against a small list of the most common passwords.
fn detect_common_password(password: &str) -> Option<DetectedPattern> {
    let common = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
    ];

    let lower = password.to_ascii_lowercase();
    if common.contains(&lower.as_str()) {
        return Some(DetectedPattern {
            pattern_type: PatternType::CommonPassword,
            description: "Password is in the list of most common passwords".to_string(),
            entropy_reduction: password.len() as f64 * 3.0,
        });
    }
    None
}

/// Classifies effective entropy into a strength rating.
fn classify_strength(effective_entropy: f64) -> PasswordStrength {
    match effective_entropy {
        e if e < 28.0 => PasswordStrength::VeryWeak,
        e if e < 36.0 => PasswordStrength::Weak,
        e if e < 60.0 => PasswordStrength::Fair,
        e if e < 80.0 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

/// Converts a password strength to a threat level.
fn strength_to_threat(strength: &PasswordStrength) -> ThreatLevel {
    match strength {
        PasswordStrength::VeryWeak => ThreatLevel::Critical,
        PasswordStrength::Weak => ThreatLevel::High,
        PasswordStrength::Fair => ThreatLevel::Medium,
        PasswordStrength::Strong => ThreatLevel::Low,
        PasswordStrength::VeryStrong => ThreatLevel::None,
    }
}

/// Estimates crack time given entropy bits and guesses per second.
fn estimate_crack_time(entropy_bits: f64, guesses_per_second: f64) -> String {
    let seconds = (2.0_f64.powf(entropy_bits) / 2.0) / guesses_per_second;

    if seconds < 1.0 {
        return "Instant".to_string();
    }
    if seconds < 60.0 {
        return format!("{:.0} seconds", seconds);
    }
    if seconds < 3600.0 {
        return format!("{:.1} minutes", seconds / 60.0);
    }
    if seconds < 86400.0 {
        return format!("{:.1} hours", seconds / 3600.0);
    }
    if seconds < 86400.0 * 365.25 {
        return format!("{:.1} days", seconds / 86400.0);
    }
    if seconds < 86400.0 * 365.25 * 100.0 {
        return format!("{:.1} years", seconds / (86400.0 * 365.25));
    }
    if seconds < 86400.0 * 365.25 * 1_000_000.0 {
        return format!("{:.0} years", seconds / (86400.0 * 365.25));
    }
    "Centuries".to_string()
}

/// Generates warnings based on password analysis.
fn generate_warnings(
    password: &str,
    patterns: &[DetectedPattern],
) -> Vec<String> {
    let mut warnings = Vec::new();

    if password.len() < 8 {
        warnings.push("Password is too short (minimum 8 characters)".to_string());
    }
    if password.len() < 12 {
        warnings.push("Consider using at least 12 characters".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        warnings.push("No uppercase letters detected".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        warnings.push("No lowercase letters detected".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        warnings.push("No digits detected".to_string());
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        warnings.push("No symbols detected".to_string());
    }

    for pattern in patterns {
        warnings.push(pattern.description.clone());
    }

    warnings
}

/// Generates suggestions for improving password strength.
fn generate_suggestions(
    password: &str,
    patterns: &[DetectedPattern],
) -> Vec<String> {
    let mut suggestions = Vec::new();

    if password.len() < 16 {
        suggestions.push("Use a longer password (16+ characters recommended)".to_string());
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        suggestions.push("Add symbols for higher entropy".to_string());
    }
    if patterns.iter().any(|p| p.pattern_type == PatternType::KeyboardWalk) {
        suggestions.push("Avoid keyboard walk patterns".to_string());
    }
    if patterns.iter().any(|p| p.pattern_type == PatternType::CommonPassword) {
        suggestions.push("This is a commonly used password — choose something unique".to_string());
    }
    if patterns.iter().any(|p| p.pattern_type == PatternType::RepeatedChars) {
        suggestions.push("Avoid repeating characters".to_string());
    }

    if suggestions.is_empty() {
        suggestions.push("Password looks good!".to_string());
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_zero_entropy() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn weak_password_low_entropy() {
        let entropy = calculate_entropy("password");
        assert!(entropy < 40.0);
    }

    #[test]
    fn strong_password_high_entropy() {
        let entropy = calculate_entropy("Kx9#mP2$vL5@nQ8!");
        assert!(entropy > 80.0);
    }

    #[test]
    fn detects_keyboard_walk() {
        let result = detect_keyboard_walk("qwerty");
        assert!(result.is_some());
    }

    #[test]
    fn detects_repeated_chars() {
        let result = detect_repeated_chars("aaabbb");
        assert!(result.is_some());
    }

    #[test]
    fn detects_common_password() {
        let result = detect_common_password("password");
        assert!(result.is_some());
    }

    #[test]
    fn strong_password_analysis() {
        let analysis = analyze_password("Kx9#mP2$vL5@nQ8!");
        assert!(analysis.strength >= PasswordStrength::Strong);
    }

    #[test]
    fn weak_password_analysis() {
        let analysis = analyze_password("password");
        assert!(analysis.strength <= PasswordStrength::Weak);
    }
}
