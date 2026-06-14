# Threat Model Template

> **Purpose:** This template provides a standardized structure for documenting threat models for any new feature or module added to KESTREL Vault. Every feature that handles sensitive data, performs cryptographic operations, or modifies the security boundary MUST have a completed threat model before development begins.

---

## Feature Name

**Feature:** [Feature name]
**Module:** [e.g., vault, scanner, audit, config]
**Author:** [Name]
**Date:** [YYYY-MM-DD]
**Status:** [Draft / In Review / Approved]
**Reviewers:** [Names of security reviewers]

---

## Overview

<!-- Provide a 2-3 paragraph description of the feature, its purpose, and how it fits into the overall KESTREL Vault architecture. Include:

- What the feature does
- Which other modules it interacts with
- What data it processes
- Whether it introduces new trust boundaries or modifies existing ones
-->

---

## Assets

<!-- List all assets (data, keys, credentials, capabilities) that this feature interacts with or creates. For each asset, specify:

- Classification: Public, Internal, Confidential, Secret
- Where it exists: Memory, Disk, Network, IPC
- Who has access: Frontend, Backend, OS, Attacker

Example format:

| Asset | Classification | Location | Access |
|-------|---------------|----------|--------|
| Master password | Secret | Rust memory (transient) | Backend only |
| Derived key | Secret | Rust memory (secrecy::Secret) | Backend only |
| Encrypted entry BLOBs | Confidential | SQLCipher database | Backend (via PRAGMA key) |
| Folder names | Confidential | SQLCipher database (AES-256-GCM BLOB) | Backend (after decryption) |
-->

| Asset | Classification | Location | Access |
|-------|---------------|----------|--------|
| | | | |

---

## Threat Actors

<!-- Identify all threat actors who might attempt to compromise this feature. For each actor, describe their capabilities and motivation.

Common threat actors for KESTREL Vault:

- **Local Attacker**: Physical or remote access to the user's machine. Can read files, inspect memory, run processes. Motivation: credential theft.
- **Malware**: Malicious software running on the user's machine. Can inspect memory, intercept IPC, log keystrokes. Motivation: credential theft, financial gain.
- **Shoulder Surfer**: Physically present person who can see the screen. Motivation: credential theft, curiosity.
- **Forensic Analyst**: Has access to the device after seizure. Uses specialized tools (memory imaging, disk forensics). Motivation: investigation, coercion.
- **Supply Chain Attacker**: Attempts to compromise dependencies or build pipeline. Motivation: mass credential theft.
- **Network Attacker**: Intercepting network traffic. Motivation: credential interception. (Low relevance for local-first KESTREL Vault.)
-->

| Actor | Capabilities | Motivation | Sophistication |
|-------|-------------|------------|---------------|
| | | | |

---

## Attack Vectors

<!-- For each attack vector, provide:
- A clear description of the attack
- The threat actor who would execute it
- The severity: Critical / High / Medium / Low
- The likelihood: High / Medium / Low
- The impact if successful: what is compromised
- The current or planned mitigation

Severity definitions:
- Critical: Leads to complete vault compromise (all passwords exposed)
- High: Leads to partial vault compromise or master password exposure
- Medium: Leads to information leakage but not direct credential access
- Low: Leads to denial of service or minor information leakage
-->

### AV-1: [Attack Vector Name]

| Attribute | Value |
|-----------|-------|
| **Description** | |
| **Threat Actor** | |
| **Severity** | Critical / High / Medium / Low |
| **Likelihood** | High / Medium / Low |
| **Impact** | |
| **Prerequisites** | |
| **Attack Steps** | 1. <br>2. <br>3. |
| **Mitigation** | |

### AV-2: [Attack Vector Name]

| Attribute | Value |
|-----------|-------|
| **Description** | |
| **Threat Actor** | |
| **Severity** | Critical / High / Medium / Low |
| **Likelihood** | High / Medium / Low |
| **Impact** | |
| **Prerequisites** | |
| **Attack Steps** | 1. <br>2. <br>3. |
| **Mitigation** | |

<!-- Add more attack vectors as needed. Copy the template above for each. -->

---

## Mitigations

<!-- Map each attack vector to its mitigations. A single mitigation may address multiple attack vectors. Organize by mitigation strategy. -->

### M-1: [Mitigation Name]

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-1, AV-3 |
| **Description** | |
| **Implementation** | |
| **Verification** | How do we verify this mitigation is effective? (e.g., code review, fuzz testing, penetration testing) |
| **Status** | Implemented / Planned / Future |

### M-2: [Mitigation Name]

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-2 |
| **Description** | |
| **Implementation** | |
| **Verification** | |
| **Status** | Implemented / Planned / Future |

<!-- Add more mitigations as needed. -->

---

## Residual Risks

<!-- After all mitigations are applied, what risks remain? These are risks that we accept because:
- The mitigation is too expensive relative to the risk
- The threat is outside our threat model
- No practical mitigation exists

For each residual risk, document:
- What the risk is
- Why we accept it
- What could change that would require revisiting this decision
-->

| Risk | Severity | Justification for Acceptance | Revisit Trigger |
|------|----------|------------------------------|-----------------|
| | | | |

---

## Security Requirements

<!-- List the concrete, testable security requirements that this feature must satisfy. These should be derived from the mitigations above. Each requirement should be verifiable through testing, code review, or automated checks.

Format: "The [feature] SHALL [requirement]" for mandatory requirements,
       "The [feature] SHOULD [requirement]" for recommended requirements.
-->

### Mandatory Requirements (SHALL)

1. The [feature] SHALL [requirement]
2. The [feature] SHALL [requirement]

### Recommended Requirements (SHOULD)

1. The [feature] SHOULD [requirement]
2. The [feature] SHOULD [requirement]

---

## Monitoring & Detection

<!-- How will we detect if this feature is being attacked or has been compromised? Include:
- Audit events that should be generated
- Anomalies to watch for
- Alerts that should be configured
- Logging requirements
-->

### Audit Events

| Event | Category | Action | Trigger | Metadata |
|-------|----------|--------|---------|----------|
| | | | | |

### Anomaly Detection

| Anomaly | Detection Method | Alert Threshold | Response |
|---------|-----------------|-----------------|----------|
| | | | |

### Logging Requirements

<!-- What must be logged? What must NOT be logged? -->

**Must log:**
-

**Must NOT log:**
- Passwords (plaintext or encrypted)
- Cryptographic keys
- Decrypted vault data
- Session tokens that could be replayed

---

## Review History

| Date | Reviewer | Result | Notes |
|------|----------|--------|-------|
| | | Approved / Changes Required | |

---

## Appendix: Threat Modeling Methodology

This threat model follows a simplified STRIDE methodology:

| STRIDE Category | Description | Example in KESTREL Vault Context |
|----------------|-------------|--------------------------------|
| **S**poofing | Pretending to be another entity | Malware impersonating the vault process |
| **T**ampering | Modifying data or code | Modifying encrypted entries in the database |
| **R**epudiation | Denying an action was performed | Deleting audit events to cover tracks |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Leaking passwords through memory dumps |
| **D**enial of Service | Making the system unavailable | Brute-force lockout exhaustion |
| **E**levation of Privilege | Gaining unauthorized access levels | Exploiting IPC to extract keys |

Each attack vector should be analyzed against all applicable STRIDE categories.
