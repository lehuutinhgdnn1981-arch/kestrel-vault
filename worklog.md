---
Task ID: 1
Agent: main
Task: Integrate UI/UX design from compressed file into Kestrel Vault project

Work Log:
- Extracted and analyzed UI/UX design from /home/z/my-project/upload/kestrel-design/app/
- Design has 9 pages: UnlockScreen, Dashboard, PasswordVault, FileVault, SecureNotes, SecurityCenter, ThreatScanner, AuditLogs, Settings
- Design uses single useVaultStore with demo data; existing project uses auth-store + vault-store + note-store with Tauri backend
- Updated Layout.tsx: Added storage usage bar, password/notes count in sidebar
- Updated PasswordVault.tsx: Added folder sidebar with categories (All/Social/Work/Finance/Personal/No Folder), avatar colors per service (Google=#4285F4, etc.), sort button, new folder button
- Updated SecureNotes.tsx: Added markdown render/preview split view with Editor + Preview panes, renderMarkdown function for basic markdown rendering
- Updated FileVault.tsx: Replaced "coming soon" placeholder with full 3-column layout (folder sidebar + file list with grid layout + detail panel with SHA256, copy, decrypt button)
- Updated SecurityCenter.tsx: Added "Update old passwords" issue with ClockIcon, "Old Items (>1 year)" metric, search bar, "View all" button
- Updated ThreatScanner.tsx: Added pulse animation on scan hero, Scan Settings button, more scan history entries, "View all" button
- Updated AuditLogs.tsx: Added per-event type icons (Unlock/Lock/Plus/Trash2/Upload/Download/Settings), hash copy with CheckCircle feedback, severity-based icons, more event type filters, demo data fallback
- Updated Settings.tsx: Added Language selector, backup location with Browse button, lock on window blur toggle, reset settings button, "Last changed" for master password, Edit buttons for KDF params, version build info
- Updated Dashboard.tsx: Added notification bell with red dot, recent activity with colored icons, storage usage bar section, Upload File button, full activity descriptions

Stage Summary:
- All 9 pages updated with enhanced UI/UX from design while preserving existing Tauri backend integration
- Existing store architecture (auth-store, vault-store, note-store) preserved - no store changes needed
- react-router-dom v6 imports preserved (not v7)
- FileVault now has full 3-column layout instead of "coming soon" placeholder
- SecureNotes now has Editor + Preview markdown split view
- AuditLogs has fallback demo data when Tauri backend fails
