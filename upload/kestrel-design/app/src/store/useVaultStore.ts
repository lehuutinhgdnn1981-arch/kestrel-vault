import { create } from 'zustand'

export interface VaultItem {
  id: string
  title: string
  website: string
  username: string
  password: string
  notes: string
  folder: string
  tags: string[]
  favorite: boolean
  createdAt: string
  updatedAt: string
}

export interface SecureNote {
  id: string
  title: string
  content: string
  category: string
  favorite: boolean
  createdAt: string
  updatedAt: string
}

export interface VaultFile {
  id: string
  name: string
  size: string
  type: string
  folder: string
  modified: string
  risk: 'safe' | 'warning' | 'danger'
  encrypted: boolean
  sha256: string
}

export interface AuditEvent {
  id: string
  type: string
  description: string
  timestamp: string
  hash: string
  severity: 'info' | 'success' | 'warning' | 'danger'
}

export interface VaultState {
  isUnlocked: boolean
  unlockTime: number | null
  securityScore: number
  passwordCount: number
  fileCount: number
  noteCount: number
  storageUsed: number
  storageTotal: number
  autoLockMinutes: number
  lastScan: string | null
  selectedVaultItem: string | null
  selectedFile: string | null
  selectedNote: string | null
  vaultItems: VaultItem[]
  secureNotes: SecureNote[]
  files: VaultFile[]
  auditLogs: AuditEvent[]

  setUnlocked: (unlocked: boolean) => void
  setSelectedVaultItem: (id: string | null) => void
  setSelectedFile: (id: string | null) => void
  setSelectedNote: (id: string | null) => void
  addVaultItem: (item: VaultItem) => void
  addNote: (note: SecureNote) => void
  addFile: (file: VaultFile) => void
  addAuditEvent: (event: AuditEvent) => void
}

const demoVaultItems: VaultItem[] = [
  { id: '1', title: 'Google', website: 'google.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'My personal Google account', folder: 'Work', tags: ['work', 'email'], favorite: true, createdAt: '2024-05-15T10:00:00Z', updatedAt: '2024-05-20T10:32:00Z' },
  { id: '2', title: 'Facebook', website: 'facebook.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'Social media account', folder: 'Social', tags: ['social'], favorite: false, createdAt: '2024-05-10T08:00:00Z', updatedAt: '2024-05-18T14:00:00Z' },
  { id: '3', title: 'GitHub', website: 'github.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'Code repository access', folder: 'Work', tags: ['dev', 'work'], favorite: true, createdAt: '2024-04-20T09:00:00Z', updatedAt: '2024-05-19T11:00:00Z' },
  { id: '4', title: 'Discord', website: 'discord.com', username: 'nghia#1234', password: '••••••••••••', notes: 'Community server access', folder: 'Social', tags: ['social', 'gaming'], favorite: false, createdAt: '2024-05-01T12:00:00Z', updatedAt: '2024-05-15T16:00:00Z' },
  { id: '5', title: 'Netflix', website: 'netflix.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'Streaming service', folder: 'Personal', tags: ['entertainment'], favorite: false, createdAt: '2024-03-15T20:00:00Z', updatedAt: '2024-05-10T09:00:00Z' },
  { id: '6', title: 'Spotify', website: 'spotify.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'Music streaming', folder: 'Personal', tags: ['music'], favorite: true, createdAt: '2024-04-01T10:00:00Z', updatedAt: '2024-05-12T13:00:00Z' },
  { id: '7', title: 'Twitter', website: 'twitter.com', username: 'nghia@example.com', password: '••••••••••••', notes: 'Social media', folder: 'Social', tags: ['social'], favorite: false, createdAt: '2024-02-10T15:00:00Z', updatedAt: '2024-05-08T10:00:00Z' },
  { id: '8', title: 'AWS Console', website: 'aws.amazon.com', username: 'admin@company.com', password: '••••••••••••', notes: 'Production AWS root access', folder: 'Work', tags: ['dev', 'work', 'critical'], favorite: true, createdAt: '2024-01-05T08:00:00Z', updatedAt: '2024-05-20T08:00:00Z' },
]

const demoNotes: SecureNote[] = [
  { id: '1', title: 'Server Credentials', content: '# Production Server\n\n**IP:** 192.168.1.100\n**User:** admin\n**Password:** [REDACTED]\n\n## Database\n**Host:** db.production.com\n**User:** db_admin\n**Password:** [REDACTED]', category: 'Infrastructure', favorite: true, createdAt: '2024-05-20T10:35:00Z', updatedAt: '2024-05-20T10:35:00Z' },
  { id: '2', title: 'API Keys', content: '# API Keys\n\n**Stripe:** sk_live_51H...\n**SendGrid:** SG.xxx...\n**Twilio:** ACxxx...', category: 'Development', favorite: false, createdAt: '2024-05-19T14:00:00Z', updatedAt: '2024-05-19T14:00:00Z' },
  { id: '3', title: 'Secure Backup Codes', content: '# Backup Codes\n\n1. 8472 9103\n2. 5634 7821\n3. 1298 4567\n4. 3456 7890\n5. 6789 0123', category: 'Security', favorite: true, createdAt: '2024-05-18T09:00:00Z', updatedAt: '2024-05-18T09:00:00Z' },
  { id: '4', title: 'WiFi Passwords', content: '# WiFi Networks\n\n**Home Network:** SecureHome2024!\n**Office Guest:** GuestAccess2024\n**Lab Network:** LabSecure#99', category: 'Personal', favorite: false, createdAt: '2024-05-17T16:00:00Z', updatedAt: '2024-05-17T16:00:00Z' },
  { id: '5', title: 'Private Thoughts', content: 'Remember to rotate the AWS access keys next week. Also need to update the backup strategy for the new database cluster.', category: 'Personal', favorite: false, createdAt: '2024-05-15T20:00:00Z', updatedAt: '2024-05-15T20:00:00Z' },
  { id: '6', title: 'Meeting Notes', content: '# Sprint Planning\n\n- Update security policies\n- Review access logs\n- Penetration testing scheduled for June\n- New hire onboarding checklist', category: 'Work', favorite: false, createdAt: '2024-05-14T10:00:00Z', updatedAt: '2024-05-14T10:00:00Z' },
]

const demoFiles: VaultFile[] = [
  { id: '1', name: 'report.pdf', size: '2.1 MB', type: 'PDF', folder: 'Documents', modified: '2 min ago', risk: 'safe', encrypted: true, sha256: 'a1b2c3d4e5f6789012345678901234567890abcd' },
  { id: '2', name: 'design-system.fig', size: '18.6 MB', type: 'FIG', folder: 'Documents', modified: '1 hour ago', risk: 'safe', encrypted: true, sha256: 'b2c3d4e5f6789012345678901234567890abcdef' },
  { id: '3', name: 'photo.jpg', size: '3.4 MB', type: 'JPG', folder: 'Images', modified: '2 hours ago', risk: 'safe', encrypted: true, sha256: 'c3d4e5f6789012345678901234567890abcdef01' },
  { id: '4', name: 'backup.zip', size: '512 MB', type: 'ZIP', folder: 'Archives', modified: '1 day ago', risk: 'safe', encrypted: true, sha256: 'd4e5f6789012345678901234567890abcdef0123' },
  { id: '5', name: 'invoice-2024.pdf', size: '1.2 MB', type: 'PDF', folder: 'Documents', modified: '2 days ago', risk: 'safe', encrypted: true, sha256: 'e5f6789012345678901234567890abcdef012345' },
  { id: '6', name: 'diagram.png', size: '1.8 MB', type: 'PNG', folder: 'Images', modified: '3 days ago', risk: 'safe', encrypted: true, sha256: 'f6789012345678901234567890abcdef01234567' },
  { id: '7', name: 'data-export.csv', size: '956 KB', type: 'CSV', folder: 'Documents', modified: '3 days ago', risk: 'safe', encrypted: true, sha256: '6789012345678901234567890abcdef012345678' },
  { id: '8', name: 'presentation.pptx', size: '12.4 MB', type: 'PPTX', folder: 'Documents', modified: '4 days ago', risk: 'safe', encrypted: true, sha256: '789012345678901234567890abcdef0123456789' },
]

const demoAuditLogs: AuditEvent[] = [
  { id: '1', type: 'unlock', description: 'Unlocked vault', timestamp: '2024-05-20T10:30:00Z', hash: 'a1b2c3d4e5f6', severity: 'success' },
  { id: '2', type: 'password_added', description: 'Added password for Google', timestamp: '2024-05-20T10:32:00Z', hash: 'b2c3d4e5f6g7', severity: 'info' },
  { id: '3', type: 'file_uploaded', description: 'Uploaded file report.pdf', timestamp: '2024-05-20T10:35:00Z', hash: 'c3d4e5f6g7h8', severity: 'info' },
  { id: '4', type: 'lock', description: 'Locked vault', timestamp: '2024-05-20T09:15:00Z', hash: 'd4e5f6g7h8i9', severity: 'success' },
  { id: '5', type: 'scan', description: 'Security scan completed — No threats found', timestamp: '2024-05-20T09:00:00Z', hash: 'e5f6g7h8i9j0', severity: 'success' },
  { id: '6', type: 'backup', description: 'Exported backup — Size: 156 MB', timestamp: '2024-05-20T08:45:00Z', hash: 'f6g7h8i9j0k1', severity: 'info' },
  { id: '7', type: 'password_deleted', description: 'Deleted password for Old Account', timestamp: '2024-05-19T16:00:00Z', hash: 'g7h8i9j0k1l2', severity: 'warning' },
  { id: '8', type: 'settings_changed', description: 'Changed auto-lock settings', timestamp: '2024-05-19T14:30:00Z', hash: 'h8i9j0k1l2m3', severity: 'info' },
  { id: '9', type: 'unlock', description: 'Unlocked vault', timestamp: '2024-05-19T08:00:00Z', hash: 'i9j0k1l2m3n4', severity: 'success' },
  { id: '10', type: 'scan', description: 'Security scan completed — No threats found', timestamp: '2024-05-18T22:00:00Z', hash: 'j0k1l2m3n4o5', severity: 'success' },
  { id: '11', type: 'file_uploaded', description: 'Uploaded file backup.zip', timestamp: '2024-05-18T20:00:00Z', hash: 'k1l2m3n4o5p6', severity: 'info' },
  { id: '12', type: 'password_added', description: 'Added password for AWS Console', timestamp: '2024-05-18T10:00:00Z', hash: 'l2m3n4o5p6q7', severity: 'info' },
]

export const useVaultStore = create<VaultState>((set) => ({
  isUnlocked: false,
  unlockTime: null,
  securityScore: 87,
  passwordCount: 342,
  fileCount: 21,
  noteCount: 12,
  storageUsed: 2.46,
  storageTotal: 10,
  autoLockMinutes: 5,
  lastScan: '2024-05-20T10:30:00Z',
  selectedVaultItem: null,
  selectedFile: null,
  selectedNote: null,
  vaultItems: demoVaultItems,
  secureNotes: demoNotes,
  files: demoFiles,
  auditLogs: demoAuditLogs,

  setUnlocked: (unlocked: boolean) => set({ isUnlocked: unlocked, unlockTime: unlocked ? Date.now() : null }),
  setSelectedVaultItem: (id: string | null) => set({ selectedVaultItem: id }),
  setSelectedFile: (id: string | null) => set({ selectedFile: id }),
  setSelectedNote: (id: string | null) => set({ selectedNote: id }),
  addVaultItem: (item: VaultItem) => set((state: VaultState) => ({ vaultItems: [item, ...state.vaultItems], passwordCount: state.passwordCount + 1 })),
  addNote: (note: SecureNote) => set((state: VaultState) => ({ secureNotes: [note, ...state.secureNotes], noteCount: state.noteCount + 1 })),
  addFile: (file: VaultFile) => set((state: VaultState) => ({ files: [file, ...state.files], fileCount: state.fileCount + 1 })),
  addAuditEvent: (event: AuditEvent) => set((state: VaultState) => ({ auditLogs: [event, ...state.auditLogs] })),
}))
