import { useState, useEffect, useCallback } from 'react'
import {
  Search,
  Plus,
  List,
  FolderIcon,
  Inbox,
  Copy,
  Eye,
  EyeOff,
  Pencil,
  Trash2,
  ChevronDown,
  X,
  Wand2,
  Shield,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
} from 'lucide-react'
import { useVaultStore } from '@/stores/vault-store'
import { useAuthStore } from '@/stores/auth-store'
import { vaultCommands, folderCommands, scannerCommands, type PasswordStrengthResult } from '@/lib/tauri'
import { staggerStyle } from '@/hooks/use-stagger'
import { useI18n } from '@/hooks/use-i18n'

// ─── Favicon Helper ─────────────────────────────────────────────────
function getFaviconUrl(url: string | null): string | null {
  if (!url) return null
  try {
    let domain = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim()
    if (!domain) return null
    // Use Google's favicon service to fetch website logos
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`
  } catch {
    return null
  }
}

const avatarColors: Record<string, string> = {
  Google: '#4285F4', Facebook: '#1877F2', GitHub: '#333333', Discord: '#5865F2',
  Netflix: '#E50914', Spotify: '#1DB954', Twitter: '#1DA1F2', 'AWS Console': '#FF9900',
}

// ─── Password Generator ─────────────────────────────────────────────
function generateStrongPassword(length: number = 20): string {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz'
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const numbers = '0123456789'
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
  const allChars = lowercase + uppercase + numbers + symbols

  // Ensure at least one of each category
  let password = ''
  password += lowercase[Math.floor(Math.random() * lowercase.length)]
  password += uppercase[Math.floor(Math.random() * uppercase.length)]
  password += numbers[Math.floor(Math.random() * numbers.length)]
  password += symbols[Math.floor(Math.random() * symbols.length)]

  // Fill the rest randomly
  for (let i = password.length; i < length; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)]
  }

  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('')
}

// ─── Password Strength Indicator Component ──────────────────────────
function PasswordStrengthIndicator({ strength }: { strength: PasswordStrengthResult | null }) {
  if (!strength) return null

  const getBarColor = (score: number) => {
    if (score <= 1) return 'var(--kestrel-danger)'  // Red - Very Weak / Weak
    if (score === 2) return 'var(--kestrel-warning)'  // Yellow - Fair
    if (score === 3) return 'var(--kestrel-primary)'  // Blue - Strong
    return 'var(--kestrel-success)'                    // Green - Very Strong
  }

  const barColor = getBarColor(strength.score)

  return (
    <div className="mt-1.5 space-y-1.5">
      <div className="flex items-center gap-2">
        <div className="flex-1 flex gap-1">
          {[0, 1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-1.5 flex-1 rounded-full transition-all duration-300"
              style={{
                backgroundColor: i <= strength.score ? barColor : 'var(--kestrel-disabled-bg)',
              }}
            />
          ))}
        </div>
        <span className="text-xs font-medium" style={{ color: barColor }}>
          {strength.label}
        </span>
      </div>
      {strength.warnings.length > 0 && (
        <div className="space-y-0.5">
          {strength.warnings.slice(0, 2).map((w, i) => (
            <p key={i} className="text-xs flex items-start gap-1" style={{ color: 'var(--kestrel-danger)' }}>
              <AlertTriangle size={10} className="mt-0.5 flex-shrink-0" /> {w}
            </p>
          ))}
        </div>
      )}
      {strength.suggestions.length > 0 && (
        <div className="space-y-0.5">
          {strength.suggestions.slice(0, 2).map((s, i) => (
            <p key={i} className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{s}</p>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Website Logo Component ─────────────────────────────────────────
function WebsiteLogo({ url, title, size = 36 }: { url: string | null; title: string; size?: number }) {
  const [imgError, setImgError] = useState(false)
  const faviconUrl = getFaviconUrl(url)
  const color = avatarColors[title] || 'var(--kestrel-text-muted)'

  // Reset error state when URL changes
  useEffect(() => {
    setImgError(false)
  }, [url])

  if (faviconUrl && !imgError) {
    return (
      <div
        className="rounded-full flex items-center justify-center flex-shrink-0 overflow-hidden"
        style={{ width: size, height: size, backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)' }}
      >
        <img
          src={faviconUrl}
          alt=""
          className="object-contain"
          style={{ width: Math.round(size * 0.6), height: Math.round(size * 0.6) }}
          onError={() => setImgError(true)}
        />
      </div>
    )
  }

  // Fallback: colored circle with first letter
  return (
    <div
      className="rounded-full flex items-center justify-center text-white font-semibold flex-shrink-0"
      style={{
        width: size,
        height: size,
        backgroundColor: color,
        fontSize: Math.round(size * 0.38),
      }}
    >
      {title[0]}
    </div>
  )
}

// ─── Breach Check via Rust Backend (HIBP API) ────────────────────────
//
// The breach check is now handled by the Rust backend:
// 1. Frontend calls scannerCommands.checkEntryBreach(entryId)
// 2. Rust reveals the password from the encrypted vault
// 3. Rust SHA-1 hashes it locally
// 4. Rust sends only the first 5 chars of the hash to HIBP API (k-anonymity)
// 5. HIBP returns matching hash suffixes + counts
// 6. Rust checks locally and returns the result
//
// Privacy: The full password and full hash NEVER leave the device.
// The API call is made from Rust (not blocked by CSP).

interface BreachCheckState {
  status: 'idle' | 'checking' | 'safe' | 'breached' | 'error'
  count?: number
  errorMessage?: string
}

function BreachCheckResult({ entryId, t }: { entryId: string; t: (key: any, params?: Record<string, string | number>) => string }) {
  const [state, setState] = useState<BreachCheckState>({ status: 'idle' })

  const handleCheck = async () => {
    setState({ status: 'checking' })
    try {
      const result = await scannerCommands.checkEntryBreach(entryId)
      if (result.is_breached) {
        setState({ status: 'breached', count: result.occurrence_count })
      } else {
        setState({ status: 'safe' })
      }
    } catch (err) {
      console.error('Breach check failed:', err)
      const msg = err instanceof Error ? err.message : 'Unknown error'
      setState({ status: 'error', errorMessage: msg })
    }
  }

  const getStyles = () => {
    switch (state.status) {
      case 'breached':
        return { bg: 'var(--kestrel-danger-subtle)', color: 'var(--kestrel-danger)', border: 'rgba(239,68,68,0.3)' }
      case 'safe':
        return { bg: 'var(--kestrel-success-subtle)', color: 'var(--kestrel-success)', border: 'rgba(34,197,94,0.3)' }
      case 'error':
        return { bg: 'var(--kestrel-warning-subtle)', color: 'var(--kestrel-warning)', border: 'rgba(245,158,11,0.3)' }
      default:
        return { bg: 'var(--kestrel-hover-bg)', color: 'var(--kestrel-text-muted)', border: 'var(--kestrel-border)' }
    }
  }

  const styles = getStyles()

  return (
    <div className="space-y-2">
      <button
        onClick={handleCheck}
        disabled={state.status === 'checking'}
        className="flex items-center gap-1.5 px-3 h-8 rounded-lg text-xs font-medium transition-colors"
        style={{
          backgroundColor: styles.bg,
          color: styles.color,
          border: `1px solid ${styles.border}`,
        }}
      >
        {state.status === 'checking' ? (
          <RefreshCw size={13} className="animate-spin" />
        ) : state.status === 'safe' ? (
          <CheckCircle size={13} />
        ) : state.status === 'breached' ? (
          <AlertTriangle size={13} />
        ) : (
          <Shield size={13} />
        )}
        {state.status === 'checking'
          ? t('vault.checkingHibp')
          : state.status === 'safe'
            ? t('vault.safeNotBreached')
            : state.status === 'breached'
              ? t('vault.breachedFound', { count: state.count?.toLocaleString() ?? '0' })
              : state.status === 'error'
                ? t('vault.checkFailedRetry')
                : t('vault.checkHibp')}
      </button>

      {state.status === 'breached' && (
        <div className="p-3 rounded-lg" style={{ backgroundColor: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)' }}>
          <p className="text-xs font-medium" style={{ color: 'var(--kestrel-danger)' }}>
            {t('vault.breachWarning', { count: state.count?.toLocaleString() ?? '0' })}
          </p>
          <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-muted)' }}>
            {t('vault.changeImmediately')}
          </p>
        </div>
      )}

      {state.status === 'safe' && (
        <p className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
          {t('vault.safeNoBreach')}
        </p>
      )}

      {state.status === 'error' && state.errorMessage && (
        <p className="text-xs" style={{ color: 'var(--kestrel-warning)' }}>
          {state.errorMessage}
        </p>
      )}

      {state.status === 'idle' && (
        <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
          {t('vault.hibpDescription')}
        </p>
      )}
    </div>
  )
}

// ─── Main Component ─────────────────────────────────────────────────
export default function PasswordVault() {
  const entries = useVaultStore((s) => s.entries)
  const fetchEntries = useVaultStore((s) => s.fetchEntries)
  const deleteEntry = useVaultStore((s) => s.deleteEntry)
  const selectedEntryId = useVaultStore((s) => s.selectedEntryId)
  const selectEntry = useVaultStore((s) => s.selectEntry)
  const folders = useVaultStore((s) => s.folders)
  const fetchFolders = useVaultStore((s) => s.fetchFolders)
  const appState = useAuthStore((s) => s.appState)
  const { t } = useI18n()

  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [revealedPassword, setRevealedPassword] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  // Add Item dialog state
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [newNotes, setNewNotes] = useState('')
  const [newFolderId, setNewFolderId] = useState<string | null>(null)
  const [isAdding, setIsAdding] = useState(false)

  // Password strength state for Add dialog
  const [newPasswordStrength, setNewPasswordStrength] = useState<PasswordStrengthResult | null>(null)
  const [newPasswordVisible, setNewPasswordVisible] = useState(false)

  // Edit mode state
  const [editMode, setEditMode] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editUsername, setEditUsername] = useState('')
  const [editPassword, setEditPassword] = useState('')
  const [editUrl, setEditUrl] = useState('')
  const [editNotes, setEditNotes] = useState('')
  const [editFolderId, setEditFolderId] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState(false)

  // Password strength state for Edit dialog
  const [editPasswordStrength, setEditPasswordStrength] = useState<PasswordStrengthResult | null>(null)
  const [editPasswordVisible, setEditPasswordVisible] = useState(false)

  useEffect(() => {
    if (appState === 'unlocked') {
      fetchEntries()
      fetchFolders()
    }
  }, [appState, fetchEntries, fetchFolders])

  // Reset edit mode when selected entry changes
  useEffect(() => {
    setEditMode(false)
    setRevealedPassword(null)
  }, [selectedEntryId])

  // ── Real-time password strength check for Add dialog ──
  useEffect(() => {
    if (!newPassword) {
      setNewPasswordStrength(null)
      return
    }
    const timer = setTimeout(async () => {
      try {
        const result = await scannerCommands.getPasswordStrength(newPassword)
        setNewPasswordStrength(result)
      } catch {
        setNewPasswordStrength(null)
      }
    }, 300) // Debounce 300ms
    return () => clearTimeout(timer)
  }, [newPassword])

  // ── Real-time password strength check for Edit dialog ──
  useEffect(() => {
    if (!editPassword) {
      setEditPasswordStrength(null)
      return
    }
    const timer = setTimeout(async () => {
      try {
        const result = await scannerCommands.getPasswordStrength(editPassword)
        setEditPasswordStrength(result)
      } catch {
        setEditPasswordStrength(null)
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [editPassword])

  // When opening the Add dialog, default folder to the current active folder
  const openAddDialog = useCallback(() => {
    if (activeFolder !== 'all' && activeFolder !== 'none') {
      setNewFolderId(activeFolder)
    } else {
      setNewFolderId(null)
    }
    setShowAddDialog(true)
  }, [activeFolder])

  const filteredItems = entries.filter((item) => {
    const matchesSearch = !searchQuery ||
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.url ?? '').toLowerCase().includes(searchQuery.toLowerCase())

    const matchesFolder = activeFolder === 'all' ||
      (activeFolder === 'none' && !item.folder_id) ||
      (activeFolder !== 'none' && item.folder_id === activeFolder)

    return matchesFolder && matchesSearch
  })

  const selectedItem = entries.find((e) => e.id === selectedEntryId) ?? null

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 1000)
    // Auto-clear clipboard after 30 seconds for security
    setTimeout(() => {
      navigator.clipboard.readText().then((current) => {
        if (current === text) {
          navigator.clipboard.writeText('').catch(() => {})
        }
      }).catch(() => {})
    }, 30000)
  }

  const handleRevealPassword = async (id: string) => {
    try {
      const result = await vaultCommands.revealPassword(id)
      setRevealedPassword(result.password)
      setTimeout(() => setRevealedPassword(null), result.auto_clear_seconds * 1000)
    } catch {
      setRevealedPassword(null)
    }
  }

  const handleDelete = async (id: string) => {
    await deleteEntry(id)
    setRevealedPassword(null)
  }

  const handleAddEntry = async () => {
    if (!newTitle.trim() || !newUsername.trim() || !newPassword.trim()) return
    setIsAdding(true)
    try {
      await vaultCommands.createEntry(
        newTitle,
        newUsername,
        newPassword,
        newUrl || undefined,
        newNotes || undefined,
        newFolderId ?? undefined,
      )
      setShowAddDialog(false)
      setNewTitle('')
      setNewUsername('')
      setNewPassword('')
      setNewUrl('')
      setNewNotes('')
      setNewFolderId(null)
      setNewPasswordStrength(null)
      setNewPasswordVisible(false)
      await fetchEntries()
    } catch {
      // Error handled gracefully
    } finally {
      setIsAdding(false)
    }
  }

  const handleStartEdit = () => {
    if (!selectedItem) return
    setEditTitle(selectedItem.title)
    setEditUsername(selectedItem.username)
    setEditPassword('')
    setEditUrl(selectedItem.url ?? '')
    setEditNotes(selectedItem.notes_preview ?? '')
    setEditFolderId(selectedItem.folder_id)
    setEditMode(true)
    setEditPasswordStrength(null)
    setEditPasswordVisible(false)
  }

  const handleSaveEdit = async () => {
    if (!selectedItem) return
    setIsSaving(true)
    try {
      const updates: {
        title?: string;
        username?: string;
        password?: string;
        url?: string;
        notes?: string;
        folderId?: string;
      } = {}
      if (editTitle !== selectedItem.title) updates.title = editTitle
      if (editUsername !== selectedItem.username) updates.username = editUsername
      if (editPassword) updates.password = editPassword
      if (editUrl !== (selectedItem.url ?? '')) updates.url = editUrl
      if (editNotes !== (selectedItem.notes_preview ?? '')) updates.notes = editNotes
      if (editFolderId !== selectedItem.folder_id) updates.folderId = editFolderId ?? undefined

      await vaultCommands.updateEntry(selectedItem.id, updates)
      setEditMode(false)
      setRevealedPassword(null)
      setEditPasswordStrength(null)
      await fetchEntries()
    } catch {
      // Error handled gracefully
    } finally {
      setIsSaving(false)
    }
  }

  const handleCreateFolder = async () => {
    const name = prompt('Enter folder name:')
    if (!name?.trim()) return
    try {
      await folderCommands.createFolder(name.trim())
      await fetchFolders()
    } catch {
      // Error handled gracefully
    }
  }

  const handleGeneratePassword = (target: 'add' | 'edit') => {
    const generated = generateStrongPassword(20)
    if (target === 'add') {
      setNewPassword(generated)
      setNewPasswordVisible(true)
    } else {
      setEditPassword(generated)
      setEditPasswordVisible(true)
    }
  }

  return (
    <div className="flex h-full">
      {/* Folder sidebar */}
      <div className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid var(--kestrel-border)', backgroundColor: 'var(--kestrel-surface)' }}>
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('vault.title')}</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }} />
            <input
              type="text"
              placeholder={t('vault.searchPasswords')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--kestrel-bg)', paddingLeft: '32px', paddingRight: '10px', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
            />
          </div>
          <button
            onClick={openAddDialog}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: 'var(--kestrel-primary)', color: 'var(--kestrel-text-on-dark)' }}>
            <Plus size={16} /> {t('vault.addItem')}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-2">
          {/* All Items */}
          <button
            onClick={() => setActiveFolder('all')}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
            style={{
              backgroundColor: activeFolder === 'all' ? 'var(--kestrel-hover-bg)' : 'transparent',
              borderLeft: activeFolder === 'all' ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
              color: activeFolder === 'all' ? 'var(--kestrel-text)' : 'var(--kestrel-text-muted)',
            }}
          >
            <List size={16} />
            <span className="text-sm flex-1">{t('vault.allItems')}</span>
          </button>

          {/* No Folder */}
          <button
            onClick={() => setActiveFolder('none')}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
            style={{
              backgroundColor: activeFolder === 'none' ? 'var(--kestrel-hover-bg)' : 'transparent',
              borderLeft: activeFolder === 'none' ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
              color: activeFolder === 'none' ? 'var(--kestrel-text)' : 'var(--kestrel-text-muted)',
            }}
          >
            <Inbox size={16} />
            <span className="text-sm flex-1">{t('vault.noFolder')}</span>
          </button>

          {/* Real folders from backend */}
          {folders.map((folder) => {
            const isActive = activeFolder === folder.id
            return (
              <button
                key={folder.id}
                onClick={() => setActiveFolder(folder.id)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
                style={{
                  backgroundColor: isActive ? 'var(--kestrel-hover-bg)' : 'transparent',
                  borderLeft: isActive ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
                  color: isActive ? 'var(--kestrel-text)' : 'var(--kestrel-text-muted)',
                }}
              >
                <FolderIcon size={16} />
                <span className="text-sm flex-1">{folder.name}</span>
                {folder.entry_count > 0 && (
                  <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{folder.entry_count}</span>
                )}
              </button>
            )
          })}
          <div className="px-3 py-2">
            <button onClick={handleCreateFolder} className="text-sm font-medium" style={{ color: 'var(--kestrel-primary)' }}>+ {t('vault.newFolder')}</button>
          </div>
        </div>

        <div className="p-4 flex items-center gap-2" style={{ borderTop: '1px solid var(--kestrel-border)' }}>
          <div className="w-5 h-5 rounded flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-sidebar)' }}>
            <img src="/kestrel-logo.png" alt="" className="w-3 h-3 object-contain" />
          </div>
          <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{entries.length} {t('vault.entries')}</span>
        </div>
      </div>

      {/* Entry list */}
      <div className="flex flex-col h-full flex-1"
        style={{ borderRight: '1px solid var(--kestrel-border)', minWidth: '320px', backgroundColor: 'var(--kestrel-surface)' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--kestrel-border)' }}>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              {activeFolder === 'all' ? t('vault.allItems') : activeFolder === 'none' ? t('vault.noFolder') : folders.find((f) => f.id === activeFolder)?.name || t('vault.allItems')}
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-border-subtle)', color: 'var(--kestrel-text-muted)' }}>
              {filteredItems.length}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-1 text-xs px-2 py-1 rounded" style={{ color: 'var(--kestrel-text-muted)', border: '1px solid var(--kestrel-border)' }}>
              {t('vault.sortByName')} <ChevronDown size={12} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center px-6">
              <Inbox size={32} style={{ color: 'var(--kestrel-text-light)' }} className="mb-3" />
              <p className="text-sm font-medium" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.noItemsFound')}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('vault.addPasswordOrSearch')}</p>
            </div>
          ) : (
            filteredItems.map((item, index) => {
              const isSelected = selectedEntryId === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => selectEntry(item.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left transition-all duration-200 animate-stagger-in"
                  style={{
                    backgroundColor: isSelected ? 'var(--kestrel-selected-bg)' : 'transparent',
                    borderLeft: isSelected ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
                    borderBottom: '1px solid var(--kestrel-border-subtle)',
                    ...staggerStyle(index),
                  }}
                >
                  <WebsiteLogo url={item.url} title={item.title} size={36} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate" style={{ color: 'var(--kestrel-text)' }}>{item.title}</div>
                    <div className="text-xs truncate" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{item.username}</div>
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* Detail panel */}
      <div className="flex flex-col h-full" style={{ width: '380px', backgroundColor: 'var(--kestrel-surface)' }}>
        {!selectedItem ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <img src="/kestrel-logo.png" alt="" className="w-12 h-12 object-contain mb-3 opacity-30" />
            <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('vault.selectEntry')}</p>
          </div>
        ) : editMode ? (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-5" style={{ borderBottom: '1px solid var(--kestrel-border)' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('vault.editEntry')}</h3>
                <div className="flex items-center gap-1">
                  <button onClick={handleSaveEdit} disabled={isSaving}
                    className="px-3 h-8 rounded-lg text-xs font-medium transition-colors"
                    style={{ backgroundColor: 'var(--kestrel-primary)', color: 'var(--kestrel-text-on-dark)', opacity: isSaving ? 0.6 : 1 }}>
                    {isSaving ? t('vault.saving') : t('vault.save')}
                  </button>
                  <button onClick={() => setEditMode(false)}
                    className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                    <X size={15} />
                  </button>
                </div>
              </div>
            </div>

            <div className="p-5 space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Title</label>
                <input type="text" value={editTitle} onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Username</label>
                <input type="text" value={editUsername} onChange={(e) => setEditUsername(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Password</label>
                <div className="flex items-center gap-1">
                  <div className="flex-1 relative">
                    <input
                      type={editPasswordVisible ? 'text' : 'password'}
                      value={editPassword}
                      onChange={(e) => setEditPassword(e.target.value)}
                      placeholder={t('vault.leaveBlankPassword')}
                      className="w-full h-9 rounded-lg text-sm outline-none px-3 pr-8"
                      style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
                    />
                    <button
                      type="button"
                      onClick={() => setEditPasswordVisible(!editPasswordVisible)}
                      className="absolute right-2 top-1/2 -translate-y-1/2"
                      style={{ color: 'var(--kestrel-text-on-dark-muted)' }}
                    >
                      {editPasswordVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleGeneratePassword('edit')}
                    className="h-9 px-2.5 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors flex-shrink-0"
                    style={{ backgroundColor: 'var(--kestrel-primary-subtle)', color: 'var(--kestrel-primary)', border: '1px solid rgba(37,99,235,0.2)' }}
                    title="Generate strong password"
                  >
                    <Wand2 size={13} /> {t('vault.generate')}
                  </button>
                </div>
                <PasswordStrengthIndicator strength={editPasswordStrength} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.website')}</label>
                <input type="text" value={editUrl} onChange={(e) => setEditUrl(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.folder')}</label>
                <select
                  value={editFolderId ?? ''}
                  onChange={(e) => setEditFolderId(e.target.value || null)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
                >
                  <option value="">{t('vault.noFolder')}</option>
                  {folders.map((f) => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  ))}
                </select>
              </div>
              <div>
<label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.notes_field')}</label>
                <textarea value={editNotes} onChange={(e) => setEditNotes(e.target.value)}
                  className="w-full h-20 rounded-lg text-sm outline-none p-3 resize-none"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-5" style={{ borderBottom: '1px solid var(--kestrel-border)' }}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <WebsiteLogo url={selectedItem.url} title={selectedItem.title} size={48} />
                  <div>
                    <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{selectedItem.title}</h3>
                    <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{selectedItem.url ?? t('vault.noWebsite')}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button onClick={handleStartEdit} className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                    <Pencil size={15} />
                  </button>
                  <button onClick={() => handleDelete(selectedItem.id)} className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            </div>

            <div className="p-5 space-y-5">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.username')}</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm flex-1" style={{ color: 'var(--kestrel-text)' }}>{selectedItem.username}</span>
                  <button onClick={() => handleCopy(selectedItem.username, 'username')}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                    {copiedField === 'username' ? <span className="text-xs text-green-600">{t('vault.copied')}</span> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.password_field')}</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm flex-1" style={{ color: 'var(--kestrel-text)' }}>
                    {revealedPassword ?? '••••••••••••'}
                  </span>
                  <button onClick={() => handleRevealPassword(selectedItem.id)}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                    {revealedPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  {revealedPassword && (
                    <button onClick={() => handleCopy(revealedPassword, 'password')}
                      className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: 'var(--kestrel-text-muted)' }}>
                      {copiedField === 'password' ? <span className="text-xs text-green-600">{t('vault.copied')}</span> : <Copy size={14} />}
                    </button>
                  )}
                </div>
              </div>

              {selectedItem.url && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.website')}</label>
                  <div className="flex items-center gap-2">
                    <a href={`https://${selectedItem.url}`} target="_blank" rel="noopener noreferrer"
                      className="text-sm hover:underline flex-1" style={{ color: 'var(--kestrel-primary)' }}>
                      {selectedItem.url}
                    </a>
                  </div>
                </div>
              )}

              {selectedItem.folder_id && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.folder')}</label>
                  <div className="flex items-center gap-2">
                    <FolderIcon size={14} style={{ color: 'var(--kestrel-text-muted)' }} />
                    <span className="text-sm" style={{ color: 'var(--kestrel-text)' }}>
                      {folders.find((f) => f.id === selectedItem.folder_id)?.name ?? 'Unknown'}
                    </span>
                  </div>
                </div>
              )}

              {selectedItem.notes_preview && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.notes_field')}</label>
                  <p className="text-sm" style={{ color: 'var(--kestrel-text-secondary)' }}>{selectedItem.notes_preview}</p>
                </div>
              )}

              {/* Breach Check Section */}
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.securityCheck')}</label>
                <BreachCheckResult entryId={selectedItem.id} t={t} />
              </div>
            </div>

            <div className="mt-auto p-5" style={{ borderTop: '1px solid var(--kestrel-border)' }}>
              <div className="space-y-1">
                <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('vault.created')} {new Date(selectedItem.created_at).toLocaleDateString()}</p>
                <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('vault.updated')} {new Date(selectedItem.updated_at).toLocaleDateString()}</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Item Dialog */}
      {showAddDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-overlay)' }}>
          <div className="rounded-xl p-6 w-full max-w-md max-h-[90vh] overflow-y-auto" style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-dropdown)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('vault.addNewItem')}</h3>
              <button onClick={() => { setShowAddDialog(false); setNewPasswordStrength(null); setNewPasswordVisible(false) }} className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: 'var(--kestrel-text-muted)' }}>
                <X size={16} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.titleRequired')}</label>
                <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Google"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.usernameRequired')}</label>
                <input type="text" value={newUsername} onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. user@example.com"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('vault.passwordRequired')}</label>
                <div className="flex items-center gap-1">
                  <div className="flex-1 relative">
                    <input
                      type={newPasswordVisible ? 'text' : 'password'}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder={t('vault.enterPassword')}
                      className="w-full h-9 rounded-lg text-sm outline-none px-3 pr-8"
                      style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
                    />
                    <button
                      type="button"
                      onClick={() => setNewPasswordVisible(!newPasswordVisible)}
                      className="absolute right-2 top-1/2 -translate-y-1/2"
                      style={{ color: 'var(--kestrel-text-on-dark-muted)' }}
                    >
                      {newPasswordVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleGeneratePassword('add')}
                    className="h-9 px-2.5 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors flex-shrink-0"
                    style={{ backgroundColor: 'var(--kestrel-primary-subtle)', color: 'var(--kestrel-primary)', border: '1px solid rgba(37,99,235,0.2)' }}
                    title="Generate strong password"
                  >
                    <Wand2 size={13} /> Generate
                  </button>
                </div>
                <PasswordStrengthIndicator strength={newPasswordStrength} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Website</label>
                <input type="text" value={newUrl} onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="e.g. google.com"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Folder</label>
                <select
                  value={newFolderId ?? ''}
                  onChange={(e) => setNewFolderId(e.target.value || null)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
                >
                  <option value="">{t('vault.noFolder')}</option>
                  {folders.map((f) => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>Notes</label>
                <textarea value={newNotes} onChange={(e) => setNewNotes(e.target.value)}
                  placeholder="Optional notes"
                  className="w-full h-20 rounded-lg text-sm outline-none p-3 resize-none"
                  style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 mt-6">
              <button onClick={() => { setShowAddDialog(false); setNewPasswordStrength(null); setNewPasswordVisible(false) }}
                className="px-4 h-9 rounded-lg text-sm font-medium"
                style={{ backgroundColor: 'var(--kestrel-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}>
                Cancel
              </button>
              <button onClick={handleAddEntry} disabled={isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim()}
                className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                style={{
                  backgroundColor: isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim() ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)',
                  color: isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim() ? 'var(--kestrel-disabled-text)' : 'var(--kestrel-text-on-dark)',
                }}>
                {isAdding ? t('vault.adding') : t('vault.addItem')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
