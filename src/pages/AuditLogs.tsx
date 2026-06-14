import { useState, useEffect } from 'react'
import {
  Search,
  CheckCircle,
  Copy,
  Lock,
  Unlock,
  Plus,
  Trash2,
  Upload,
  ShieldCheck,
  Download,
  Settings,
  FileText,
  FolderPlus,
  Eye,
  Edit3,
  RefreshCw,
  AlertTriangle,
  Key,
  Database,
} from 'lucide-react'
import { auditCommands } from '@/lib/tauri'
import { staggerStyle } from '@/hooks/use-stagger'
import { useI18n } from '@/hooks/use-i18n'

interface AuditEventLocal {
  id: string
  /** Composite type derived from category+action, used for filtering and icons */
  type: string
  description: string
  timestamp: string
  category: string
  action: string
  subject: string
  hash: string
}

// ─── Composite type mapping: (category, action) → display type ───
// This maps the backend's (category, action) pairs to frontend display types
function mapEventType(category: string, action: string): string {
  const cat = category.toLowerCase()
  const act = action.toLowerCase()

  // Auth events
  if (cat === 'auth') {
    if (act.includes('unlock') || act === 'loginsucceeded') return 'unlock'
    if (act.includes('lock') || act === 'vaultlocked') return 'lock'
    if (act.includes('fail') || act.includes('violation') || act === 'loginfailed') return 'auth_failed'
    if (act.includes('init')) return 'vault_init'
    return 'auth_other'
  }

  // Vault entry events
  if (cat === 'vault') {
    if (act.includes('entrycreated') || act === 'create') return 'password_added'
    if (act.includes('entryupdated') || act === 'update') return 'password_updated'
    if (act.includes('entrydeleted') || act === 'delete') return 'password_deleted'
    if (act.includes('passwordrevealed') || act === 'read') return 'password_revealed'
    if (act.includes('foldercreated')) return 'folder_created'
    if (act.includes('folderdeleted')) return 'folder_deleted'
    if (act.includes('export') || act === 'vaultexported') return 'backup_export'
    if (act.includes('import') || act === 'vaultimported') return 'backup_import'
    if (act.includes('clear') || act === 'vaultcleared') return 'vault_cleared'
    if (act.includes('backup') || act === 'backupcreated') return 'backup_created'
    return 'vault_other'
  }

  // Notes events
  if (cat === 'notes') {
    if (act.includes('created')) return 'note_created'
    if (act.includes('updated')) return 'note_updated'
    if (act.includes('deleted')) return 'note_deleted'
    if (act.includes('revealed')) return 'note_revealed'
    return 'notes_other'
  }

  // Settings events
  if (cat === 'settings') {
    if (act.includes('changed')) return 'settings_changed'
    if (act.includes('reset')) return 'settings_reset'
    return 'settings_other'
  }

  // Audit / System events
  if (cat === 'audit') return 'audit_export'
  if (cat === 'security') return 'security_event'
  if (cat === 'system') return 'system_event'

  // Scanner events
  if (cat === 'scanner' || act.includes('scan')) return 'scan'

  return 'other'
}

// ─── Event type filter definitions ───
const eventTypeFilterKeys = [
  { id: 'all', labelKey: 'audit.allEvents' as const },
  { id: 'unlock', labelKey: 'audit.unlockVault' as const },
  { id: 'lock', labelKey: 'audit.lockVault' as const },
  { id: 'auth_failed', labelKey: 'audit.authFailed' as const },
  { id: 'password_added', labelKey: 'audit.passwordAdded' as const },
  { id: 'password_updated', labelKey: 'audit.passwordUpdated' as const },
  { id: 'password_deleted', labelKey: 'audit.passwordDeleted' as const },
  { id: 'password_revealed', labelKey: 'audit.passwordRevealed' as const },
  { id: 'folder_created', labelKey: 'audit.folderCreated' as const },
  { id: 'note_created', labelKey: 'audit.noteCreated' as const },
  { id: 'note_updated', labelKey: 'audit.noteUpdated' as const },
  { id: 'note_deleted', labelKey: 'audit.noteDeleted' as const },
  { id: 'backup_export', labelKey: 'audit.backupExport' as const },
  { id: 'backup_import', labelKey: 'audit.backupImport' as const },
  { id: 'backup_created', labelKey: 'audit.backupCreated' as const },
  { id: 'settings_changed', labelKey: 'audit.settingsChanged' as const },
  { id: 'scan', labelKey: 'audit.threatEvents' as const },
]

// ─── Severity config ───
const severityConfig: Record<string, { dot: string; icon: React.ElementType }> = {
  success: { dot: 'var(--kestrel-success)', icon: CheckCircle },
  info: { dot: 'var(--kestrel-primary)', icon: Settings },
  warning: { dot: 'var(--kestrel-warning)', icon: AlertTriangle },
  danger: { dot: 'var(--kestrel-danger)', icon: Trash2 },
}

// ─── Icon mapping per composite type ───
const eventIcons: Record<string, React.ElementType> = {
  unlock: Unlock,
  lock: Lock,
  auth_failed: AlertTriangle,
  vault_init: Key,
  auth_other: ShieldCheck,
  password_added: Plus,
  password_updated: Edit3,
  password_deleted: Trash2,
  password_revealed: Eye,
  folder_created: FolderPlus,
  folder_deleted: Trash2,
  note_created: FileText,
  note_updated: Edit3,
  note_deleted: Trash2,
  note_revealed: Eye,
  backup_export: Download,
  backup_import: Upload,
  backup_created: Database,
  vault_cleared: Trash2,
  vault_other: ShieldCheck,
  notes_other: FileText,
  settings_changed: Settings,
  settings_reset: RefreshCw,
  settings_other: Settings,
  audit_export: Download,
  security_event: ShieldCheck,
  system_event: Settings,
  scan: ShieldCheck,
  other: Settings,
}

// ─── Friendly description for each action ───
function buildDescription(type: string, subject: string): string {
  switch (type) {
    case 'unlock': return `Vault unlocked — ${subject}`
    case 'lock': return `Vault locked — ${subject}`
    case 'auth_failed': return `Failed unlock attempt — ${subject}`
    case 'vault_init': return `Vault initialized — ${subject}`
    case 'password_added': return `Password entry created — ${subject}`
    case 'password_updated': return `Password entry updated — ${subject}`
    case 'password_deleted': return `Password entry deleted — ${subject}`
    case 'password_revealed': return `Password revealed — ${subject}`
    case 'folder_created': return `Folder created — ${subject}`
    case 'folder_deleted': return `Folder deleted — ${subject}`
    case 'note_created': return `Note created — ${subject}`
    case 'note_updated': return `Note updated — ${subject}`
    case 'note_deleted': return `Note deleted — ${subject}`
    case 'note_revealed': return `Note revealed — ${subject}`
    case 'backup_export': return `Vault exported — ${subject}`
    case 'backup_import': return `Vault imported — ${subject}`
    case 'backup_created': return `Backup created — ${subject}`
    case 'vault_cleared': return `Vault data cleared — ${subject}`
    case 'settings_changed': return `Settings changed — ${subject}`
    case 'settings_reset': return `Settings reset — ${subject}`
    case 'audit_export': return `Audit log exported — ${subject}`
    case 'scan': return `Security scan — ${subject}`
    case 'security_event': return `Security event — ${subject}`
    case 'system_event': return `System event — ${subject}`
    default: return `${subject}`
  }
}

// ─── Severity per composite type ───
function getEventSeverity(type: string): 'success' | 'info' | 'warning' | 'danger' {
  if (type === 'unlock' || type === 'backup_created' || type === 'scan') return 'success'
  if (type === 'auth_failed') return 'danger'
  if (type === 'password_deleted' || type === 'folder_deleted' || type === 'note_deleted' || type === 'vault_cleared') return 'warning'
  return 'info'
}

export default function AuditLogs() {
  const { t } = useI18n()
  const [activeFilter, setActiveFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [events, setEvents] = useState<AuditEventLocal[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)
  const [isExporting, setIsExporting] = useState(false)

  const eventTypeFilters = eventTypeFilterKeys.map((f) => ({
    id: f.id,
    label: t(f.labelKey),
  }))

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const result = await auditCommands.queryEvents({ limit: 200 })
        const mapped: AuditEventLocal[] = result.events.map((e) => {
          const compositeType = mapEventType(e.category, e.action)
          return {
            id: e.id,
            type: compositeType,
            description: buildDescription(compositeType, e.subject),
            timestamp: e.timestamp,
            category: e.category,
            action: e.action,
            subject: e.subject,
            hash: e.id.slice(0, 12),
          }
        })
        setEvents(mapped)
      } catch {
        setEvents([])
      } finally {
        setIsLoading(false)
      }
    }
    fetchEvents()
  }, [])

  const filteredLogs = events.filter((log) => {
    const matchesFilter = activeFilter === 'all' || log.type === activeFilter
    const matchesSearch = !searchQuery ||
      log.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.category.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const grouped: Record<string, AuditEventLocal[]> = filteredLogs.reduce((acc, log) => {
    const date = new Date(log.timestamp).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
    if (!acc[date]) acc[date] = []
    acc[date].push(log)
    return acc
  }, {} as Record<string, AuditEventLocal[]>)

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash).catch(() => {})
    setCopiedHash(hash)
    setTimeout(() => setCopiedHash(null), 1000)
  }

  const handleExport = async (format: 'json' | 'csv') => {
    setIsExporting(true)
    try {
      const data = await auditCommands.exportEvents(format)
      const blob = new Blob([data], { type: format === 'json' ? 'application/json' : 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-log.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // Export failed silently
    } finally {
      setIsExporting(false)
    }
  }

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
  }

  return (
    <div className="flex h-full">
      <div
        className="flex flex-col h-full flex-shrink-0 overflow-y-auto"
        style={{ width: '220px', borderRight: '1px solid var(--kestrel-border)', backgroundColor: 'var(--kestrel-surface)' }}
      >
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('audit.title')}</h2>
          <div className="space-y-2 mb-4">
            <button
              onClick={() => handleExport('json')}
              disabled={isExporting}
              className="w-full h-8 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
              style={{ backgroundColor: isExporting ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
            >
              <Download size={12} /> {isExporting ? t('audit.exporting') : t('audit.exportJson')}
            </button>
            <button
              onClick={() => handleExport('csv')}
              disabled={isExporting}
              className="w-full h-8 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
              style={{ backgroundColor: isExporting ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
            >
              <Download size={12} /> {isExporting ? t('audit.exporting') : t('audit.exportCsv')}
            </button>
          </div>
          <div className="relative mb-4">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }} />
            <input
              type="text"
              placeholder={t('audit.searchEvents')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--kestrel-hover-bg)', paddingLeft: '32px', paddingRight: '10px', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
            />
          </div>

          <div className="space-y-0.5">
            <p className="text-xs font-semibold mb-2 px-1" style={{ color: 'var(--kestrel-text-muted)' }}>{t('audit.eventType')}</p>
            {eventTypeFilters.map((filter) => {
              const count = filter.id === 'all' ? events.length : events.filter((e) => e.type === filter.id).length
              return (
                <button
                  key={filter.id}
                  onClick={() => setActiveFilter(filter.id)}
                  className="w-full flex items-center gap-2.5 px-2 py-1.5 rounded-md text-left text-sm transition-colors duration-150"
                  style={{
                    backgroundColor: activeFilter === filter.id ? 'var(--kestrel-selected-bg)' : 'transparent',
                    color: activeFilter === filter.id ? 'var(--kestrel-primary)' : 'var(--kestrel-text-muted)',
                    fontWeight: activeFilter === filter.id ? 500 : 400,
                  }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: activeFilter === filter.id ? 'var(--kestrel-primary)' : 'var(--kestrel-text-light)' }}
                  />
                  <span className="flex-1 truncate">{filter.label}</span>
                  <span className="text-xs opacity-60">{count}</span>
                </button>
              )
            })}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
              style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
          </div>
        ) : Object.entries(grouped).length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <Search size={32} style={{ color: 'var(--kestrel-text-light)' }} className="mb-3" />
            <p className="text-sm" style={{ color: 'var(--kestrel-text-muted)' }}>{t('audit.noEvents')}</p>
          </div>
        ) : (
          Object.entries(grouped).map(([date, logs]) => (
            <div key={date} className="mb-8">
              <h4
                className="text-sm font-semibold sticky top-0 py-2 mb-3"
                style={{
                  color: 'var(--kestrel-text)',
                  backgroundColor: 'var(--kestrel-bg)',
                  borderBottom: '1px solid var(--kestrel-border)',
                  zIndex: 10,
                }}
              >
                {date}
              </h4>

              <div className="relative pl-6">
                <div
                  className="absolute left-2 top-0 bottom-0 w-0.5"
                  style={{ backgroundColor: 'var(--kestrel-border)' }}
                />

                {logs.map((log, logIndex) => {
                  const severity = getEventSeverity(log.type)
                  const config = severityConfig[severity] ?? severityConfig.info
                  const EventIcon = eventIcons[log.type] || Settings
                  return (
                    <div key={log.id} className="relative mb-4 animate-stagger-in" style={staggerStyle(logIndex)}>
                      <div
                        className="absolute -left-6 top-3 w-3 h-3 rounded-full border-2"
                        style={{ backgroundColor: config!.dot, borderColor: 'var(--kestrel-bg)' }}
                      />

                      <div
                        className="flex items-start gap-3 p-3 rounded-lg transition-all duration-200"
                        style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
                      >
                        <div
                          className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                          style={{ backgroundColor: `${config!.dot}15` }}
                        >
                          <EventIcon size={15} style={{ color: config!.dot }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm" style={{ color: 'var(--kestrel-text)' }}>{log.description}</p>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>
                            {log.category} / {log.action.replace(/([A-Z])/g, ' $1').trim()}
                          </p>
                          <div className="flex items-center gap-2 mt-1.5">
                            <span className="font-mono-geist text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                              {t('audit.hash')}: {log.hash}
                            </span>
                            <button
                              onClick={() => handleCopyHash(log.hash)}
                              className="flex items-center gap-1 text-xs"
                              style={{ color: 'var(--kestrel-text-muted)' }}
                            >
                              {copiedHash === log.hash ? (
                                <>
                                  <CheckCircle size={10} style={{ color: 'var(--kestrel-success)' }} />
                                  <span style={{ color: 'var(--kestrel-success)' }}>{t('audit.copied')}</span>
                                </>
                              ) : (
                                <Copy size={10} />
                              )}
                            </button>
                          </div>
                        </div>
                        <span className="text-xs flex-shrink-0" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                          {formatTime(log.timestamp)}
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
