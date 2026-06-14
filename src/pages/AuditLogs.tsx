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
} from 'lucide-react'
import { auditCommands } from '@/lib/tauri'

interface AuditEventLocal {
  id: string
  type: string
  description: string
  timestamp: string
  category: string
  action: string
  subject: string
  hash: string
}

const eventTypeFilters = [
  { id: 'all', label: 'All Events' },
  { id: 'unlock', label: 'Unlock Vault' },
  { id: 'lock', label: 'Lock Vault' },
  { id: 'password_added', label: 'Password Added' },
  { id: 'password_deleted', label: 'Password Deleted' },
  { id: 'file_uploaded', label: 'File Uploaded' },
  { id: 'file_deleted', label: 'File Deleted' },
  { id: 'scan', label: 'Threat Events' },
  { id: 'backup', label: 'Backup Export' },
  { id: 'settings_changed', label: 'Settings Changed' },
]

const severityConfig: Record<string, { dot: string; icon: React.ElementType }> = {
  success: { dot: '#22C55E', icon: CheckCircle },
  info: { dot: '#2563EB', icon: Settings },
  warning: { dot: '#F59E0B', icon: ShieldCheck },
  danger: { dot: '#EF4444', icon: Trash2 },
}

const eventIcons: Record<string, React.ElementType> = {
  unlock: Unlock,
  lock: Lock,
  password_added: Plus,
  password_deleted: Trash2,
  file_uploaded: Upload,
  file_deleted: Trash2,
  scan: ShieldCheck,
  backup: Download,
  settings_changed: Settings,
}

// Fallback demo data
const demoAuditLogs: AuditEventLocal[] = [
  { id: '1', type: 'unlock', description: 'Unlocked vault', timestamp: '2024-05-20T10:30:00Z', category: 'auth', action: 'unlock', subject: 'vault', hash: 'a1b2c3d4e5f6' },
  { id: '2', type: 'password_added', description: 'Added password for Google', timestamp: '2024-05-20T10:32:00Z', category: 'vault', action: 'add', subject: 'Google', hash: 'b2c3d4e5f6g7' },
  { id: '3', type: 'file_uploaded', description: 'Uploaded file report.pdf', timestamp: '2024-05-20T10:35:00Z', category: 'vault', action: 'upload', subject: 'report.pdf', hash: 'c3d4e5f6g7h8' },
  { id: '4', type: 'lock', description: 'Locked vault', timestamp: '2024-05-20T09:15:00Z', category: 'auth', action: 'lock', subject: 'vault', hash: 'd4e5f6g7h8i9' },
  { id: '5', type: 'scan', description: 'Security scan completed — No threats found', timestamp: '2024-05-20T09:00:00Z', category: 'scanner', action: 'scan', subject: 'full', hash: 'e5f6g7h8i9j0' },
  { id: '6', type: 'backup', description: 'Exported backup — Size: 156 MB', timestamp: '2024-05-20T08:45:00Z', category: 'vault', action: 'export', subject: 'backup', hash: 'f6g7h8i9j0k1' },
  { id: '7', type: 'password_deleted', description: 'Deleted password for Old Account', timestamp: '2024-05-19T16:00:00Z', category: 'vault', action: 'delete', subject: 'Old Account', hash: 'g7h8i9j0k1l2' },
  { id: '8', type: 'settings_changed', description: 'Changed auto-lock settings', timestamp: '2024-05-19T14:30:00Z', category: 'settings', action: 'update', subject: 'auto-lock', hash: 'h8i9j0k1l2m3' },
]

export default function AuditLogs() {
  const [activeFilter, setActiveFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [events, setEvents] = useState<AuditEventLocal[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const result = await auditCommands.queryEvents({ limit: 50 })
        const mapped: AuditEventLocal[] = result.events.map((e) => ({
          id: e.id,
          type: e.category,
          description: `${e.action} — ${e.subject}`,
          timestamp: e.timestamp,
          category: e.category,
          action: e.action,
          subject: e.subject,
          hash: e.id.slice(0, 12),
        }))
        setEvents(mapped)
      } catch {
        // Use demo data as fallback
        setEvents(demoAuditLogs)
      } finally {
        setIsLoading(false)
      }
    }
    fetchEvents()
  }, [])

  const filteredLogs = events.filter((log) => {
    const matchesFilter = activeFilter === 'all' || log.type === activeFilter
    const matchesSearch = !searchQuery ||
      log.description.toLowerCase().includes(searchQuery.toLowerCase())
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

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
  }

  const getEventSeverity = (type: string): 'success' | 'info' | 'warning' | 'danger' => {
    if (type === 'unlock' || type === 'scan') return 'success'
    if (type === 'password_added' || type === 'file_uploaded' || type === 'backup' || type === 'settings_changed') return 'info'
    if (type === 'password_deleted' || type === 'file_deleted') return 'warning'
    if (type === 'lock') return 'info'
    return 'info'
  }

  return (
    <div className="flex h-full animate-fade-in">
      <div
        className="flex flex-col h-full flex-shrink-0 overflow-y-auto"
        style={{ width: '220px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}
      >
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4" style={{ color: '#0F172A' }}>Audit Logs</h2>
          <div className="relative mb-4">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
            <input
              type="text"
              placeholder="Search events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: '#F8FAFC', paddingLeft: '32px', paddingRight: '10px', border: '1px solid #E2E8F0', color: '#0F172A' }}
            />
          </div>

          <div className="space-y-0.5">
            <p className="text-xs font-semibold mb-2 px-1" style={{ color: '#64748B' }}>EVENT TYPE</p>
            {eventTypeFilters.map((filter) => (
              <button
                key={filter.id}
                onClick={() => setActiveFilter(filter.id)}
                className="w-full flex items-center gap-2.5 px-2 py-1.5 rounded-md text-left text-sm transition-colors duration-150"
                style={{
                  backgroundColor: activeFilter === filter.id ? '#F8FAFC' : 'transparent',
                  color: activeFilter === filter.id ? '#0F172A' : '#64748B',
                  fontWeight: activeFilter === filter.id ? 500 : 400,
                }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ backgroundColor: activeFilter === filter.id ? '#2563EB' : '#CBD5E1' }}
                />
                {filter.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-8" style={{ backgroundColor: '#F8FAFC' }}>
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
              style={{ borderColor: '#2563EB', borderTopColor: 'transparent' }} />
          </div>
        ) : Object.entries(grouped).length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <Search size={32} style={{ color: '#CBD5E1' }} className="mb-3" />
            <p className="text-sm" style={{ color: '#64748B' }}>No events found</p>
          </div>
        ) : (
          Object.entries(grouped).map(([date, logs]) => (
            <div key={date} className="mb-8">
              <h4
                className="text-sm font-semibold sticky top-0 py-2 mb-3"
                style={{
                  color: '#0F172A',
                  backgroundColor: '#F8FAFC',
                  borderBottom: '1px solid #E2E8F0',
                  zIndex: 10,
                }}
              >
                {date}
              </h4>

              <div className="relative pl-6">
                <div
                  className="absolute left-2 top-0 bottom-0 w-0.5"
                  style={{ backgroundColor: '#E2E8F0' }}
                />

                {logs.map((log) => {
                  const severity = getEventSeverity(log.type)
                  const config = severityConfig[severity] ?? severityConfig.info
                  const EventIcon = eventIcons[log.type] || Settings
                  return (
                    <div key={log.id} className="relative mb-4">
                      <div
                        className="absolute -left-6 top-3 w-3 h-3 rounded-full border-2"
                        style={{ backgroundColor: config.dot, borderColor: '#F8FAFC' }}
                      />

                      <div
                        className="flex items-start gap-3 p-3 rounded-lg transition-colors duration-150"
                        style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
                      >
                        <div
                          className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                          style={{ backgroundColor: `${config.dot}15` }}
                        >
                          <EventIcon size={15} style={{ color: config.dot }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm" style={{ color: '#0F172A' }}>{log.description}</p>
                          <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>
                            Type: {log.type.replace(/_/g, ' ')}
                          </p>
                          <div className="flex items-center gap-2 mt-1.5">
                            <span className="font-mono-geist text-xs" style={{ color: '#94A3B8' }}>
                              Hash: {log.hash}
                            </span>
                            <button
                              onClick={() => handleCopyHash(log.hash)}
                              className="flex items-center gap-1 text-xs"
                              style={{ color: '#64748B' }}
                            >
                              {copiedHash === log.hash ? (
                                <>
                                  <CheckCircle size={10} style={{ color: '#22C55E' }} />
                                  <span style={{ color: '#22C55E' }}>Copied</span>
                                </>
                              ) : (
                                <Copy size={10} />
                              )}
                            </button>
                          </div>
                        </div>
                        <span className="text-xs flex-shrink-0" style={{ color: '#94A3B8' }}>
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
