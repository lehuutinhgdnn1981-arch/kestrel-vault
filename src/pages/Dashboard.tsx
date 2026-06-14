import { useEffect, useState } from 'react'
import {
  ShieldCheck,
  Key,
  FileText,
  StickyNote,
  Plus,
  Upload,
  FilePlus,
  Search,
  CheckCircle,
  Shield,
  Trash2,
  Lock,
  Settings,
  Eye,
} from 'lucide-react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import { useAuthStore } from '@/stores/auth-store'
import { useVaultStore } from '@/stores/vault-store'
import { useNoteStore } from '@/stores/note-store'
import { useNavigate } from 'react-router-dom'
import { auditCommands, fileCommands, scannerCommands, type AuditEventView } from '@/lib/tauri'
import { useI18n } from '@/hooks/use-i18n'

const sparkData1 = [
  { v: 65 }, { v: 72 }, { v: 68 }, { v: 75 }, { v: 80 }, { v: 77 }, { v: 85 }, { v: 87 },
]
const sparkData2 = [
  { v: 320 }, { v: 325 }, { v: 330 }, { v: 328 }, { v: 335 }, { v: 338 }, { v: 340 }, { v: 342 },
]
const sparkData3 = [
  { v: 12 }, { v: 14 }, { v: 15 }, { v: 16 }, { v: 18 }, { v: 19 }, { v: 20 }, { v: 21 },
]

// Map audit event categories/actions to icons and colors
function getAuditEventStyle(category: string, action: string): { icon: typeof Plus; color: string } {
  if (category === 'vault') {
    if (action === 'create') return { icon: Plus, color: 'var(--kestrel-primary)' }
    if (action === 'delete') return { icon: Trash2, color: 'var(--kestrel-danger)' }
    if (action === 'password_reveal') return { icon: Eye, color: 'var(--kestrel-warning)' }
    return { icon: Key, color: 'var(--kestrel-primary)' }
  }
  if (category === 'notes') return { icon: FilePlus, color: 'var(--kestrel-accent-purple)' }
  if (category === 'files') return { icon: Upload, color: 'var(--kestrel-success)' }
  if (category === 'scanner') return { icon: ShieldCheck, color: 'var(--kestrel-success)' }
  if (category === 'auth') {
    if (action === 'unlock') return { icon: Lock, color: 'var(--kestrel-success)' }
    if (action === 'lock') return { icon: Lock, color: 'var(--kestrel-text-muted)' }
    return { icon: Shield, color: 'var(--kestrel-primary)' }
  }
  if (category === 'settings') return { icon: Settings, color: 'var(--kestrel-text-muted)' }
  return { icon: Shield, color: 'var(--kestrel-text-muted)' }
}

function formatTimeAgo(timestamp: string, t: (key: any) => string): string {
  const now = Date.now()
  const then = new Date(timestamp).getTime()
  const diffMs = now - then
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSeconds < 60) return t('time.justNow')
  if (diffMinutes < 60) return `${diffMinutes} ${t('time.minAgo')}`
  if (diffHours < 24) return `${diffHours} ${diffHours === 1 ? t('time.hourAgo') : t('time.hoursAgo')}`
  return `${diffDays} ${diffDays === 1 ? t('time.dayAgo') : t('time.daysAgo')}`
}

interface ActivityItem {
  icon: typeof Plus
  color: string
  text: string
  time: string
}

function AnimatedNumber({ value, duration = 600 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    const start = performance.now()
    const animate = (now: number) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(value * eased))
      if (progress < 1) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [value, duration])

  return <>{display}</>
}

function SecurityScoreGauge({ score }: { score: number }) {
  const r = 54
  const circumference = 2 * Math.PI * r
  const offset = circumference - (score / 100) * circumference

  const color = score >= 90 ? 'var(--kestrel-success)' : score >= 70 ? 'var(--kestrel-primary)' : score >= 40 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)'

  return (
    <svg width="140" height="140" viewBox="0 0 140 140">
      <circle
        cx="70" cy="70" r={r}
        fill="none"
        stroke="var(--kestrel-border)"
        strokeWidth="8"
      />
      <circle
        cx="70" cy="70" r={r}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 70 70)"
        style={{ transition: 'stroke-dashoffset 800ms ease-out' }}
      />
      <text x="70" y="65" textAnchor="middle" fill="var(--kestrel-text)" fontSize="28" fontWeight="600">
        {score}
      </text>
      <text x="70" y="82" textAnchor="middle" fill="var(--kestrel-text-muted)" fontSize="11">
        /100
      </text>
    </svg>
  )
}

function MiniSparkline({ data, color }: { data: Array<{ v: number }>; color: string }) {
  return (
    <ResponsiveContainer width={80} height={30}>
      <LineChart data={data}>
        <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const entries = useVaultStore((s) => s.entries)
  const fetchEntries = useVaultStore((s) => s.fetchEntries)
  const notes = useNoteStore((s) => s.notes)
  const fetchNotes = useNoteStore((s) => s.fetchNotes)
  const appState = useAuthStore((s) => s.appState)

  const [securityScore, setSecurityScore] = useState(0)
  const [recentActivity, setRecentActivity] = useState<ActivityItem[]>([])

  const passwordCount = entries.length
  const noteCount = notes.length
  const [fileCount, setFileCount] = useState(0)
  const [storageUsed, setStorageUsed] = useState(0)
  const storageTotal = 10

  useEffect(() => {
    if (appState === 'unlocked') {
      fetchEntries()
      fetchNotes()

      // Fetch security score
      const fetchScore = async () => {
        try {
          const result = await scannerCommands.getSecurityScore()
          setSecurityScore(result.score)
        } catch {
          // Silently fail — score will remain 0
        }
      }
      fetchScore()

      // Fetch file count from backend
      const fetchFileCount = async () => {
        try {
          const files = await fileCommands.list()
          setFileCount(files.length)
          const totalBytes = files.reduce((sum, f) => sum + f.size_bytes, 0)
          setStorageUsed(totalBytes / (1024 * 1024 * 1024)) // Convert to GB
        } catch {
          // Silently fail — file count will remain 0
        }
      }
      fetchFileCount()

      // Fetch recent activity from audit log
      const fetchActivity = async () => {
        try {
          const page = await auditCommands.queryEvents({ limit: 5 })
          const activityItems: ActivityItem[] = page.events.map((event: AuditEventView) => {
            const style = getAuditEventStyle(event.category, event.action)
            return {
              icon: style.icon,
              color: style.color,
              text: `${event.action} ${event.category}: ${event.subject}`,
              time: formatTimeAgo(event.timestamp, t),
            }
          })
          setRecentActivity(activityItems)
        } catch {
          // Silently fail — activity will remain empty
        }
      }
      fetchActivity()
    }
  }, [appState, fetchEntries, fetchNotes])

  return (
    <div className="animate-fade-in">
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-4 gap-4">
          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-primary-subtle)' }}>
                <ShieldCheck size={16} style={{ color: 'var(--kestrel-primary)' }} />
              </div>
              <MiniSparkline data={sparkData1} color="var(--kestrel-primary)" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              <AnimatedNumber value={securityScore} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.securityScore')}</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-success-subtle)' }}>
                <Key size={16} style={{ color: 'var(--kestrel-success)' }} />
              </div>
              <MiniSparkline data={sparkData2} color="var(--kestrel-success)" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              <AnimatedNumber value={passwordCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.passwords')}</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-warning-subtle)' }}>
                <FileText size={16} style={{ color: 'var(--kestrel-warning)' }} />
              </div>
              <MiniSparkline data={sparkData3} color="var(--kestrel-warning)" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              <AnimatedNumber value={fileCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.files')}</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-purple-subtle)' }}>
                <StickyNote size={16} style={{ color: 'var(--kestrel-accent-purple)' }} />
              </div>
            </div>
            <div className="text-2xl font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              <AnimatedNumber value={noteCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.notes')}</p>
          </div>
        </div>

        <div className="grid grid-cols-5 gap-4">
          <div
            className="col-span-3 rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <h3 className="text-base font-semibold mb-4" style={{ color: 'var(--kestrel-text)' }}>{t('dashboard.securityScore')}</h3>
            <div className="flex flex-col items-center">
              <SecurityScoreGauge score={securityScore} />
              <p className="text-sm font-medium mt-2" style={{ color: securityScore >= 70 ? 'var(--kestrel-success)' : securityScore >= 40 ? 'var(--kestrel-warning)' : 'var(--kestrel-danger)' }}>
                {securityScore >= 90 ? t('dashboard.excellent') : securityScore >= 70 ? t('dashboard.strong') : securityScore >= 40 ? t('dashboard.fair') : t('dashboard.needsAttention')}
              </p>
              <div className="flex items-center gap-1.5 mt-1">
                <CheckCircle size={14} style={{ color: securityScore >= 70 ? 'var(--kestrel-success)' : 'var(--kestrel-warning)' }} />
                <span className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
                  {securityScore >= 70 ? t('dashboard.vaultSecure') : t('dashboard.reviewIssues')}
                </span>
              </div>
            </div>
          </div>

          <div
            className="col-span-2 rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('dashboard.recentActivity')}</h3>
              <button onClick={() => navigate('/audit')} className="text-xs font-medium" style={{ color: 'var(--kestrel-primary)' }}>{t('dashboard.viewAll')}</button>
            </div>
            <div className="space-y-1">
              {recentActivity.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('dashboard.noRecentActivity')}</p>
                </div>
              ) : (
                recentActivity.map((item, i) => {
                  const Icon = item.icon
                  return (
                    <div
                      key={i}
                      className="flex items-center gap-3 px-2 py-2 rounded-lg transition-colors duration-150 cursor-pointer"
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                    >
                      <div
                        className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: `${item.color}15` }}
                      >
                        <Icon size={13} style={{ color: item.color }} />
                      </div>
                      <span className="text-sm flex-1 truncate" style={{ color: 'var(--kestrel-text)' }}>{item.text}</span>
                      <span className="text-xs flex-shrink-0" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{item.time}</span>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-success-subtle)' }}>
                <Shield size={20} style={{ color: 'var(--kestrel-success)' }} />
              </div>
              <div>
                <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('dashboard.noThreats')}</h3>
                <p className="text-sm" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.vaultSafe')}</p>
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('dashboard.runScan')}</p>
          </div>

          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-success-subtle)' }}>
                <CheckCircle size={20} style={{ color: 'var(--kestrel-success)' }} />
              </div>
              <div>
                <h3 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('dashboard.allSystemsOperational')}</h3>
                <p className="text-sm" style={{ color: 'var(--kestrel-text-muted)' }}>{t('dashboard.runningSmoothly')}</p>
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('dashboard.lastChecked')}</p>
          </div>
        </div>

        <div
          className="rounded-xl p-6"
          style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-card)' }}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{t('dashboard.storageUsage')}</span>
            <span className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{storageUsed.toFixed(2)} GB / {storageTotal} GB {t('dashboard.used')}</span>
          </div>
          <div className="w-full h-2 rounded-full mb-6" style={{ backgroundColor: 'var(--kestrel-border-subtle)' }}>
            <div
              className="h-2 rounded-full"
              style={{
                width: `${(storageUsed / storageTotal) * 100}%`,
                backgroundColor: 'var(--kestrel-primary)',
                transition: 'width 300ms ease',
              }}
            />
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/vault')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-primary)', color: '#FFFFFF' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary-hover)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary)' }}
            >
              <Plus size={16} /> {t('dashboard.addPassword')}
            </button>
            <button
              onClick={() => navigate('/files')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-surface)' }}
            >
              <Upload size={16} /> {t('dashboard.uploadFile')}
            </button>
            <button
              onClick={() => navigate('/notes')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-surface)' }}
            >
              <FilePlus size={16} /> {t('dashboard.newNote')}
            </button>
            <button
              onClick={() => navigate('/scanner')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-surface)' }}
            >
              <Search size={16} /> {t('dashboard.runScanBtn')}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
