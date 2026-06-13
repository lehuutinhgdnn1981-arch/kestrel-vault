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
  Bell,
  Trash2,
} from 'lucide-react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import { useAuthStore } from '@/stores/auth-store'
import { useVaultStore } from '@/stores/vault-store'
import { useNoteStore } from '@/stores/note-store'
import { useNavigate } from 'react-router-dom'

const sparkData1 = [
  { v: 65 }, { v: 72 }, { v: 68 }, { v: 75 }, { v: 80 }, { v: 77 }, { v: 85 }, { v: 87 },
]
const sparkData2 = [
  { v: 320 }, { v: 325 }, { v: 330 }, { v: 328 }, { v: 335 }, { v: 338 }, { v: 340 }, { v: 342 },
]
const sparkData3 = [
  { v: 12 }, { v: 14 }, { v: 15 }, { v: 16 }, { v: 18 }, { v: 19 }, { v: 20 }, { v: 21 },
]

const recentActivity = [
  { icon: Plus, color: '#2563EB', text: 'Added password for Google', time: '2 min ago' },
  { icon: Upload, color: '#22C55E', text: 'Uploaded file report.pdf', time: '10 min ago' },
  { icon: ShieldCheck, color: '#22C55E', text: 'Security scan completed', time: '1 hour ago' },
  { icon: FilePlus, color: '#8B5CF6', text: "Added note 'Server Credentials'", time: '2 hours ago' },
  { icon: Trash2, color: '#EF4444', text: 'Deleted password for Old Account', time: '3 hours ago' },
]

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

  const color = score >= 90 ? '#22C55E' : score >= 70 ? '#2563EB' : score >= 40 ? '#F59E0B' : '#EF4444'

  return (
    <svg width="140" height="140" viewBox="0 0 140 140">
      <circle
        cx="70" cy="70" r={r}
        fill="none"
        stroke="#E2E8F0"
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
      <text x="70" y="65" textAnchor="middle" fill="#0F172A" fontSize="28" fontWeight="600">
        {score}
      </text>
      <text x="70" y="82" textAnchor="middle" fill="#64748B" fontSize="11">
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
  const entries = useVaultStore((s) => s.entries)
  const fetchEntries = useVaultStore((s) => s.fetchEntries)
  const notes = useNoteStore((s) => s.notes)
  const fetchNotes = useNoteStore((s) => s.fetchNotes)
  const appState = useAuthStore((s) => s.appState)

  useEffect(() => {
    if (appState === 'unlocked') {
      fetchEntries()
      fetchNotes()
    }
  }, [appState, fetchEntries, fetchNotes])

  const passwordCount = entries.length
  const noteCount = notes.length
  const fileCount = 0 // placeholder until file vault backend integration
  const securityScore = 87 // placeholder until scanner integration
  const storageUsed = 2.46
  const storageTotal = 10

  return (
    <div className="animate-fade-in">
      <div
        className="flex items-center justify-between px-8"
        style={{ height: '56px', backgroundColor: '#F8FAFC', borderBottom: '1px solid #E2E8F0' }}
      >
        <div>
          <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Dashboard</h2>
        </div>
        <div className="flex items-center gap-4">
          <div
            className="flex items-center gap-2 px-3 h-9 rounded-lg"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', width: '280px' }}
          >
            <Search size={16} style={{ color: '#64748B' }} />
            <input
              type="text"
              placeholder="Search..."
              className="bg-transparent outline-none text-sm flex-1"
              style={{ color: '#0F172A' }}
            />
          </div>
          <button
            className="relative w-9 h-9 flex items-center justify-center rounded-lg transition-colors duration-150"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0' }}
          >
            <Bell size={16} style={{ color: '#64748B' }} />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full" style={{ backgroundColor: '#EF4444' }} />
          </button>
        </div>
      </div>

      <div className="p-8 space-y-6">
        <div className="grid grid-cols-4 gap-4">
          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(37, 99, 235, 0.1)' }}>
                <ShieldCheck size={16} style={{ color: '#2563EB' }} />
              </div>
              <MiniSparkline data={sparkData1} color="#2563EB" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: '#0F172A' }}>
              <AnimatedNumber value={securityScore} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>Security Score</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)' }}>
                <Key size={16} style={{ color: '#22C55E' }} />
              </div>
              <MiniSparkline data={sparkData2} color="#22C55E" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: '#0F172A' }}>
              <AnimatedNumber value={passwordCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>Passwords</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(245, 158, 11, 0.1)' }}>
                <FileText size={16} style={{ color: '#F59E0B' }} />
              </div>
              <MiniSparkline data={sparkData3} color="#F59E0B" />
            </div>
            <div className="text-2xl font-semibold" style={{ color: '#0F172A' }}>
              <AnimatedNumber value={fileCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>Files</p>
          </div>

          <div
            className="rounded-xl p-5 transition-shadow duration-150 hover:shadow-md"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(139, 92, 246, 0.1)' }}>
                <StickyNote size={16} style={{ color: '#8B5CF6' }} />
              </div>
            </div>
            <div className="text-2xl font-semibold" style={{ color: '#0F172A' }}>
              <AnimatedNumber value={noteCount} />
            </div>
            <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>Notes</p>
          </div>
        </div>

        <div className="grid grid-cols-5 gap-4">
          <div
            className="col-span-3 rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <h3 className="text-base font-semibold mb-4" style={{ color: '#0F172A' }}>Security Score</h3>
            <div className="flex flex-col items-center">
              <SecurityScoreGauge score={securityScore} />
              <p className="text-sm font-medium mt-2" style={{ color: '#22C55E' }}>Strong</p>
              <div className="flex items-center gap-1.5 mt-1">
                <CheckCircle size={14} style={{ color: '#22C55E' }} />
                <span className="text-xs" style={{ color: '#64748B' }}>Your vault is secure</span>
              </div>
            </div>
          </div>

          <div
            className="col-span-2 rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>Recent Activity</h3>
              <button onClick={() => navigate('/audit')} className="text-xs font-medium" style={{ color: '#2563EB' }}>View all</button>
            </div>
            <div className="space-y-1">
              {recentActivity.map((item, i) => {
                const Icon = item.icon
                return (
                  <div
                    key={i}
                    className="flex items-center gap-3 px-2 py-2 rounded-lg transition-colors duration-150 cursor-pointer"
                    onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#F8FAFC' }}
                    onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                  >
                    <div
                      className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${item.color}15` }}
                    >
                      <Icon size={13} style={{ color: item.color }} />
                    </div>
                    <span className="text-sm flex-1 truncate" style={{ color: '#0F172A' }}>{item.text}</span>
                    <span className="text-xs flex-shrink-0" style={{ color: '#94A3B8' }}>{item.time}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)' }}>
                <Shield size={20} style={{ color: '#22C55E' }} />
              </div>
              <div>
                <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>No threats found</h3>
                <p className="text-sm" style={{ color: '#64748B' }}>Your vault is safe</p>
              </div>
            </div>
            <p className="text-xs" style={{ color: '#94A3B8' }}>Last scan: 2 hours ago</p>
          </div>

          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)' }}>
                <CheckCircle size={20} style={{ color: '#22C55E' }} />
              </div>
              <div>
                <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>All systems operational</h3>
                <p className="text-sm" style={{ color: '#64748B' }}>Everything is running smoothly</p>
              </div>
            </div>
            <p className="text-xs" style={{ color: '#94A3B8' }}>Last checked: just now</p>
          </div>
        </div>

        <div
          className="rounded-xl p-6"
          style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 2px 0 rgb(0 0 0 / 0.03)' }}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium" style={{ color: '#0F172A' }}>Storage Usage</span>
            <span className="text-xs" style={{ color: '#64748B' }}>{storageUsed.toFixed(2)} GB / {storageTotal} GB used</span>
          </div>
          <div className="w-full h-2 rounded-full mb-6" style={{ backgroundColor: '#F1F5F9' }}>
            <div
              className="h-2 rounded-full"
              style={{
                width: `${(storageUsed / storageTotal) * 100}%`,
                backgroundColor: '#2563EB',
                transition: 'width 300ms ease',
              }}
            />
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/vault')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#1D4ED8' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#2563EB' }}
            >
              <Plus size={16} /> Add Password
            </button>
            <button
              onClick={() => navigate('/files')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: '#FFFFFF', color: '#0F172A', border: '1px solid #E2E8F0' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#F8FAFC' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#FFFFFF' }}
            >
              <Upload size={16} /> Upload File
            </button>
            <button
              onClick={() => navigate('/notes')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: '#FFFFFF', color: '#0F172A', border: '1px solid #E2E8F0' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#F8FAFC' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#FFFFFF' }}
            >
              <FilePlus size={16} /> New Note
            </button>
            <button
              onClick={() => navigate('/scanner')}
              className="flex items-center gap-2 px-4 h-9 rounded-lg text-sm font-medium transition-colors duration-150"
              style={{ backgroundColor: '#FFFFFF', color: '#0F172A', border: '1px solid #E2E8F0' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#F8FAFC' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#FFFFFF' }}
            >
              <Search size={16} /> Run Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
