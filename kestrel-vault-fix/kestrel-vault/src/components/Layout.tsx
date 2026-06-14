import { useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  FileText,
  StickyNote,
  ShieldCheck,
  Search,
  ScrollText,
  Settings,
  Lock,
  Unlock,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth-store'
import { useVaultStore } from '@/stores/vault-store'
import { useNoteStore } from '@/stores/note-store'

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/vault', label: 'Vault', icon: Shield },
  { path: '/files', label: 'Files', icon: FileText },
  { path: '/notes', label: 'Notes', icon: StickyNote },
  { path: '/security', label: 'Security', icon: ShieldCheck },
  { path: '/scanner', label: 'Scanner', icon: Search },
  { path: '/audit', label: 'Audit Logs', icon: ScrollText },
  { path: '/settings', label: 'Settings', icon: Settings },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const appState = useAuthStore((s) => s.appState)
  const lock = useAuthStore((s) => s.lock)
  const isUnlocked = appState === 'unlocked'

  const entries = useVaultStore((s) => s.entries)
  const notes = useNoteStore((s) => s.notes)

  const currentPath = location.pathname

  const handleLock = async () => {
    await lock()
    navigate('/')
  }

  // Storage placeholder values (no real file vault backend yet)
  const storageUsed = 2.46
  const storageTotal = 10

  return (
    <div className="flex h-screen w-screen overflow-hidden" style={{ backgroundColor: '#F8FAFC' }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '240px', backgroundColor: '#0F172A' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4" style={{ padding: '20px 16px' }}>
          <img src="/kestrel-logo.png" alt="KESTREL" className="w-8 h-8 object-contain" />
          <div>
            <div className="text-sm font-bold tracking-widest" style={{ color: '#F8FAFC', letterSpacing: '0.08em' }}>
              KESTREL
            </div>
            <div className="text-xs font-medium tracking-widest" style={{ color: '#94A3B8', letterSpacing: '0.15em' }}>
              VAULT
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = currentPath === item.path || (item.path === '/dashboard' && currentPath === '/')
            const Icon = item.icon
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150"
                style={{
                  backgroundColor: isActive ? '#1E293B' : 'transparent',
                  borderLeft: isActive ? '3px solid #2563EB' : '3px solid transparent',
                  color: isActive ? '#F8FAFC' : '#94A3B8',
                }}
                onMouseEnter={(e) => {
                  if (!isActive) e.currentTarget.style.backgroundColor = '#1E293B'
                }}
                onMouseLeave={(e) => {
                  if (!isActive) e.currentTarget.style.backgroundColor = 'transparent'
                }}
              >
                <Icon size={18} />
                <span className="text-sm font-medium">{item.label}</span>
              </button>
            )
          })}
        </nav>

        {/* Bottom Section */}
        <div className="px-4 py-4 space-y-4" style={{ borderTop: '1px solid rgba(226, 232, 240, 0.15)' }}>
          {/* Status */}
          <div className="flex items-center gap-2">
            {isUnlocked ? (
              <>
                <Unlock size={14} style={{ color: '#22C55E' }} />
                <span className="text-xs" style={{ color: '#94A3B8' }}>Unlocked</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: '#22C55E' }} />
              </>
            ) : (
              <>
                <Lock size={14} style={{ color: '#EF4444' }} />
                <span className="text-xs" style={{ color: '#94A3B8' }}>Locked</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: '#EF4444' }} />
              </>
            )}
          </div>

          {/* Storage */}
          <div>
            <div className="flex justify-between text-xs mb-1" style={{ color: '#94A3B8' }}>
              <span>Storage</span>
              <span>{storageUsed.toFixed(2)} / {storageTotal} GB</span>
            </div>
            <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: '#1E293B' }}>
              <div
                className="h-1.5 rounded-full transition-all duration-300"
                style={{
                  width: `${(storageUsed / storageTotal) * 100}%`,
                  backgroundColor: '#2563EB',
                }}
              />
            </div>
          </div>

          {/* Stats */}
          <div className="flex justify-between text-xs" style={{ color: '#94A3B8' }}>
            <span>{entries.length} passwords</span>
            <span>{notes.length} notes</span>
          </div>

          {/* Lock Button */}
          <button
            onClick={handleLock}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#1D4ED8' }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#2563EB' }}
          >
            <Lock size={16} />
            Lock Vault
          </button>
        </div>
      </aside>

      {/* Content Area */}
      <main className="flex-1 overflow-y-auto animate-fade-in">
        {children}
      </main>
    </div>
  )
}
