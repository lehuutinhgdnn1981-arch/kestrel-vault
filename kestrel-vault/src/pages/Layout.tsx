import { useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
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
import { useI18n } from '@/hooks/use-i18n'

const navItems = [
  { path: '/dashboard', labelKey: 'nav.dashboard' as const, icon: LayoutDashboard },
  { path: '/vault', labelKey: 'nav.vault' as const, icon: Shield },
  { path: '/files', labelKey: 'nav.files' as const, icon: FileText },
  { path: '/notes', labelKey: 'nav.notes' as const, icon: StickyNote },
  { path: '/security', labelKey: 'nav.security' as const, icon: ShieldCheck },
  { path: '/scanner', labelKey: 'nav.scanner' as const, icon: Search },
  { path: '/audit', labelKey: 'nav.audit' as const, icon: ScrollText },
  { path: '/settings', labelKey: 'nav.settings' as const, icon: Settings },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const { t } = useI18n()
  const appState = useAuthStore((s) => s.appState)
  const lock = useAuthStore((s) => s.lock)
  const entries = useVaultStore((s) => s.entries)
  const notes = useNoteStore((s) => s.notes)

  // Page transition key — triggers re-animation on route change
  const [transitionKey, setTransitionKey] = useState(location.pathname)
  const [isTransitioning, setIsTransitioning] = useState(false)

  useEffect(() => {
    if (location.pathname !== transitionKey) {
      setIsTransitioning(true)
      setTransitionKey(location.pathname)
      const timer = setTimeout(() => setIsTransitioning(false), 400)
      return () => clearTimeout(timer)
    }
    return undefined
  }, [location.pathname, transitionKey])

  const currentPath = location.pathname

  const handleLock = () => {
    lock()
    navigate('/')
  }

  // Compute storage usage from real data (placeholder values)
  const storageUsed = 2.46
  const storageTotal = 10
  const passwordCount = entries.length
  const noteCount = notes.length

  return (
    <div className="flex h-screen w-screen overflow-hidden" style={{ backgroundColor: 'var(--kestrel-bg, #F8FAFC)' }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '240px', backgroundColor: 'var(--kestrel-sidebar, #0F172A)' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4" style={{ padding: '20px 16px' }}>
          <img src="/kestrel-logo.png" alt="KESTREL" className="w-8 h-8 object-contain" />
          <div>
            <div className="text-sm font-bold tracking-widest" style={{ color: 'var(--kestrel-text-on-dark, #F8FAFC)', letterSpacing: '0.08em' }}>
              KESTREL
            </div>
            <div className="text-xs font-medium tracking-widest" style={{ color: 'var(--kestrel-text-on-dark-muted, #94A3B8)', letterSpacing: '0.15em' }}>
              VAULT
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item, index) => {
            const isActive = currentPath === item.path || (currentPath === '/' && item.path === '/dashboard')
            const Icon = item.icon
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-200 press-scale"
                style={{
                  backgroundColor: isActive ? 'var(--kestrel-sidebar-hover, #1E293B)' : 'transparent',
                  borderLeft: isActive ? '3px solid var(--kestrel-primary, #2563EB)' : '3px solid transparent',
                  color: isActive ? 'var(--kestrel-text-on-dark, #F8FAFC)' : 'var(--kestrel-text-on-dark-muted, #94A3B8)',
                  animationDelay: `${index * 30}ms`,
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.backgroundColor = 'var(--kestrel-sidebar-hover, #1E293B)'
                    e.currentTarget.style.color = 'var(--kestrel-text-on-dark, #F8FAFC)'
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.backgroundColor = 'transparent'
                    e.currentTarget.style.color = 'var(--kestrel-text-on-dark-muted, #94A3B8)'
                  }
                }}
              >
                <Icon size={18} />
                <span className="text-sm font-medium">{t(item.labelKey)}</span>
              </button>
            )
          })}
        </nav>

        {/* Bottom Section */}
        <div className="px-4 py-4 space-y-4" style={{ borderTop: '1px solid rgba(226, 232, 240, 0.15)' }}>
          {/* Status */}
          <div className="flex items-center gap-2">
            {appState === 'unlocked' ? (
              <>
                <Unlock size={14} style={{ color: 'var(--kestrel-success, #22C55E)' }} />
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted, #94A3B8)' }}>{t('sidebar.unlocked')}</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: 'var(--kestrel-success, #22C55E)' }} />
              </>
            ) : (
              <>
                <Lock size={14} style={{ color: 'var(--kestrel-danger, #EF4444)' }} />
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted, #94A3B8)' }}>{t('sidebar.locked')}</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: 'var(--kestrel-danger, #EF4444)' }} />
              </>
            )}
          </div>

          {/* Storage */}
          <div>
            <div className="flex justify-between text-xs mb-1" style={{ color: 'var(--kestrel-text-on-dark-muted, #94A3B8)' }}>
              <span>{t('sidebar.storage')}</span>
              <span>{storageUsed.toFixed(2)} / {storageTotal} GB</span>
            </div>
            <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-sidebar-hover, #1E293B)' }}>
              <div
                className="h-1.5 rounded-full transition-all duration-500"
                style={{
                  width: `${(storageUsed / storageTotal) * 100}%`,
                  backgroundColor: 'var(--kestrel-primary, #2563EB)',
                }}
              />
            </div>
            <div className="flex justify-between text-xs mt-1" style={{ color: 'var(--kestrel-text-muted, #64748B)' }}>
              <span>{passwordCount} {t('sidebar.passwords')}</span>
              <span>{noteCount} {t('sidebar.items')}</span>
            </div>
          </div>

          {/* Lock Button */}
          <button
            onClick={handleLock}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 press-scale"
            style={{ backgroundColor: 'var(--kestrel-primary, #2563EB)', color: '#FFFFFF' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary-hover, #1D4ED8)' }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary, #2563EB)' }}
          >
            <Lock size={16} />
            {t('sidebar.lockVault')}
          </button>
        </div>
      </aside>

      {/* Content Area with page transitions */}
      <main
        key={transitionKey}
        className={`flex-1 overflow-y-auto ${isTransitioning ? 'page-enter' : ''}`}
      >
        {children}
      </main>
    </div>
  )
}
