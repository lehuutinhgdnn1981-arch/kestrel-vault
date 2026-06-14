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
import { useState, useEffect } from 'react'
import { useI18n } from '@/hooks/use-i18n'
import { useAuthStore } from '@/stores/auth-store'
import { useVaultStore } from '@/stores/vault-store'
import { useNoteStore } from '@/stores/note-store'
import { fileCommands } from '@/lib/tauri'
import SearchDialog from '@/components/SearchDialog'
import NotificationDropdown from '@/components/NotificationDropdown'

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const appState = useAuthStore((s) => s.appState)
  const lock = useAuthStore((s) => s.lock)
  const entries = useVaultStore((s) => s.entries)
  const notes = useNoteStore((s) => s.notes)
  const [fileCount, setFileCount] = useState(0)
  const [storageUsed, setStorageUsed] = useState(0)
  const [searchOpen, setSearchOpen] = useState(false)
  const { t } = useI18n()

  const navItems = [
    { path: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
    { path: '/vault', label: t('nav.vault'), icon: Shield },
    { path: '/files', label: t('nav.files'), icon: FileText },
    { path: '/notes', label: t('nav.notes'), icon: StickyNote },
    { path: '/security', label: t('nav.security'), icon: ShieldCheck },
    { path: '/scanner', label: t('nav.scanner'), icon: Search },
    { path: '/audit', label: t('nav.audit'), icon: ScrollText },
    { path: '/settings', label: t('nav.settings'), icon: Settings },
  ]

  const ROUTE_LABELS: Record<string, string> = {
    '/dashboard': t('nav.dashboard'),
    '/vault': t('nav.vault'),
    '/files': t('nav.files'),
    '/notes': t('nav.notes'),
    '/security': t('nav.security'),
    '/scanner': t('nav.scanner'),
    '/audit': t('nav.audit'),
    '/settings': t('nav.settings'),
  }

  useEffect(() => {
    if (appState === 'unlocked') {
      fileCommands.list().then((files) => {
        setFileCount(files.length)
        const totalBytes = files.reduce((sum, f) => sum + f.size_bytes, 0)
        setStorageUsed(totalBytes / (1024 * 1024 * 1024))
      }).catch(() => {})
    }
  }, [appState])

  const currentPath = location.pathname

  const handleLock = () => {
    lock()
    navigate('/')
  }

  // Compute storage usage from real data
  const storageTotal = 10
  const passwordCount = entries.length
  const noteCount = notes.length

  // Get page title from current route
  const pageTitle = ROUTE_LABELS[currentPath] || t('nav.dashboard')

  // Ctrl+F shortcut to open search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault()
        setSearchOpen(true)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  return (
    <div className="flex h-screen w-screen overflow-hidden" style={{ backgroundColor: 'var(--kestrel-bg)' }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '240px', backgroundColor: 'var(--kestrel-sidebar)' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4" style={{ padding: '20px 16px' }}>
          <img src="/kestrel-logo.png" alt="KESTREL" className="w-8 h-8 object-contain" />
          <div>
            <div className="text-sm font-bold tracking-widest" style={{ color: 'var(--kestrel-text-on-dark)', letterSpacing: '0.08em' }}>
              KESTREL
            </div>
            <div className="text-xs font-medium tracking-widest" style={{ color: 'var(--kestrel-text-on-dark-muted)', letterSpacing: '0.15em' }}>
              VAULT
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = currentPath === item.path || (currentPath === '/' && item.path === '/dashboard')
            const Icon = item.icon
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150"
                style={{
                  backgroundColor: isActive ? 'var(--kestrel-sidebar-hover)' : 'transparent',
                  borderLeft: isActive ? `3px solid var(--kestrel-primary)` : '3px solid transparent',
                  color: isActive ? 'var(--kestrel-text-on-dark)' : 'var(--kestrel-text-on-dark-muted)',
                }}
                onMouseEnter={(e) => {
                  if (!isActive) e.currentTarget.style.backgroundColor = 'var(--kestrel-sidebar-hover)'
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
            {appState === 'unlocked' ? (
              <>
                <Unlock size={14} style={{ color: 'var(--kestrel-success)' }} />
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('sidebar.unlocked')}</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: 'var(--kestrel-success)' }} />
              </>
            ) : (
              <>
                <Lock size={14} style={{ color: 'var(--kestrel-danger)' }} />
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('sidebar.locked')}</span>
                <span className="w-2 h-2 rounded-full ml-auto" style={{ backgroundColor: 'var(--kestrel-danger)' }} />
              </>
            )}
          </div>

          {/* Storage */}
          <div>
            <div className="flex justify-between text-xs mb-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
              <span>{t('sidebar.storage')}</span>
              <span>{storageUsed > 0 ? storageUsed.toFixed(2) : '0.00'} / {storageTotal} GB</span>
            </div>
            <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-sidebar-hover)' }}>
              <div
                className="h-1.5 rounded-full transition-all duration-300"
                style={{
                  width: `${(storageUsed / storageTotal) * 100}%`,
                  backgroundColor: 'var(--kestrel-primary)',
                }}
              />
            </div>
            <div className="flex justify-between text-xs mt-1" style={{ color: 'var(--kestrel-text-light)' }}>
              <span>{passwordCount} {t('sidebar.passwords')}</span>
              <span>{fileCount + noteCount} {t('sidebar.items')}</span>
            </div>
          </div>

          {/* Lock Button */}
          <button
            onClick={handleLock}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150"
            style={{ backgroundColor: 'var(--kestrel-primary)', color: '#FFFFFF' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary-hover)' }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-primary)' }}
          >
            <Lock size={16} />
            {t('sidebar.lockVault')}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <header
          className="flex items-center justify-between px-6 flex-shrink-0"
          style={{ height: '52px', backgroundColor: 'var(--kestrel-surface)', borderBottom: '1px solid var(--kestrel-border)' }}
        >
          <div className="flex items-center gap-3">
            <h2 className="text-base font-semibold" style={{ color: 'var(--kestrel-text)' }}>{pageTitle}</h2>
          </div>
          <div className="flex items-center gap-3">
            {/* Search Button */}
            <button
              onClick={() => setSearchOpen(true)}
              className="flex items-center gap-2 px-3 h-9 rounded-lg transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-border-subtle)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-hover-bg)' }}
              title={t('topbar.search')}
            >
              <Search size={15} style={{ color: 'var(--kestrel-text-muted)' }} />
              <span className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('topbar.search')}</span>
              <kbd
                className="text-xs px-1.5 py-0.5 rounded ml-4"
                style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text-on-dark-muted)', border: '1px solid var(--kestrel-border)' }}
              >
                {t('topbar.searchShortcut')}
              </kbd>
            </button>

            {/* Notification Bell */}
            <NotificationDropdown />

            {/* Lock Quick Button */}
            <button
              onClick={handleLock}
              className="w-9 h-9 flex items-center justify-center rounded-lg transition-colors duration-150"
              style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-danger-subtle)'; e.currentTarget.style.borderColor = 'var(--kestrel-danger)' }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--kestrel-surface)'; e.currentTarget.style.borderColor = 'var(--kestrel-border)' }}
              title={t('topbar.lockVault')}
            >
              <Lock size={15} style={{ color: 'var(--kestrel-text-muted)' }} />
            </button>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto animate-fade-in">
          {children}
        </main>
      </div>

      {/* Global Search Dialog */}
      <SearchDialog isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  )
}
