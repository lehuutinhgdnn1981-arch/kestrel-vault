import { useState, useEffect } from 'react'
import {
  Search,
  Plus,
  List,
  Users,
  Briefcase,
  CreditCard,
  User,
  Inbox,
  Copy,
  Eye,
  EyeOff,
  Pencil,
  Trash2,
  ChevronDown,
} from 'lucide-react'
import { useVaultStore } from '@/stores/vault-store'
import { useAuthStore } from '@/stores/auth-store'
import { vaultCommands } from '@/lib/tauri'

const folders = [
  { id: 'all', label: 'All Items', icon: List },
  { id: 'social', label: 'Social', icon: Users },
  { id: 'work', label: 'Work', icon: Briefcase },
  { id: 'finance', label: 'Finance', icon: CreditCard },
  { id: 'personal', label: 'Personal', icon: User },
  { id: 'none', label: 'No Folder', icon: Inbox },
]

const avatarColors: Record<string, string> = {
  Google: '#4285F4', Facebook: '#1877F2', GitHub: '#333333', Discord: '#5865F2',
  Netflix: '#E50914', Spotify: '#1DB954', Twitter: '#1DA1F2', 'AWS Console': '#FF9900',
}

export default function PasswordVault() {
  const entries = useVaultStore((s) => s.entries)
  const fetchEntries = useVaultStore((s) => s.fetchEntries)
  const deleteEntry = useVaultStore((s) => s.deleteEntry)
  const selectedEntryId = useVaultStore((s) => s.selectedEntryId)
  const selectEntry = useVaultStore((s) => s.selectEntry)
  const appState = useAuthStore((s) => s.appState)

  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [revealedPassword, setRevealedPassword] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  useEffect(() => {
    if (appState === 'unlocked') fetchEntries()
  }, [appState, fetchEntries])

  const filteredItems = entries.filter((item) => {
    const matchesSearch = !searchQuery ||
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.url ?? '').toLowerCase().includes(searchQuery.toLowerCase())

    // Filter by folder (based on URL domain heuristic)
    const domain = (item.url ?? '').toLowerCase()
    const matchesFolder = activeFolder === 'all' ||
      (activeFolder === 'social' && (domain.includes('facebook') || domain.includes('twitter') || domain.includes('discord') || domain.includes('instagram'))) ||
      (activeFolder === 'work' && (domain.includes('github') || domain.includes('aws') || domain.includes('slack') || domain.includes('jira'))) ||
      (activeFolder === 'finance' && (domain.includes('bank') || domain.includes('paypal') || domain.includes('stripe'))) ||
      (activeFolder === 'personal' && (domain.includes('netflix') || domain.includes('spotify') || domain.includes('gmail') || domain.includes('google'))) ||
      (activeFolder === 'none' && !item.url)

    return matchesFolder && matchesSearch
  })

  const selectedItem = entries.find((e) => e.id === selectedEntryId) ?? null

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 1000)
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

  return (
    <div className="flex h-full animate-fade-in">
      {/* Folder sidebar */}
      <div className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}>
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Vault</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
            <input
              type="text"
              placeholder="Search vault..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: '#F8FAFC', paddingLeft: '32px', paddingRight: '10px', border: '1px solid #E2E8F0', color: '#0F172A' }}
            />
          </div>
          <button className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}>
            <Plus size={16} /> Add Item
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-2">
          {folders.map((folder) => {
            const isActive = activeFolder === folder.id
            const Icon = folder.icon
            return (
              <button
                key={folder.id}
                onClick={() => setActiveFolder(folder.id)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
                style={{
                  backgroundColor: isActive ? '#F8FAFC' : 'transparent',
                  borderLeft: isActive ? '3px solid #2563EB' : '3px solid transparent',
                  color: isActive ? '#0F172A' : '#64748B',
                }}
              >
                <Icon size={16} />
                <span className="text-sm flex-1">{folder.label}</span>
              </button>
            )
          })}
          <div className="px-3 py-2">
            <button className="text-sm font-medium" style={{ color: '#2563EB' }}>+ New Folder</button>
          </div>
        </div>

        <div className="p-4 flex items-center gap-2" style={{ borderTop: '1px solid #E2E8F0' }}>
          <div className="w-5 h-5 rounded flex items-center justify-center" style={{ backgroundColor: '#0F172A' }}>
            <img src="/kestrel-logo.png" alt="" className="w-3 h-3 object-contain" />
          </div>
          <span className="text-xs" style={{ color: '#94A3B8' }}>{entries.length} entries</span>
        </div>
      </div>

      {/* Entry list */}
      <div className="flex flex-col h-full flex-1"
        style={{ borderRight: '1px solid #E2E8F0', minWidth: '320px', backgroundColor: '#FFFFFF' }}>
        <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #E2E8F0' }}>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold" style={{ color: '#0F172A' }}>
              {folders.find((f) => f.id === activeFolder)?.label || 'All Items'}
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: '#F1F5F9', color: '#64748B' }}>
              {filteredItems.length}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-1 text-xs px-2 py-1 rounded" style={{ color: '#64748B', border: '1px solid #E2E8F0' }}>
              Sort by: Name <ChevronDown size={12} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center px-6">
              <Inbox size={32} style={{ color: '#CBD5E1' }} className="mb-3" />
              <p className="text-sm font-medium" style={{ color: '#64748B' }}>No items found</p>
              <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>Add a new password or try a different search</p>
            </div>
          ) : (
            filteredItems.map((item) => {
              const isSelected = selectedEntryId === item.id
              const color = avatarColors[item.title] || '#64748B'
              return (
                <button
                  key={item.id}
                  onClick={() => selectEntry(item.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors duration-150"
                  style={{
                    backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.05)' : 'transparent',
                    borderLeft: isSelected ? '3px solid #2563EB' : '3px solid transparent',
                    borderBottom: '1px solid #F1F5F9',
                  }}
                >
                  <div
                    className="w-9 h-9 rounded-full flex items-center justify-center text-white text-xs font-semibold flex-shrink-0"
                    style={{ backgroundColor: color }}
                  >
                    {item.title[0]}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate" style={{ color: '#0F172A' }}>{item.title}</div>
                    <div className="text-xs truncate" style={{ color: '#94A3B8' }}>{item.username}</div>
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* Detail panel */}
      <div className="flex flex-col h-full" style={{ width: '360px', backgroundColor: '#FFFFFF' }}>
        {!selectedItem ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <img src="/kestrel-logo.png" alt="" className="w-12 h-12 object-contain mb-3 opacity-30" />
            <p className="text-sm" style={{ color: '#94A3B8' }}>Select an item to view details</p>
          </div>
        ) : (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-5" style={{ borderBottom: '1px solid #E2E8F0' }}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div
                    className="w-12 h-12 rounded-full flex items-center justify-center text-white text-base font-semibold"
                    style={{ backgroundColor: avatarColors[selectedItem.title] || '#64748B' }}
                  >
                    {selectedItem.title[0]}
                  </div>
                  <div>
                    <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>{selectedItem.title}</h3>
                    <p className="text-xs" style={{ color: '#94A3B8' }}>{selectedItem.url ?? 'No website'}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
                    <Pencil size={15} />
                  </button>
                  <button onClick={() => handleDelete(selectedItem.id)} className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            </div>

            <div className="p-5 space-y-5">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Username</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm flex-1" style={{ color: '#0F172A' }}>{selectedItem.username}</span>
                  <button onClick={() => handleCopy(selectedItem.username, 'username')}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: '#64748B' }}>
                    {copiedField === 'username' ? <span className="text-xs text-green-600">Copied</span> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Password</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm flex-1" style={{ color: '#0F172A' }}>
                    {revealedPassword ?? '••••••••••••'}
                  </span>
                  <button onClick={() => handleRevealPassword(selectedItem.id)}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: '#64748B' }}>
                    {revealedPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  {revealedPassword && (
                    <button onClick={() => handleCopy(revealedPassword, 'password')}
                      className="w-7 h-7 flex items-center justify-center rounded-md transition-colors" style={{ color: '#64748B' }}>
                      {copiedField === 'password' ? <span className="text-xs text-green-600">Copied</span> : <Copy size={14} />}
                    </button>
                  )}
                </div>
              </div>

              {selectedItem.url && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Website</label>
                  <a href={`https://${selectedItem.url}`} target="_blank" rel="noopener noreferrer"
                    className="text-sm hover:underline" style={{ color: '#2563EB' }}>
                    {selectedItem.url}
                  </a>
                </div>
              )}

              {selectedItem.notes_preview && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Notes</label>
                  <p className="text-sm" style={{ color: '#475569' }}>{selectedItem.notes_preview}</p>
                </div>
              )}
            </div>

            <div className="mt-auto p-5" style={{ borderTop: '1px solid #E2E8F0' }}>
              <div className="space-y-1">
                <p className="text-xs" style={{ color: '#94A3B8' }}>Created: {new Date(selectedItem.created_at).toLocaleDateString()}</p>
                <p className="text-xs" style={{ color: '#94A3B8' }}>Updated: {new Date(selectedItem.updated_at).toLocaleDateString()}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
