import { useState } from 'react'
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
import { useVaultStore } from '../store/useVaultStore'
import type { VaultItem } from '../store/useVaultStore'

const folders = [
  { id: 'all', label: 'All Items', icon: List, count: 95 },
  { id: 'social', label: 'Social', icon: Users, count: 8 },
  { id: 'work', label: 'Work', icon: Briefcase, count: 23 },
  { id: 'finance', label: 'Finance', icon: CreditCard, count: 6 },
  { id: 'personal', label: 'Personal', icon: User, count: 47 },
  { id: 'none', label: 'No Folder', icon: Inbox, count: 0 },
]

const avatarColors: Record<string, string> = {
  Google: '#4285F4', Facebook: '#1877F2', GitHub: '#333333', Discord: '#5865F2',
  Netflix: '#E50914', Spotify: '#1DB954', Twitter: '#1DA1F2', 'AWS Console': '#FF9900',
}

export default function PasswordVault() {
  const { vaultItems, selectedVaultItem, setSelectedVaultItem } = useVaultStore()
  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [showPassword, setShowPassword] = useState<Record<string, boolean>>({})
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const filteredItems = vaultItems.filter((item: VaultItem) => {
    const matchesFolder = activeFolder === 'all' ||
      (activeFolder === 'social' && item.folder === 'Social') ||
      (activeFolder === 'work' && item.folder === 'Work') ||
      (activeFolder === 'personal' && item.folder === 'Personal') ||
      (activeFolder === 'finance' && item.folder === 'Finance') ||
      (activeFolder === 'none' && !item.folder)
    const matchesSearch = !searchQuery ||
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.website.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesFolder && matchesSearch
  })

  const selectedItem = vaultItems.find((i: VaultItem) => i.id === selectedVaultItem)

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 1000)
  }

  return (
    <div className="flex h-full animate-fade-in">
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}
      >
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
          <button
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}
          >
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
                <span className="text-xs" style={{ color: '#94A3B8' }}>{folder.count}</span>
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
          <span className="text-xs" style={{ color: '#94A3B8' }}>Locked</span>
        </div>
      </div>

      <div
        className="flex flex-col h-full flex-1"
        style={{ borderRight: '1px solid #E2E8F0', minWidth: '320px', backgroundColor: '#FFFFFF' }}
      >
        <div
          className="flex items-center justify-between px-4 py-3"
          style={{ borderBottom: '1px solid #E2E8F0' }}
        >
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold" style={{ color: '#0F172A' }}>
              {folders.find((f) => f.id === activeFolder)?.label || 'All Items'}
            </h3>
            <span
              className="text-xs px-2 py-0.5 rounded-full"
              style={{ backgroundColor: '#F1F5F9', color: '#64748B' }}
            >
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
            filteredItems.map((item: VaultItem) => {
              const isSelected = selectedVaultItem === item.id
              const color = avatarColors[item.title] || '#64748B'
              return (
                <button
                  key={item.id}
                  onClick={() => setSelectedVaultItem(item.id)}
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
                    <p className="text-xs" style={{ color: '#94A3B8' }}>{selectedItem.website}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
                    <Pencil size={15} />
                  </button>
                  <button className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
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
                  <button
                    onClick={() => handleCopy(selectedItem.username, 'username')}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors"
                    style={{ color: '#64748B' }}
                  >
                    {copiedField === 'username' ? <span className="text-xs text-green-600">Copied</span> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Password</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm flex-1" style={{ color: '#0F172A' }}>
                    {showPassword[selectedItem.id] ? 'mySecureP@ss123!' : selectedItem.password}
                  </span>
                  <button
                    onClick={() => setShowPassword((p) => ({ ...p, [selectedItem.id]: !p[selectedItem.id] }))}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors"
                    style={{ color: '#64748B' }}
                  >
                    {showPassword[selectedItem.id] ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    onClick={() => handleCopy('mySecureP@ss123!', 'password')}
                    className="w-7 h-7 flex items-center justify-center rounded-md transition-colors"
                    style={{ color: '#64748B' }}
                  >
                    {copiedField === 'password' ? <span className="text-xs text-green-600">Copied</span> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Website</label>
                <a
                  href={`https://${selectedItem.website}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm hover:underline"
                  style={{ color: '#2563EB' }}
                >
                  {selectedItem.website}
                </a>
              </div>

              {selectedItem.notes && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Notes</label>
                  <p className="text-sm" style={{ color: '#475569' }}>{selectedItem.notes}</p>
                </div>
              )}

              {selectedItem.tags.length > 0 && (
                <div>
                  <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Tags</label>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedItem.tags.map((tag: string) => (
                      <span
                        key={tag}
                        className="text-xs px-2.5 py-0.5 rounded-full"
                        style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#475569' }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="mt-auto p-5" style={{ borderTop: '1px solid #E2E8F0' }}>
              <div className="space-y-1">
                <p className="text-xs" style={{ color: '#94A3B8' }}>Folder: {selectedItem.folder}</p>
                <p className="text-xs" style={{ color: '#94A3B8' }}>Updated: {selectedItem.updatedAt}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
