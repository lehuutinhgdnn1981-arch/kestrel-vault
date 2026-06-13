import { useState, useEffect } from 'react'
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
} from 'lucide-react'
import { useVaultStore } from '@/stores/vault-store'
import { useAuthStore } from '@/stores/auth-store'
import { vaultCommands, folderCommands } from '@/lib/tauri'

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
  const folders = useVaultStore((s) => s.folders)
  const fetchFolders = useVaultStore((s) => s.fetchFolders)
  const appState = useAuthStore((s) => s.appState)

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
  const [isAdding, setIsAdding] = useState(false)

  // Edit mode state
  const [editMode, setEditMode] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editUsername, setEditUsername] = useState('')
  const [editPassword, setEditPassword] = useState('')
  const [editUrl, setEditUrl] = useState('')
  const [editNotes, setEditNotes] = useState('')
  const [isSaving, setIsSaving] = useState(false)

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
      )
      setShowAddDialog(false)
      setNewTitle('')
      setNewUsername('')
      setNewPassword('')
      setNewUrl('')
      setNewNotes('')
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
    setEditMode(true)
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
      } = {}
      if (editTitle !== selectedItem.title) updates.title = editTitle
      if (editUsername !== selectedItem.username) updates.username = editUsername
      if (editPassword) updates.password = editPassword
      if (editUrl !== (selectedItem.url ?? '')) updates.url = editUrl
      if (editNotes !== (selectedItem.notes_preview ?? '')) updates.notes = editNotes

      await vaultCommands.updateEntry(selectedItem.id, updates)
      setEditMode(false)
      setRevealedPassword(null)
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
          <button
            onClick={() => setShowAddDialog(true)}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}>
            <Plus size={16} /> Add Item
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-2">
          {/* All Items */}
          <button
            onClick={() => setActiveFolder('all')}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
            style={{
              backgroundColor: activeFolder === 'all' ? '#F8FAFC' : 'transparent',
              borderLeft: activeFolder === 'all' ? '3px solid #2563EB' : '3px solid transparent',
              color: activeFolder === 'all' ? '#0F172A' : '#64748B',
            }}
          >
            <List size={16} />
            <span className="text-sm flex-1">All Items</span>
          </button>

          {/* No Folder */}
          <button
            onClick={() => setActiveFolder('none')}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
            style={{
              backgroundColor: activeFolder === 'none' ? '#F8FAFC' : 'transparent',
              borderLeft: activeFolder === 'none' ? '3px solid #2563EB' : '3px solid transparent',
              color: activeFolder === 'none' ? '#0F172A' : '#64748B',
            }}
          >
            <Inbox size={16} />
            <span className="text-sm flex-1">No Folder</span>
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
                  backgroundColor: isActive ? '#F8FAFC' : 'transparent',
                  borderLeft: isActive ? '3px solid #2563EB' : '3px solid transparent',
                  color: isActive ? '#0F172A' : '#64748B',
                }}
              >
                <FolderIcon size={16} />
                <span className="text-sm flex-1">{folder.name}</span>
              </button>
            )
          })}
          <div className="px-3 py-2">
            <button onClick={handleCreateFolder} className="text-sm font-medium" style={{ color: '#2563EB' }}>+ New Folder</button>
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
              {activeFolder === 'all' ? 'All Items' : activeFolder === 'none' ? 'No Folder' : folders.find((f) => f.id === activeFolder)?.name || 'All Items'}
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
        ) : editMode ? (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-5" style={{ borderBottom: '1px solid #E2E8F0' }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>Edit Entry</h3>
                <div className="flex items-center gap-1">
                  <button onClick={handleSaveEdit} disabled={isSaving}
                    className="px-3 h-8 rounded-lg text-xs font-medium transition-colors"
                    style={{ backgroundColor: '#2563EB', color: '#FFFFFF', opacity: isSaving ? 0.6 : 1 }}>
                    {isSaving ? 'Saving...' : 'Save'}
                  </button>
                  <button onClick={() => setEditMode(false)}
                    className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
                    <X size={15} />
                  </button>
                </div>
              </div>
            </div>

            <div className="p-5 space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Title</label>
                <input type="text" value={editTitle} onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Username</label>
                <input type="text" value={editUsername} onChange={(e) => setEditUsername(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Password</label>
                <input type="password" value={editPassword} onChange={(e) => setEditPassword(e.target.value)}
                  placeholder="Leave blank to keep current"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Website</label>
                <input type="text" value={editUrl} onChange={(e) => setEditUrl(e.target.value)}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Notes</label>
                <textarea value={editNotes} onChange={(e) => setEditNotes(e.target.value)}
                  className="w-full h-20 rounded-lg text-sm outline-none p-3 resize-none"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
            </div>
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
                  <button onClick={handleStartEdit} className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
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

      {/* Add Item Dialog */}
      {showAddDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.4)' }}>
          <div className="rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 8px 30px rgb(0 0 0 / 0.12)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Add New Item</h3>
              <button onClick={() => setShowAddDialog(false)} className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: '#64748B' }}>
                <X size={16} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Title *</label>
                <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Google"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Username *</label>
                <input type="text" value={newUsername} onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. user@example.com"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Password *</label>
                <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter password"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Website</label>
                <input type="text" value={newUrl} onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="e.g. google.com"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Notes</label>
                <textarea value={newNotes} onChange={(e) => setNewNotes(e.target.value)}
                  placeholder="Optional notes"
                  className="w-full h-20 rounded-lg text-sm outline-none p-3 resize-none"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 mt-6">
              <button onClick={() => setShowAddDialog(false)}
                className="px-4 h-9 rounded-lg text-sm font-medium"
                style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}>
                Cancel
              </button>
              <button onClick={handleAddEntry} disabled={isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim()}
                className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                style={{
                  backgroundColor: isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim() ? '#E2E8F0' : '#2563EB',
                  color: isAdding || !newTitle.trim() || !newUsername.trim() || !newPassword.trim() ? '#94A3B8' : '#FFFFFF',
                }}>
                {isAdding ? 'Adding...' : 'Add Item'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
