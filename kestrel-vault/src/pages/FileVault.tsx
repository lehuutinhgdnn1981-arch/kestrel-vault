import { useState } from 'react'
import { Search, Plus, HardDrive, FileText, Image, Archive, Database, Folder, Inbox, Lock, Copy, ChevronLeft, MoreHorizontal } from 'lucide-react'

const fileFolders = [
  { id: 'all', label: 'All Files', icon: HardDrive },
  { id: 'documents', label: 'Documents', icon: FileText },
  { id: 'images', label: 'Images', icon: Image },
  { id: 'archives', label: 'Archives', icon: Archive },
  { id: 'backups', label: 'Backups', icon: Database },
  { id: 'others', label: 'Others', icon: Folder },
]

export default function FileVault() {
  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  return (
    <div className="flex h-full animate-fade-in">
      <div className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}>
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Files</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
            <input type="text" placeholder="Search files..." value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: '#F8FAFC', paddingLeft: '32px', paddingRight: '10px', border: '1px solid #E2E8F0', color: '#0F172A' }} />
          </div>
          <button className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}>
            <Plus size={16} /> Upload
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-2">
          {fileFolders.map((folder) => {
            const isActive = activeFolder === folder.id
            const Icon = folder.icon
            return (
              <button key={folder.id} onClick={() => setActiveFolder(folder.id)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
                style={{ backgroundColor: isActive ? '#F8FAFC' : 'transparent', borderLeft: isActive ? '3px solid #2563EB' : '3px solid transparent', color: isActive ? '#0F172A' : '#64748B' }}>
                <Icon size={16} />
                <span className="text-sm flex-1">{folder.label}</span>
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex-1 flex flex-col items-center justify-center" style={{ backgroundColor: '#FFFFFF' }}>
        <div className="text-center px-6">
          <img src="/kestrel-logo.png" alt="" className="w-16 h-16 object-contain mb-4 mx-auto opacity-30" />
          <h3 className="text-lg font-semibold mb-2" style={{ color: '#0F172A' }}>File Vault</h3>
          <p className="text-sm" style={{ color: '#64748B' }}>
            Encrypted file storage coming soon.
          </p>
          <p className="text-xs mt-2" style={{ color: '#94A3B8' }}>
            Upload and encrypt files securely with AES-256-GCM.
          </p>
        </div>
      </div>
    </div>
  )
}
