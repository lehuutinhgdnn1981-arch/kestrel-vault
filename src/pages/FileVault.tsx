import { useState } from 'react'
import {
  Search,
  Plus,
  HardDrive,
  FileText,
  Image,
  Archive,
  Database,
  Folder,
  Lock,
  Copy,
  ChevronLeft,
  MoreHorizontal,
} from 'lucide-react'

// NOTE: File vault backend commands do not exist yet.
// This page uses demo data until file-related Tauri commands are implemented.
// When backend file commands are added, replace demoFiles with real data
// fetched via the Tauri IPC layer.

const fileFolders = [
  { id: 'all', label: 'All Files', icon: HardDrive, count: 8 },
  { id: 'documents', label: 'Documents', icon: FileText, count: 4 },
  { id: 'images', label: 'Images', icon: Image, count: 2 },
  { id: 'archives', label: 'Archives', icon: Archive, count: 1 },
  { id: 'backups', label: 'Backups', icon: Database, count: 0 },
  { id: 'others', label: 'Others', icon: Folder, count: 1 },
]

// Demo files until backend integration
const demoFiles = [
  { id: '1', name: 'report.pdf', size: '2.1 MB', type: 'PDF', folder: 'Documents', modified: '2 min ago', risk: 'safe' as const, encrypted: true, sha256: 'a1b2c3d4e5f6789012345678901234567890abcd' },
  { id: '2', name: 'design-system.fig', size: '18.6 MB', type: 'FIG', folder: 'Documents', modified: '1 hour ago', risk: 'safe' as const, encrypted: true, sha256: 'b2c3d4e5f6789012345678901234567890abcdef' },
  { id: '3', name: 'photo.jpg', size: '3.4 MB', type: 'JPG', folder: 'Images', modified: '2 hours ago', risk: 'safe' as const, encrypted: true, sha256: 'c3d4e5f6789012345678901234567890abcdef01' },
  { id: '4', name: 'backup.zip', size: '512 MB', type: 'ZIP', folder: 'Archives', modified: '1 day ago', risk: 'safe' as const, encrypted: true, sha256: 'd4e5f6789012345678901234567890abcdef0123' },
  { id: '5', name: 'invoice-2024.pdf', size: '1.2 MB', type: 'PDF', folder: 'Documents', modified: '2 days ago', risk: 'safe' as const, encrypted: true, sha256: 'e5f6789012345678901234567890abcdef012345' },
  { id: '6', name: 'diagram.png', size: '1.8 MB', type: 'PNG', folder: 'Images', modified: '3 days ago', risk: 'safe' as const, encrypted: true, sha256: 'f6789012345678901234567890abcdef01234567' },
]

const fileTypeColors: Record<string, string> = {
  PDF: '#EF4444', FIG: '#F59E0B', JPG: '#8B5CF6', PNG: '#8B5CF6',
  ZIP: '#F59E0B', CSV: '#22C55E', PPTX: '#EF4444',
}

const riskConfig: Record<string, { color: string; bg: string; label: string }> = {
  safe: { color: '#22C55E', bg: 'rgba(34, 197, 94, 0.1)', label: 'Safe' },
  warning: { color: '#F59E0B', bg: 'rgba(245, 158, 11, 0.1)', label: 'Warning' },
  danger: { color: '#EF4444', bg: 'rgba(239, 68, 68, 0.1)', label: 'Danger' },
  unknown: { color: '#94A3B8', bg: 'rgba(148, 163, 184, 0.1)', label: 'Unknown' },
}

const storageUsed = 2.46
const storageTotal = 10

export default function FileVault() {
  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null)
  const [showComingSoon, setShowComingSoon] = useState(false)

  const filteredFiles = demoFiles.filter((file) => {
    const matchesFolder = activeFolder === 'all' ||
      (activeFolder === 'documents' && file.folder === 'Documents') ||
      (activeFolder === 'images' && file.folder === 'Images') ||
      (activeFolder === 'archives' && file.folder === 'Archives') ||
      (activeFolder === 'others' && file.folder === 'Others')
    const matchesSearch = !searchQuery || file.name.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesFolder && matchesSearch
  })

  const selectedFileData = demoFiles.find((f) => f.id === selectedFileId) ?? null

  return (
    <div className="flex h-full animate-fade-in">
      {/* Folder sidebar */}
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}
      >
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Files</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
            <input
              type="text"
              placeholder="Search files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: '#F8FAFC', paddingLeft: '32px', paddingRight: '10px', border: '1px solid #E2E8F0', color: '#0F172A' }}
            />
          </div>
          <button
            onClick={() => setShowComingSoon(true)}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#E2E8F0', color: '#94A3B8', cursor: 'not-allowed' }}
            title="File upload coming soon — backend file commands not yet available"
          >
            <Plus size={16} /> Upload
          </button>
          {showComingSoon && (
            <div className="text-xs text-center py-1 px-2 rounded" style={{ backgroundColor: '#FEF3C7', color: '#92400E' }}>
              File upload coming soon
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto px-2">
          {fileFolders.map((folder) => {
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
        </div>

        <div className="p-4" style={{ borderTop: '1px solid #E2E8F0' }}>
          <p className="text-xs mb-2" style={{ color: '#64748B' }}>Total {demoFiles.length} files</p>
          <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: '#F1F5F9' }}>
            <div
              className="h-1.5 rounded-full"
              style={{ width: `${(storageUsed / storageTotal) * 100}%`, backgroundColor: '#2563EB' }}
            />
          </div>
          <p className="text-xs mt-1" style={{ color: '#94A3B8' }}>{storageUsed.toFixed(2)} GB / {storageTotal} GB</p>
        </div>
      </div>

      {/* File list */}
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
              {fileFolders.find((f) => f.id === activeFolder)?.label || 'All Files'}
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: '#F1F5F9', color: '#64748B' }}>
              {filteredFiles.length}
            </span>
          </div>
        </div>

        <div
          className="grid items-center px-4 py-2 text-xs font-medium"
          style={{ gridTemplateColumns: '1fr 80px 100px 80px', color: '#64748B', borderBottom: '1px solid #F1F5F9' }}
        >
          <span>Name</span>
          <span>Size</span>
          <span>Modified</span>
          <span>Risk</span>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredFiles.map((file) => {
            const isSelected = selectedFileId === file.id
            const color = fileTypeColors[file.type] || '#64748B'
            const risk = riskConfig[file.risk] ?? riskConfig.unknown
            return (
              <button
                key={file.id}
                onClick={() => setSelectedFileId(file.id)}
                className="w-full grid items-center px-4 py-3 text-left transition-colors duration-150"
                style={{
                  gridTemplateColumns: '1fr 80px 100px 80px',
                  backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.05)' : 'transparent',
                  borderLeft: isSelected ? '3px solid #2563EB' : '3px solid transparent',
                  borderBottom: '1px solid #F1F5F9',
                }}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className="w-7 h-7 rounded flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: `${color}15` }}
                  >
                    <span className="text-xs font-semibold" style={{ color }}>{file.type}</span>
                  </div>
                  <span className="text-sm truncate" style={{ color: '#0F172A' }}>{file.name}</span>
                </div>
                <span className="text-xs" style={{ color: '#64748B' }}>{file.size}</span>
                <span className="text-xs" style={{ color: '#94A3B8' }}>{file.modified}</span>
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: risk.color }} />
                  <span className="text-xs" style={{ color: risk.color }}>{risk.label}</span>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Detail panel */}
      <div className="flex flex-col h-full" style={{ width: '380px', backgroundColor: '#FFFFFF' }}>
        {!selectedFileData ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <img src="/kestrel-logo.png" alt="" className="w-12 h-12 object-contain mb-3 opacity-30" />
            <p className="text-sm" style={{ color: '#94A3B8' }}>Select a file to preview</p>
          </div>
        ) : (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid #E2E8F0' }}>
              <button
                onClick={() => setSelectedFileId(null)}
                className="flex items-center gap-1 text-sm"
                style={{ color: '#64748B' }}
              >
                <ChevronLeft size={16} /> Files
              </button>
              <div className="flex items-center gap-2">
                <button
                  className="h-8 px-3 rounded-lg text-sm font-medium transition-colors"
                  style={{ backgroundColor: '#E2E8F0', color: '#94A3B8', cursor: 'not-allowed' }}
                  title="Coming soon — backend file commands not yet available"
                >
                  Decrypt
                </button>
                <button className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: '#64748B' }}>
                  <MoreHorizontal size={16} />
                </button>
              </div>
            </div>

            <div className="p-5">
              <div className="flex flex-col items-center mb-5">
                <div
                  className="w-16 h-16 rounded-xl flex items-center justify-center mb-3"
                  style={{ backgroundColor: `${fileTypeColors[selectedFileData.type] || '#64748B'}15` }}
                >
                  <span className="text-lg font-bold" style={{ color: fileTypeColors[selectedFileData.type] || '#64748B' }}>
                    {selectedFileData.type}
                  </span>
                </div>
                <h3 className="text-base font-semibold" style={{ color: '#0F172A' }}>{selectedFileData.name}</h3>
                <span
                  className="text-xs px-2.5 py-0.5 rounded-full mt-2 flex items-center gap-1"
                  style={{ backgroundColor: 'rgba(37, 99, 235, 0.1)', color: '#2563EB' }}
                >
                  <Lock size={10} /> Encrypted File
                </span>
              </div>

              <div className="space-y-3">
                {[
                  { label: 'Status', value: 'Encrypted', dotColor: '#2563EB' },
                  { label: 'Risk Level', value: 'Low Risk', dotColor: '#22C55E' },
                  { label: 'Size', value: selectedFileData.size },
                  { label: 'Type', value: `${selectedFileData.type} Document` },
                  { label: 'SHA256', value: selectedFileData.sha256, mono: true },
                  { label: 'Folder', value: selectedFileData.folder },
                ].map((field) => (
                  <div key={field.label} className="flex items-start gap-3">
                    <span className="text-xs font-medium w-20 flex-shrink-0" style={{ color: '#64748B' }}>
                      {field.label}
                    </span>
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      {field.dotColor && !field.mono && (
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: field.dotColor }} />
                      )}
                      <span
                        className={`text-sm truncate ${field.mono ? 'font-mono-geist text-xs' : ''}`}
                        style={{ color: field.mono ? '#475569' : '#0F172A' }}
                      >
                        {field.value}
                      </span>
                      {field.label === 'SHA256' && (
                        <button
                          onClick={() => navigator.clipboard.writeText(selectedFileData.sha256)}
                          className="flex-shrink-0"
                          style={{ color: '#64748B' }}
                        >
                          <Copy size={12} />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div
                className="mt-5 rounded-xl p-6 text-center"
                style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}
              >
                <FileText size={32} style={{ color: '#CBD5E1' }} className="mx-auto mb-2" />
                <p className="text-sm font-medium" style={{ color: '#64748B' }}>Encrypted File</p>
                <p className="text-xs mt-3" style={{ color: '#94A3B8' }}>Preview requires decryption</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
