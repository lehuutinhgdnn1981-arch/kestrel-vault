import { useState, useEffect, useCallback } from 'react'
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
  Unlock,
  ChevronLeft,
  Trash2,
  AlertTriangle,
  CheckCircle,
  X,
} from 'lucide-react'
import { open, save } from '@tauri-apps/plugin-dialog'
import { fileCommands, type FileEntryView } from '../lib/tauri'
import { staggerStyle } from '@/hooks/use-stagger'
import { useI18n } from '@/hooks/use-i18n'

const fileFolderKeys = [
  { id: 'all', labelKey: 'files.allFiles' as const, icon: HardDrive },
  { id: 'documents', labelKey: 'files.documents' as const, icon: FileText },
  { id: 'images', labelKey: 'files.images' as const, icon: Image },
  { id: 'archives', labelKey: 'files.archives' as const, icon: Archive },
  { id: 'backups', labelKey: 'files.backups' as const, icon: Database },
  { id: 'others', labelKey: 'files.others' as const, icon: Folder },
]

const fileTypeColors: Record<string, string> = {
  PDF: '#EF4444', FIG: '#F59E0B', JPG: '#8B5CF6', PNG: '#8B5CF6',
  ZIP: '#F59E0B', CSV: '#22C55E', PPTX: '#EF4444', DOC: '#2563EB',
  DOCX: '#2563EB', XLSX: '#22C55E', TXT: '#64748B', MP4: '#F59E0B',
  MP3: '#8B5CF6', JSON: '#F59E0B', SVG: '#8B5CF6',
}

function getFileType(filename: string): string {
  const ext = filename.split('.').pop()?.toUpperCase() || 'FILE'
  return ext
}

function getFileCategory(mimeType: string): string {
  if (mimeType.startsWith('image/')) return 'images'
  if (mimeType.startsWith('audio/') || mimeType.startsWith('video/')) return 'others'
  if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('7z') || mimeType.includes('tar') || mimeType.includes('gzip')) return 'archives'
  if (mimeType.includes('pdf') || mimeType.includes('document') || mimeType.includes('text') || mimeType.includes('sheet') || mimeType.includes('presentation')) return 'documents'
  return 'others'
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function timeAgo(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)
  if (diffSec < 60) return 'just now'
  if (diffMin < 60) return `${diffMin} min ago`
  if (diffHour < 24) return `${diffHour}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return date.toLocaleDateString()
}

/** Encryption animation overlay — shown while a file is being encrypted */
function EncryptionOverlay({ fileName, stage }: { fileName: string; stage: number }) {
  const stages = [
    { label: 'Reading file' },
    { label: 'Generating encryption key' },
    { label: 'Encrypting with AES-256-GCM' },
    { label: 'Verifying integrity' },
    { label: 'Saving encrypted file' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-overlay)', backdropFilter: 'blur(4px)' }}>
      <div
        className="rounded-2xl p-8 w-full max-w-sm text-center"
        style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: '0 25px 50px -12px rgb(0 0 0 / 0.25)' }}
      >
        {/* Animated lock icon */}
        <div className="relative w-20 h-20 mx-auto mb-5">
          {/* Outer pulsing ring */}
          <div
            className="absolute inset-0 rounded-full animate-ping"
            style={{ backgroundColor: 'rgba(37, 99, 235, 0.15)', animationDuration: '1.5s' }}
          />
          {/* Middle spinning ring */}
          <div
            className="absolute inset-1 rounded-full"
            style={{
              border: '3px solid transparent',
              borderTopColor: 'var(--kestrel-primary)',
              borderRightColor: 'var(--kestrel-primary-hover)',
              animation: 'spin 1.2s linear infinite',
            }}
          />
          {/* Inner circle with lock */}
          <div
            className="absolute inset-3 rounded-full flex items-center justify-center"
            style={{ backgroundColor: 'var(--kestrel-primary-subtle)' }}
          >
            <Lock size={24} style={{ color: 'var(--kestrel-primary)' }} />
          </div>
        </div>

        <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--kestrel-text)' }}>Encrypting File</h3>
        <p className="text-sm truncate mb-5" style={{ color: 'var(--kestrel-text-muted)' }}>{fileName}</p>

        {/* Stage progress */}
        <div className="space-y-2.5">
          {stages.map((s, i) => {
            const isActive = i === stage
            const isDone = i < stage
            return (
              <div key={i} className="flex items-center gap-3">
                <div
                  className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 transition-all duration-300"
                  style={{
                    backgroundColor: isDone ? 'var(--kestrel-success)' : isActive ? 'var(--kestrel-primary)' : 'var(--kestrel-border-subtle)',
                  }}
                >
                  {isDone ? (
                    <CheckCircle size={14} style={{ color: '#FFFFFF' }} />
                  ) : isActive ? (
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--kestrel-surface)', animation: 'pulse 1s ease-in-out infinite' }} />
                  ) : (
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--kestrel-text-light)' }} />
                  )}
                </div>
                <span
                  className="text-sm transition-colors duration-300"
                  style={{ color: isDone ? 'var(--kestrel-success)' : isActive ? 'var(--kestrel-primary)' : 'var(--kestrel-text-on-dark-muted)', fontWeight: isActive ? 500 : 400 }}
                >
                  {s.label}
                </span>
              </div>
            )
          })}
        </div>

        {/* Progress bar */}
        <div className="mt-5 w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-border-subtle)' }}>
          <div
            className="h-1.5 rounded-full transition-all duration-500 ease-out"
            style={{
              width: `${((stage + 1) / stages.length) * 100}%`,
              backgroundColor: 'var(--kestrel-primary)',
            }}
          />
        </div>
      </div>

      {/* Keyframes for spin animation */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}

export default function FileVault() {
  const { t } = useI18n()
  const fileFolders = fileFolderKeys.map(f => ({ ...f, label: t(f.labelKey) }))
  const [activeFolder, setActiveFolder] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null)
  const [files, setFiles] = useState<FileEntryView[]>([])
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [encryptStage, setEncryptStage] = useState(-1) // -1 = not encrypting
  const [encryptFileName, setEncryptFileName] = useState('')
  const [_error, setError] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Load files from backend
  const loadFiles = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fileCommands.list()
      setFiles(result)
    } catch (err: any) {
      setError(err.message || 'Failed to load files')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadFiles()
  }, [loadFiles])

  // Auto-dismiss status message after 3 seconds
  useEffect(() => {
    if (statusMessage) {
      const timer = setTimeout(() => setStatusMessage(null), 3000)
      return () => clearTimeout(timer)
    }
    return undefined
  }, [statusMessage])

  // Handle file upload
  const handleUpload = async () => {
    try {
      setUploading(true)
      setError(null)

      const selected = await open({
        multiple: false,
        title: 'Select a file to encrypt',
      })

      if (!selected) {
        setUploading(false)
        return
      }

      // Tauri dialog returns string | string[] | null
      const filePath = typeof selected === 'string' ? selected : (Array.isArray(selected) ? selected[0] : null)
      if (!filePath) {
        setUploading(false)
        return
      }

      // Show encryption animation with staged progress
      const fileName = filePath.split(/[\\/]/).pop() || 'file'
      setEncryptFileName(fileName)
      setEncryptStage(0) // Reading file

      // Simulate stages while actual encryption runs
      const stageTimers = [
        setTimeout(() => setEncryptStage(1), 400),  // Generating key
        setTimeout(() => setEncryptStage(2), 900),  // Encrypting
        setTimeout(() => setEncryptStage(3), 1800), // Verifying
        setTimeout(() => setEncryptStage(4), 2200), // Saving
      ]

      try {
        const result = await fileCommands.upload(filePath)
        // Clear any remaining stage timers
        stageTimers.forEach(clearTimeout)
        // Show final stage briefly
        setEncryptStage(4)
        await new Promise(r => setTimeout(r, 400))
        setEncryptStage(-1)
        setStatusMessage({ type: 'success', text: `"${result.filename}" encrypted and uploaded successfully!` })
        await loadFiles()
      } catch (err) {
        stageTimers.forEach(clearTimeout)
        setEncryptStage(-1)
        throw err
      }
    } catch (err: any) {
      setError(err.message || 'Failed to upload file')
      setStatusMessage({ type: 'error', text: err.message || 'Upload failed' })
    } finally {
      setUploading(false)
    }
  }

  // Handle file decrypt (export)
  const handleDecrypt = async (file: FileEntryView) => {
    try {
      setError(null)

      const outputPath = await save({
        defaultPath: file.filename,
        title: 'Save decrypted file',
      })

      if (!outputPath) return

      await fileCommands.decrypt(file.id, typeof outputPath === 'string' ? outputPath : outputPath as string)
      setStatusMessage({ type: 'success', text: `"${file.filename}" decrypted and saved successfully!` })
    } catch (err: any) {
      setError(err.message || 'Failed to decrypt file')
      setStatusMessage({ type: 'error', text: err.message || 'Decryption failed' })
    }
  }

  // Handle file delete
  const handleDelete = async (file: FileEntryView) => {
    if (!confirm(`Are you sure you want to delete "${file.filename}"? This action cannot be undone.`)) return

    try {
      setError(null)
      await fileCommands.delete(file.id, true)
      setStatusMessage({ type: 'success', text: `"${file.filename}" deleted successfully.` })
      if (selectedFileId === file.id) setSelectedFileId(null)
      await loadFiles()
    } catch (err: any) {
      setError(err.message || 'Failed to delete file')
      setStatusMessage({ type: 'error', text: err.message || 'Delete failed' })
    }
  }

  const filteredFiles = files.filter((file) => {
    const category = getFileCategory(file.mime_type)
    const matchesFolder = activeFolder === 'all' || category === activeFolder
    const matchesSearch = !searchQuery || file.filename.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesFolder && matchesSearch
  })

  const selectedFileData = files.find((f) => f.id === selectedFileId) ?? null

  // Compute folder counts
  const folderCounts = fileFolders.map((folder) => {
    if (folder.id === 'all') return { ...folder, count: files.length }
    const count = files.filter((f) => getFileCategory(f.mime_type) === folder.id).length
    return { ...folder, count }
  })

  const totalSize = files.reduce((acc, f) => acc + f.size_bytes, 0)

  return (
    <div className="flex h-full">
      {/* Encryption animation overlay */}
      {encryptStage >= 0 && (
        <EncryptionOverlay fileName={encryptFileName} stage={encryptStage} />
      )}

      {/* Status message toast */}
      {statusMessage && (
        <div
          className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg"
          style={{
            backgroundColor: statusMessage.type === 'success' ? 'var(--kestrel-badge-success-bg)' : 'var(--kestrel-danger-subtle)',
            border: `1px solid ${statusMessage.type === 'success' ? 'var(--kestrel-success)' : 'var(--kestrel-danger)'}`,
            color: statusMessage.type === 'success' ? 'var(--kestrel-badge-success-text)' : 'var(--kestrel-danger)',
          }}
        >
          {statusMessage.type === 'success' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
          <span className="text-sm font-medium">{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="ml-2 opacity-60 hover:opacity-100">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Folder sidebar */}
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '220px', borderRight: '1px solid var(--kestrel-border)', backgroundColor: 'var(--kestrel-surface)' }}
      >
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('files.title')}</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }} />
            <input
              type="text"
              placeholder={t('files.searchFiles')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--kestrel-bg)', paddingLeft: '32px', paddingRight: '10px', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
            />
          </div>
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{
              backgroundColor: uploading ? 'var(--kestrel-primary-subtle)' : 'var(--kestrel-primary)',
              color: uploading ? 'var(--kestrel-primary)' : '#FFFFFF',
              cursor: uploading ? 'not-allowed' : 'pointer',
            }}
          >
            <Plus size={16} /> {uploading ? t('files.encrypting') : t('files.uploadFile')}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-2">
          {folderCounts.map((folder) => {
            const isActive = activeFolder === folder.id
            const Icon = folder.icon
            return (
              <button
                key={folder.id}
                onClick={() => setActiveFolder(folder.id)}
                className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-all duration-150 mb-0.5"
                style={{
                  backgroundColor: isActive ? 'var(--kestrel-selected-bg)' : 'transparent',
                  borderLeft: isActive ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
                  color: isActive ? 'var(--kestrel-primary)' : 'var(--kestrel-text-muted)',
                }}
              >
                <Icon size={16} />
                <span className="text-sm flex-1">{folder.label}</span>
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{folder.count}</span>
              </button>
            )
          })}
        </div>

        <div className="p-4" style={{ borderTop: '1px solid var(--kestrel-border)' }}>
          <p className="text-xs mb-2" style={{ color: 'var(--kestrel-text-muted)' }}>{files.length} {t('vault.entries')}</p>
          <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-border-subtle)' }}>
            <div
              className="h-1.5 rounded-full"
              style={{ width: `${Math.min((totalSize / (10 * 1024 * 1024 * 1024)) * 100, 100)}%`, backgroundColor: 'var(--kestrel-primary)' }}
            />
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{formatFileSize(totalSize)} / 10 GB</p>
        </div>
      </div>

      {/* File list */}
      <div
        className="flex flex-col h-full flex-1"
        style={{ borderRight: '1px solid var(--kestrel-border)', minWidth: '320px', backgroundColor: 'var(--kestrel-surface)' }}
      >
        <div
          className="flex items-center justify-between px-4 py-3"
          style={{ borderBottom: '1px solid var(--kestrel-border)' }}
        >
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--kestrel-text)' }}>
              {fileFolders.find((f) => f.id === activeFolder)?.label || t('files.allFiles')}
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--kestrel-border-subtle)', color: 'var(--kestrel-text-muted)' }}>
              {filteredFiles.length}
            </span>
          </div>
          <button
            onClick={loadFiles}
            className="text-xs px-2 py-1 rounded"
            style={{ color: 'var(--kestrel-text-muted)', backgroundColor: 'var(--kestrel-bg)' }}
          >
            Refresh
          </button>
        </div>

        <div
          className="grid items-center px-4 py-2 text-xs font-medium"
          style={{ gridTemplateColumns: '1fr 80px 100px 80px', color: 'var(--kestrel-text-muted)', borderBottom: '1px solid var(--kestrel-border-subtle)' }}
        >
          <span>Name</span>
          <span>Size</span>
          <span>Modified</span>
          <span>Status</span>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading && files.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3" />
              <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('common.loading')}</p>
            </div>
          ) : filteredFiles.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center px-6">
              <HardDrive size={40} style={{ color: 'var(--kestrel-text-light)' }} className="mb-3" />
              <p className="text-sm font-medium" style={{ color: 'var(--kestrel-text-muted)' }}>{t('files.noFiles')}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('files.uploadFirst')}</p>
            </div>
          ) : (
            filteredFiles.map((file, index) => {
              const isSelected = selectedFileId === file.id
              const fileType = getFileType(file.filename)
              const color = fileTypeColors[fileType] || '#64748B'
              return (
                <button
                  key={file.id}
                  onClick={() => setSelectedFileId(file.id)}
                  className="w-full grid items-center px-4 py-3 text-left transition-all duration-200 animate-stagger-in"
                  style={{
                    gridTemplateColumns: '1fr 80px 100px 80px',
                    backgroundColor: isSelected ? 'var(--kestrel-selected-bg)' : 'transparent',
                    borderLeft: isSelected ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
                    borderBottom: '1px solid var(--kestrel-border-subtle)',
                    ...staggerStyle(index),
                  }}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className="w-7 h-7 rounded flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${color}15` }}
                    >
                      <span className="text-xs font-semibold" style={{ color }}>{fileType}</span>
                    </div>
                    <span className="text-sm truncate" style={{ color: 'var(--kestrel-text)' }}>{file.filename}</span>
                  </div>
                  <span className="text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>{formatFileSize(file.size_bytes)}</span>
                  <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{timeAgo(file.updated_at)}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--kestrel-primary)' }} />
                    <span className="text-xs" style={{ color: 'var(--kestrel-primary)' }}>Encrypted</span>
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* Detail panel */}
      <div className="flex flex-col h-full" style={{ width: '380px', backgroundColor: 'var(--kestrel-surface)' }}>
        {!selectedFileData ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <img src="/kestrel-logo.png" alt="" className="w-12 h-12 object-contain mb-3 opacity-30" />
            <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{t('files.selectFile')}</p>
          </div>
        ) : (
          <div className="flex flex-col h-full overflow-y-auto">
            <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--kestrel-border)' }}>
              <button
                onClick={() => setSelectedFileId(null)}
                className="flex items-center gap-1 text-sm"
                style={{ color: 'var(--kestrel-text-muted)' }}
              >
                <ChevronLeft size={16} /> {t('files.title')}
              </button>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDecrypt(selectedFileData)}
                  className="h-8 px-3 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5"
                  style={{ backgroundColor: 'var(--kestrel-primary)', color: '#FFFFFF', cursor: 'pointer' }}
                >
                  <Unlock size={14} /> {t('files.decrypt')}
                </button>
                <button
                  onClick={() => handleDelete(selectedFileData)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors"
                  style={{ color: 'var(--kestrel-danger)' }}
                  title="Delete file"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>

            <div className="p-5">
              <div className="flex flex-col items-center mb-5">
                <div
                  className="w-16 h-16 rounded-xl flex items-center justify-center mb-3"
                  style={{ backgroundColor: `${fileTypeColors[getFileType(selectedFileData.filename)] || '#64748B'}15` }}
                >
                  <span className="text-lg font-bold" style={{ color: fileTypeColors[getFileType(selectedFileData.filename)] || '#64748B' }}>
                    {getFileType(selectedFileData.filename)}
                  </span>
                </div>
                <h3 className="text-base font-semibold text-center" style={{ color: 'var(--kestrel-text)' }}>{selectedFileData.filename}</h3>
                <span
                  className="text-xs px-2.5 py-0.5 rounded-full mt-2 flex items-center gap-1"
                  style={{ backgroundColor: 'var(--kestrel-primary-subtle)', color: 'var(--kestrel-primary)' }}
                >
                  <Lock size={10} /> AES-256-GCM Encrypted
                </span>
              </div>

              <div className="space-y-3">
                {[
                  { label: 'Status', value: 'Encrypted', dotColor: 'var(--kestrel-primary)' },
                  { label: 'Algorithm', value: 'AES-256-GCM', dotColor: 'var(--kestrel-success)' },
                  { label: 'Size', value: formatFileSize(selectedFileData.size_bytes) },
                  { label: 'Type', value: selectedFileData.mime_type },
                  { label: 'Original Size', value: `${selectedFileData.size_bytes.toLocaleString()} bytes` },
                  { label: 'Created', value: new Date(selectedFileData.created_at).toLocaleString() },
                  { label: 'Modified', value: new Date(selectedFileData.updated_at).toLocaleString() },
                ].map((field) => (
                  <div key={field.label} className="flex items-start gap-3">
                    <span className="text-xs font-medium w-24 flex-shrink-0" style={{ color: 'var(--kestrel-text-muted)' }}>
                      {field.label}
                    </span>
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      {field.dotColor && (
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: field.dotColor }} />
                      )}
                      <span className="text-sm truncate" style={{ color: 'var(--kestrel-text)' }}>
                        {field.value}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              <div
                className="mt-5 rounded-xl p-6 text-center"
                style={{ backgroundColor: 'var(--kestrel-bg)', border: '1px solid var(--kestrel-border)' }}
              >
                <Lock size={32} style={{ color: 'var(--kestrel-primary)' }} className="mx-auto mb-2" />
                <p className="text-sm font-medium" style={{ color: 'var(--kestrel-text)' }}>{t('files.noFiles')}</p>
                <p className="text-xs mt-2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                  {t('files.decrypt')}
                </p>
                <p className="text-xs mt-1" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                  Content is protected with AES-256-GCM
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
