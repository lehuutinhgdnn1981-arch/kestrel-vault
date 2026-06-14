import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Shield, FileText, StickyNote, X, ArrowRight } from 'lucide-react'
import { vaultCommands, fileCommands, type VaultEntryView } from '@/lib/tauri'
import { useNoteStore } from '@/stores/note-store'
import { TIMEOUTS } from '@/lib/constants'
import { useI18n } from '@/hooks/use-i18n'

interface SearchResult {
  id: string
  type: 'password' | 'file' | 'note'
  title: string
  subtitle: string
  path: string
}

interface SearchDialogProps {
  isOpen: boolean
  onClose: () => void
}

export default function SearchDialog({ isOpen, onClose }: SearchDialogProps) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const { t } = useI18n()
  const notes = useNoteStore((s) => s.notes)
  const debounceRef = useRef<ReturnType<typeof setTimeout>>()

  // Focus input when dialog opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50)
      setQuery('')
      setResults([])
      setSelectedIndex(0)
    }
  }, [isOpen])

  // Debounced search
  const performSearch = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      setResults([])
      setIsSearching(false)
      return
    }

    setIsSearching(true)
    const searchResults: SearchResult[] = []

    try {
      // Search vault entries via backend
      const vaultEntries: VaultEntryView[] = await vaultCommands.searchEntries(searchQuery, 10)
      for (const entry of vaultEntries) {
        searchResults.push({
          id: entry.id,
          type: 'password',
          title: entry.title || 'Untitled',
          subtitle: entry.username || entry.url || 'No username',
          path: '/vault',
        })
      }
    } catch {
      // Silently fail
    }

    // Search files client-side
    try {
      const files = await fileCommands.list()
      const fileResults = files.filter(
        (f) =>
          f.filename?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          f.mime_type?.toLowerCase().includes(searchQuery.toLowerCase()),
      )
      for (const file of fileResults.slice(0, 5)) {
        searchResults.push({
          id: file.id,
          type: 'file',
          title: file.filename || 'Unknown file',
          subtitle: `${(file.size_bytes / 1024).toFixed(1)} KB`,
          path: '/files',
        })
      }
    } catch {
      // Silently fail
    }

    // Search notes client-side
    const noteResults = notes.filter(
      (n) =>
        n.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.content?.toLowerCase().includes(searchQuery.toLowerCase()),
    )
    for (const note of noteResults.slice(0, 5)) {
      searchResults.push({
        id: note.id,
        type: 'note',
        title: note.title || 'Untitled Note',
        subtitle: note.content?.substring(0, 60) || 'Empty note',
        path: '/notes',
      })
    }

    setResults(searchResults)
    setIsSearching(false)
    setSelectedIndex(0)
  }, [notes])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => performSearch(query), TIMEOUTS.searchDebounce)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query, performSearch])

  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex((prev) => Math.min(prev + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex((prev) => Math.max(prev - 1, 0))
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      e.preventDefault()
      handleSelectResult(results[selectedIndex])
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  const handleSelectResult = (result: SearchResult) => {
    navigate(result.path)
    onClose()
  }

  const getTypeIcon = (type: SearchResult['type']) => {
    switch (type) {
      case 'password':
        return <Shield size={16} style={{ color: 'var(--kestrel-primary)' }} />
      case 'file':
        return <FileText size={16} style={{ color: 'var(--kestrel-warning)' }} />
      case 'note':
        return <StickyNote size={16} style={{ color: 'var(--kestrel-accent-purple)' }} />
    }
  }

  const getTypeBadge = (type: SearchResult['type']) => {
    const colors: Record<SearchResult['type'], { bg: string; text: string; label: string }> = {
      password: { bg: 'var(--kestrel-primary-subtle)', text: 'var(--kestrel-primary)', label: t('search.password') },
      file: { bg: 'var(--kestrel-warning-subtle)', text: 'var(--kestrel-warning)', label: t('search.file') },
      note: { bg: 'var(--kestrel-purple-subtle)', text: 'var(--kestrel-accent-purple)', label: t('search.note') },
    }
    const c = colors[type]
    return (
      <span
        className="text-xs font-medium px-2 py-0.5 rounded-full"
        style={{ backgroundColor: c.bg, color: c.text }}
      >
        {c.label}
      </span>
    )
  }

  if (!isOpen) return null

  return (
    <div
      className="fixed inset-0 flex items-start justify-center pt-[15vh]"
      style={{ backgroundColor: 'var(--kestrel-overlay)', zIndex: 9999 }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl shadow-2xl overflow-hidden"
        style={{ animation: 'fadeIn 150ms ease-out', backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input */}
        <div
          className="flex items-center gap-3 px-4"
          style={{ height: '52px', borderBottom: '1px solid var(--kestrel-border)' }}
        >
          <Search size={18} style={{ color: 'var(--kestrel-text-muted)' }} />
          <input
            ref={inputRef}
            type="text"
            placeholder={t('search.placeholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent outline-none text-sm"
            style={{ color: 'var(--kestrel-text)' }}
          />
          {query && (
            <button onClick={() => setQuery('')} className="p-1 rounded" style={{ color: 'var(--kestrel-text-muted)' }}>
              <X size={14} />
            </button>
          )}
          <kbd
            className="text-xs px-1.5 py-0.5 rounded"
            style={{ backgroundColor: 'var(--kestrel-hover-bg)', color: 'var(--kestrel-text-muted)', border: '1px solid var(--kestrel-border)' }}
          >
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-[360px] overflow-y-auto">
          {isSearching && (
            <div className="flex items-center justify-center py-8">
              <div className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
              <span className="ml-2 text-sm" style={{ color: 'var(--kestrel-text-muted)' }}>{t('search.searching')}</span>
            </div>
          )}

          {!isSearching && query && results.length === 0 && (
            <div className="text-center py-8">
              <Search size={24} style={{ color: 'var(--kestrel-text-light)', margin: '0 auto 8px' }} />
              <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                {t('search.noResults')} "{query}"
              </p>
            </div>
          )}

          {!isSearching && !query && (
            <div className="text-center py-8">
              <p className="text-sm" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                {t('search.typeToSearch')}
              </p>
              <div className="flex items-center justify-center gap-4 mt-3">
                <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
                  <Shield size={12} /> {t('search.passwords')}
                </span>
                <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
                  <FileText size={12} /> {t('search.files')}
                </span>
                <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--kestrel-text-muted)' }}>
                  <StickyNote size={12} /> {t('search.notesLabel')}
                </span>
              </div>
            </div>
          )}

          {!isSearching && results.length > 0 && (
            <div>
              {results.map((result, index) => (
                <button
                  key={`${result.type}-${result.id}`}
                  onClick={() => handleSelectResult(result)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors duration-100"
                  style={{
                    backgroundColor: index === selectedIndex ? 'var(--kestrel-selected-bg)' : 'transparent',
                  }}
                  onMouseEnter={() => setSelectedIndex(index)}
                >
                  <div
                    className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: 'var(--kestrel-hover-bg)' }}
                  >
                    {getTypeIcon(result.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: 'var(--kestrel-text)' }}>
                      {result.title}
                    </p>
                    <p className="text-xs truncate" style={{ color: 'var(--kestrel-text-muted)' }}>
                      {result.subtitle}
                    </p>
                  </div>
                  {getTypeBadge(result.type)}
                  <ArrowRight size={14} style={{ color: 'var(--kestrel-text-light)' }} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        {results.length > 0 && (
          <div
            className="flex items-center gap-4 px-4 py-2 text-xs"
            style={{ color: 'var(--kestrel-text-on-dark-muted)', borderTop: '1px solid var(--kestrel-border-subtle)', backgroundColor: 'var(--kestrel-footer-bg)' }}
          >
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)' }}>↑↓</kbd>
              {t('search.navigate')}
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)' }}>↵</kbd>
              {t('search.open')}
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)' }}>esc</kbd>
              {t('search.close')}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
