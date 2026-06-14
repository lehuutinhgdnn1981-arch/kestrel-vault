import { useState, useEffect } from 'react'
import {
  Search,
  Plus,
  Trash2,
  FileText,
  X,
  Save,
  CheckCircle,
} from 'lucide-react'
import { useNoteStore } from '@/stores/note-store'
import { useAuthStore } from '@/stores/auth-store'
import { noteCommands } from '@/lib/tauri'
import { staggerStyle } from '@/hooks/use-stagger'
import { useI18n } from '@/hooks/use-i18n'

function renderMarkdown(content: string): string {
  return content
    .replace(/^# (.*$)/gm, '<h1 class="text-xl font-semibold mb-3" style="color:var(--kestrel-text)">$1</h1>')
    .replace(/^## (.*$)/gm, '<h2 class="text-base font-semibold mb-2 mt-4" style="color:var(--kestrel-text)">$1</h2>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/^\* (.*$)/gm, '<li class="ml-4 mb-1">$1</li>')
    .replace(/^- (.*$)/gm, '<li class="ml-4 mb-1">$1</li>')
    .replace(/\[REDACTED\]/g, '<span class="px-1.5 py-0.5 rounded text-xs font-mono-geist" style="background-color:var(--kestrel-border-subtle);color:var(--kestrel-text-muted)">••••••••</span>')
    .replace(/^(?!<[hl]|<li)(.*$)/gm, '<p class="mb-2 text-sm" style="color:var(--kestrel-text-secondary)">$1</p>')
    .replace(/<\/p>\n<p/g, '</p><p')
    .replace(/<li class="ml-4 mb-1">(.*?)<\/li>/g, '<li class="ml-4 mb-1 flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full flex-shrink-0" style="background-color:var(--kestrel-primary)"></span>$1</li>')
}

export default function SecureNotes() {
  const notes = useNoteStore((s) => s.notes)
  const fetchNotes = useNoteStore((s) => s.fetchNotes)
  const selectedNoteId = useNoteStore((s) => s.selectedNoteId)
  const selectNote = useNoteStore((s) => s.selectNote)
  const revealNote = useNoteStore((s) => s.revealNote)
  const revealedContent = useNoteStore((s) => s.revealedContent)
  const createNote = useNoteStore((s) => s.createNote)
  const deleteNote = useNoteStore((s) => s.deleteNote)
  const appState = useAuthStore((s) => s.appState)

  const [searchQuery, setSearchQuery] = useState('')
  const [editingContent, setEditingContent] = useState('')
  const [editingTitle, setEditingTitle] = useState('')
  const [isDirty, setIsDirty] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [saveMessage, setSaveMessage] = useState<string | null>(null)

  // New Note dialog state
  const [showNewDialog, setShowNewDialog] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newContent, setNewContent] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  const { t } = useI18n()

  useEffect(() => {
    if (appState === 'unlocked') fetchNotes()
  }, [appState, fetchNotes])

  const filteredNotes = notes.filter((note) =>
    !searchQuery || note.title.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const selectedNoteData = notes.find((n) => n.id === selectedNoteId) ?? null

  const handleSelectNote = async (id: string) => {
    if (isDirty && selectedNoteId) {
      const proceed = window.confirm(t('notes.unsavedChanges'))
      if (!proceed) return
    }
    selectNote(id)
    setIsDirty(false)
    setSaveMessage(null)
    const result = await revealNote(id)
    if (result) {
      setEditingContent(result.content)
      const note = notes.find((n) => n.id === id)
      setEditingTitle(note?.title || '')
    }
  }

  const handleSaveNote = async () => {
    if (!selectedNoteId || !isDirty) return
    setIsSaving(true)
    try {
      await noteCommands.updateNote(selectedNoteId, {
        title: editingTitle || undefined,
        content: editingContent,
      })
      setIsDirty(false)
      setSaveMessage(t('notes.saved'))
      setTimeout(() => setSaveMessage(null), 2000)
      await fetchNotes()
    } catch {
      setSaveMessage(t('notes.saveFailed'))
      setTimeout(() => setSaveMessage(null), 3000)
    } finally {
      setIsSaving(false)
    }
  }

  // Ctrl+S / Cmd+S to save
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault()
        if (isDirty && selectedNoteId) handleSaveNote()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isDirty, selectedNoteId, editingContent, editingTitle])

  const handleCreateNote = async () => {
    if (!newTitle.trim() || !newContent.trim()) return
    setIsCreating(true)
    try {
      await createNote(newTitle, newContent)
      setShowNewDialog(false)
      setNewTitle('')
      setNewContent('')
    } catch {
      // Error handled gracefully
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeleteNote = async (id: string) => {
    try {
      await deleteNote(id)
    } catch {
      // Error handled gracefully
    }
  }

  return (
    <div className="flex h-full">
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '320px', borderRight: '1px solid var(--kestrel-border)', backgroundColor: 'var(--kestrel-surface)' }}
      >
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('notes.title')}</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--kestrel-text-on-dark-muted)' }} />
            <input
              type="text"
              placeholder={t('notes.searchNotes')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--kestrel-hover-bg)', paddingLeft: '32px', paddingRight: '10px', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }}
            />
          </div>
          <button
            onClick={() => setShowNewDialog(true)}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: 'var(--kestrel-primary)', color: '#FFFFFF' }}
          >
            <Plus size={16} /> {t('notes.newNote')}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredNotes.map((note, index) => {
            const isSelected = selectedNoteId === note.id
            const preview = note.has_content ? t('notes.contentAvailable') : t('notes.emptyNote')
            return (
              <button
                key={note.id}
                onClick={() => handleSelectNote(note.id)}
                className="w-full text-left px-4 py-3 transition-all duration-200 animate-stagger-in"
                style={{
                  backgroundColor: isSelected ? 'var(--kestrel-selected-bg)' : 'transparent',
                  borderLeft: isSelected ? '3px solid var(--kestrel-primary)' : '3px solid transparent',
                  borderBottom: '1px solid var(--kestrel-border-subtle)',
                  ...staggerStyle(index),
                }}
              >
                <h4 className="text-sm font-medium mb-1" style={{ color: 'var(--kestrel-text)' }}>{note.title}</h4>
                <p className="text-xs truncate mb-1.5" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>{preview}</p>
                <span className="text-xs" style={{ color: 'var(--kestrel-text-on-dark-muted)' }}>
                  {new Date(note.updated_at).toLocaleDateString()}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex flex-col h-full flex-1" style={{ backgroundColor: 'var(--kestrel-surface)' }}>
        {!selectedNoteData ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <FileText size={32} style={{ color: 'var(--kestrel-text-light)' }} className="mb-3" />
            <p className="text-sm font-medium" style={{ color: 'var(--kestrel-text-muted)' }}>{t('notes.selectNote')}</p>
          </div>
        ) : (
          <div className="flex flex-col h-full">
            <div
              className="flex items-center justify-between px-6 py-3"
              style={{ borderBottom: '1px solid var(--kestrel-border)' }}
            >
              <input
                type="text"
                value={editingTitle || selectedNoteData.title}
                onChange={(e) => { setEditingTitle(e.target.value); setIsDirty(true) }}
                className="text-lg font-semibold bg-transparent outline-none flex-1"
                style={{ color: 'var(--kestrel-text)' }}
              />
              <div className="flex items-center gap-1">
                {isDirty && (
                  <button
                    onClick={handleSaveNote}
                    disabled={isSaving}
                    className="h-7 px-3 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                    style={{ backgroundColor: isSaving ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)', color: isSaving ? 'var(--kestrel-disabled-text)' : '#FFFFFF' }}
                  >
                    {isSaving ? <div className="w-3 h-3 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--kestrel-disabled-text)', borderTopColor: 'transparent' }} /> : <Save size={12} />}
                    {isSaving ? t('notes.saving') : t('notes.save')}
                  </button>
                )}
                {saveMessage && (
                  <span className="text-xs flex items-center gap-1" style={{ color: saveMessage === t('notes.saved') ? 'var(--kestrel-success)' : 'var(--kestrel-danger)' }}>
                    <CheckCircle size={12} /> {saveMessage}
                  </span>
                )}
                <button
                  onClick={() => handleDeleteNote(selectedNoteData.id)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors"
                  style={{ color: 'var(--kestrel-text-muted)' }}
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>

            <div className="flex flex-1 overflow-hidden">
              {/* Editor pane */}
              <div className="flex-1 flex flex-col" style={{ borderRight: '1px solid var(--kestrel-border)' }}>
                <div className="px-3 py-1.5 text-xs font-medium" style={{ backgroundColor: 'var(--kestrel-hover-bg)', color: 'var(--kestrel-text-muted)', borderBottom: '1px solid var(--kestrel-border)' }}>
                  {t('notes.editor')}
                </div>
                {revealedContent ? (
                  <textarea
                    value={editingContent || revealedContent.content}
                    onChange={(e) => { setEditingContent(e.target.value); setIsDirty(true) }}
                    className="flex-1 w-full p-5 text-sm resize-none outline-none font-mono-geist"
                    style={{ backgroundColor: 'var(--kestrel-surface)', color: 'var(--kestrel-text)', lineHeight: 1.7, border: 'none' }}
                    spellCheck={false}
                  />
                ) : (
                  <div className="flex items-center justify-center h-32">
                    <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
                      style={{ borderColor: 'var(--kestrel-primary)', borderTopColor: 'transparent' }} />
                  </div>
                )}
              </div>

              {/* Preview pane */}
              <div className="flex-1 flex flex-col">
                <div className="px-3 py-1.5 text-xs font-medium" style={{ backgroundColor: 'var(--kestrel-hover-bg)', color: 'var(--kestrel-text-muted)', borderBottom: '1px solid var(--kestrel-border)' }}>
                  {t('notes.preview')}
                </div>
                <div
                  className="flex-1 p-5 overflow-y-auto prose-sm max-w-none"
                  style={{ color: 'var(--kestrel-text)' }}
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(editingContent || (revealedContent?.content ?? '')) }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* New Note Dialog */}
      {showNewDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--kestrel-overlay)' }}>
          <div className="rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: 'var(--kestrel-surface)', border: '1px solid var(--kestrel-border)', boxShadow: 'var(--kestrel-shadow-dropdown)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--kestrel-text)' }}>{t('notes.newNote')}</h3>
              <button onClick={() => setShowNewDialog(false)} className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: 'var(--kestrel-text-muted)' }}>
                <X size={16} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('notes.title_field')}</label>
                <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)}
                  placeholder={t('notes.exampleTitle')}
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--kestrel-text-muted)' }}>{t('notes.contentRequired')}</label>
                <textarea value={newContent} onChange={(e) => setNewContent(e.target.value)}
                  placeholder={t('notes.contentPlaceholder')}
                  className="w-full h-40 rounded-lg text-sm outline-none p-3 resize-none font-mono-geist"
                  style={{ backgroundColor: 'var(--kestrel-hover-bg)', border: '1px solid var(--kestrel-border)', color: 'var(--kestrel-text)', lineHeight: 1.7 }} />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 mt-6">
              <button onClick={() => setShowNewDialog(false)}
                className="px-4 h-9 rounded-lg text-sm font-medium"
                style={{ backgroundColor: 'var(--kestrel-hover-bg)', color: 'var(--kestrel-text)', border: '1px solid var(--kestrel-border)' }}>
                {t('notes.cancel')}
              </button>
              <button onClick={handleCreateNote} disabled={isCreating || !newTitle.trim() || !newContent.trim()}
                className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                style={{
                  backgroundColor: isCreating || !newTitle.trim() || !newContent.trim() ? 'var(--kestrel-disabled-bg)' : 'var(--kestrel-primary)',
                  color: isCreating || !newTitle.trim() || !newContent.trim() ? 'var(--kestrel-disabled-text)' : '#FFFFFF',
                }}>
                {isCreating ? t('notes.creating') : t('notes.createNote')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
