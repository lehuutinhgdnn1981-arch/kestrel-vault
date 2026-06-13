import { useState, useEffect } from 'react'
import {
  Search,
  Plus,
  Pencil,
  Trash2,
  FileText,
  X,
} from 'lucide-react'
import { useNoteStore } from '@/stores/note-store'
import { useAuthStore } from '@/stores/auth-store'

function renderMarkdown(content: string): string {
  return content
    .replace(/^# (.*$)/gm, '<h1 class="text-xl font-semibold mb-3" style="color:#0F172A">$1</h1>')
    .replace(/^## (.*$)/gm, '<h2 class="text-base font-semibold mb-2 mt-4" style="color:#0F172A">$1</h2>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/^\* (.*$)/gm, '<li class="ml-4 mb-1">$1</li>')
    .replace(/^- (.*$)/gm, '<li class="ml-4 mb-1">$1</li>')
    .replace(/\[REDACTED\]/g, '<span class="px-1.5 py-0.5 rounded text-xs font-mono-geist" style="background-color:#F1F5F9;color:#64748B">••••••••</span>')
    .replace(/^(?!<[hl]|<li)(.*$)/gm, '<p class="mb-2 text-sm" style="color:#475569">$1</p>')
    .replace(/<\/p>\n<p/g, '</p><p')
    .replace(/<li class="ml-4 mb-1">(.*?)<\/li>/g, '<li class="ml-4 mb-1 flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full flex-shrink-0" style="background-color:#2563EB"></span>$1</li>')
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

  // New Note dialog state
  const [showNewDialog, setShowNewDialog] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newContent, setNewContent] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  useEffect(() => {
    if (appState === 'unlocked') fetchNotes()
  }, [appState, fetchNotes])

  const filteredNotes = notes.filter((note) =>
    !searchQuery || note.title.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const selectedNoteData = notes.find((n) => n.id === selectedNoteId) ?? null

  const handleSelectNote = async (id: string) => {
    selectNote(id)
    const result = await revealNote(id)
    if (result) setEditingContent(result.content)
  }

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
    <div className="flex h-full animate-fade-in">
      <div
        className="flex flex-col h-full flex-shrink-0"
        style={{ width: '320px', borderRight: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}
      >
        <div className="p-4 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color: '#0F172A' }}>Notes</h2>
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
            <input
              type="text"
              placeholder="Search notes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 rounded-lg text-sm outline-none"
              style={{ backgroundColor: '#F8FAFC', paddingLeft: '32px', paddingRight: '10px', border: '1px solid #E2E8F0', color: '#0F172A' }}
            />
          </div>
          <button
            onClick={() => setShowNewDialog(true)}
            className="w-full h-9 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors duration-150"
            style={{ backgroundColor: '#2563EB', color: '#FFFFFF' }}
          >
            <Plus size={16} /> New Note
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredNotes.map((note) => {
            const isSelected = selectedNoteId === note.id
            const preview = note.has_content ? 'Content available' : 'Empty note'
            return (
              <button
                key={note.id}
                onClick={() => handleSelectNote(note.id)}
                className="w-full text-left px-4 py-3 transition-colors duration-150"
                style={{
                  backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.05)' : 'transparent',
                  borderLeft: isSelected ? '3px solid #2563EB' : '3px solid transparent',
                  borderBottom: '1px solid #F1F5F9',
                }}
              >
                <h4 className="text-sm font-medium mb-1" style={{ color: '#0F172A' }}>{note.title}</h4>
                <p className="text-xs truncate mb-1.5" style={{ color: '#94A3B8' }}>{preview}</p>
                <span className="text-xs" style={{ color: '#94A3B8' }}>
                  {new Date(note.updated_at).toLocaleDateString()}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex flex-col h-full flex-1" style={{ backgroundColor: '#FFFFFF' }}>
        {!selectedNoteData ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <FileText size={32} style={{ color: '#CBD5E1' }} className="mb-3" />
            <p className="text-sm font-medium" style={{ color: '#64748B' }}>Select a note to view or edit</p>
          </div>
        ) : (
          <div className="flex flex-col h-full">
            <div
              className="flex items-center justify-between px-6 py-3"
              style={{ borderBottom: '1px solid #E2E8F0' }}
            >
              <input
                type="text"
                defaultValue={selectedNoteData.title}
                className="text-lg font-semibold bg-transparent outline-none flex-1"
                style={{ color: '#0F172A' }}
              />
              <div className="flex items-center gap-1">
                <button className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
                  <Pencil size={15} />
                </button>
                <button
                  onClick={() => handleDeleteNote(selectedNoteData.id)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors"
                  style={{ color: '#64748B' }}
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>

            <div className="flex flex-1 overflow-hidden">
              {/* Editor pane */}
              <div className="flex-1 flex flex-col" style={{ borderRight: '1px solid #E2E8F0' }}>
                <div className="px-3 py-1.5 text-xs font-medium" style={{ backgroundColor: '#F8FAFC', color: '#64748B', borderBottom: '1px solid #E2E8F0' }}>
                  Editor
                </div>
                {revealedContent ? (
                  <textarea
                    value={editingContent || revealedContent.content}
                    onChange={(e) => setEditingContent(e.target.value)}
                    className="flex-1 w-full p-5 text-sm resize-none outline-none font-mono-geist"
                    style={{ backgroundColor: '#FFFFFF', color: '#0F172A', lineHeight: 1.7, border: 'none' }}
                    spellCheck={false}
                  />
                ) : (
                  <div className="flex items-center justify-center h-32">
                    <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin"
                      style={{ borderColor: '#2563EB', borderTopColor: 'transparent' }} />
                  </div>
                )}
              </div>

              {/* Preview pane */}
              <div className="flex-1 flex flex-col">
                <div className="px-3 py-1.5 text-xs font-medium" style={{ backgroundColor: '#F8FAFC', color: '#64748B', borderBottom: '1px solid #E2E8F0' }}>
                  Preview
                </div>
                <div
                  className="flex-1 p-5 overflow-y-auto prose-sm max-w-none"
                  style={{ color: '#0F172A' }}
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(editingContent || (revealedContent?.content ?? '')) }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* New Note Dialog */}
      {showNewDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.4)' }}>
          <div className="rounded-xl p-6 w-full max-w-md" style={{ backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 8px 30px rgb(0 0 0 / 0.12)' }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold" style={{ color: '#0F172A' }}>New Note</h3>
              <button onClick={() => setShowNewDialog(false)} className="w-8 h-8 flex items-center justify-center rounded-lg" style={{ color: '#64748B' }}>
                <X size={16} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Title *</label>
                <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Server Credentials"
                  className="w-full h-9 rounded-lg text-sm outline-none px-3"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A' }} />
              </div>
              <div>
                <label className="text-xs font-medium mb-1 block" style={{ color: '#64748B' }}>Content *</label>
                <textarea value={newContent} onChange={(e) => setNewContent(e.target.value)}
                  placeholder="Write your note content here..."
                  className="w-full h-40 rounded-lg text-sm outline-none p-3 resize-none font-mono-geist"
                  style={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#0F172A', lineHeight: 1.7 }} />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 mt-6">
              <button onClick={() => setShowNewDialog(false)}
                className="px-4 h-9 rounded-lg text-sm font-medium"
                style={{ backgroundColor: '#F8FAFC', color: '#0F172A', border: '1px solid #E2E8F0' }}>
                Cancel
              </button>
              <button onClick={handleCreateNote} disabled={isCreating || !newTitle.trim() || !newContent.trim()}
                className="px-4 h-9 rounded-lg text-sm font-medium transition-colors"
                style={{
                  backgroundColor: isCreating || !newTitle.trim() || !newContent.trim() ? '#E2E8F0' : '#2563EB',
                  color: isCreating || !newTitle.trim() || !newContent.trim() ? '#94A3B8' : '#FFFFFF',
                }}>
                {isCreating ? 'Creating...' : 'Create Note'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
