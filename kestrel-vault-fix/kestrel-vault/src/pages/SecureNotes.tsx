import { useState, useEffect } from 'react'
import {
  Search,
  Plus,
  Pencil,
  Trash2,
  FileText,
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
  const appState = useAuthStore((s) => s.appState)

  const [searchQuery, setSearchQuery] = useState('')
  const [editingContent, setEditingContent] = useState('')

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
                <button className="w-8 h-8 flex items-center justify-center rounded-lg transition-colors" style={{ color: '#64748B' }}>
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
    </div>
  )
}
