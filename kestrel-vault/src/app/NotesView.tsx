/**
 * Secure Notes view.
 *
 * Full UI for creating, editing, deleting, and viewing encrypted notes.
 * Content is only revealed on explicit user action and auto-cleared
 * after a timeout. All encryption/decryption happens in the Rust backend.
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  Plus,
  Search,
  FileText,
  ChevronRight,
  Trash2,
  Eye,
  EyeOff,
  Clock,
  Edit3,
  X,
} from "lucide-react";
import { useNoteStore } from "@/stores/note-store";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogContent,
  DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { formatRelativeTime, truncate } from "@/lib/utils";

// ─── Create / Edit Note Dialog ────────────────────────────────────

interface NoteFormDialogProps {
  open: boolean;
  onClose: () => void;
  mode: "create" | "edit";
  noteId?: string;
  initialTitle?: string;
  initialContent?: string;
}

const NoteFormDialog: React.FC<NoteFormDialogProps> = ({
  open,
  onClose,
  mode,
  noteId,
  initialTitle = "",
  initialContent = "",
}) => {
  const [title, setTitle] = useState(initialTitle);
  const [content, setContent] = useState(initialContent);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const createNote = useNoteStore((s) => s.createNote);
  const updateNote = useNoteStore((s) => s.updateNote);

  // Reset form when dialog opens
  useEffect(() => {
    if (open) {
      setTitle(initialTitle);
      setContent(initialContent);
      setError(null);
    }
  }, [open, initialTitle, initialContent]);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);

      if (!title.trim()) {
        setError("Title is required");
        return;
      }
      if (!content.trim()) {
        setError("Content is required");
        return;
      }

      setIsSubmitting(true);
      try {
        if (mode === "create") {
          const result = await createNote(title.trim(), content.trim());
          if (result) {
            onClose();
          }
        } else if (noteId) {
          const result = await updateNote(noteId, {
            title: title.trim(),
            content: content.trim(),
          });
          if (result) {
            onClose();
          }
        }
      } finally {
        setIsSubmitting(false);
      }
    },
    [title, content, mode, noteId, createNote, updateNote, onClose],
  );

  return (
    <Dialog open={open} onClose={onClose} size="lg">
      <DialogHeader>
        <DialogTitle>
          {mode === "create" ? "New Secure Note" : "Edit Note"}
        </DialogTitle>
        <DialogDescription>
          {mode === "create"
            ? "Create a new encrypted note. All content is encrypted on your device."
            : "Update the note. Changes are re-encrypted with a fresh key."}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <div className="space-y-4">
            <div>
              <label
                htmlFor="note-title"
                className="mb-1 block text-xs font-medium text-muted-foreground"
              >
                Title
              </label>
              <input
                id="note-title"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Note title"
                maxLength={256}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
                autoFocus
              />
            </div>
            <div>
              <label
                htmlFor="note-content"
                className="mb-1 block text-xs font-medium text-muted-foreground"
              >
                Content
              </label>
              <textarea
                id="note-content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Write your secure note here…"
                rows={12}
                maxLength={100000}
                className="w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
              />
              <p className="mt-1 text-xs text-muted-foreground">
                {content.length.toLocaleString()} / 100,000 characters
              </p>
            </div>
            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}
          </div>
        </DialogContent>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting}>
            {mode === "create" ? "Create Note" : "Save Changes"}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
};

// ─── Delete Confirmation Dialog ───────────────────────────────────

interface DeleteConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  noteTitle: string;
  onConfirm: () => void;
  isDeleting: boolean;
}

const DeleteConfirmDialog: React.FC<DeleteConfirmDialogProps> = ({
  open,
  onClose,
  noteTitle,
  onConfirm,
  isDeleting,
}) => (
  <Dialog open={open} onClose={onClose} size="sm">
    <DialogHeader>
      <DialogTitle>Delete Note</DialogTitle>
      <DialogDescription>
        Are you sure you want to delete &ldquo;{truncate(noteTitle, 40)}&rdquo;?
        This action cannot be undone.
      </DialogDescription>
    </DialogHeader>
    <DialogFooter>
      <Button variant="outline" onClick={onClose} disabled={isDeleting}>
        Cancel
      </Button>
      <Button variant="destructive" onClick={onConfirm} isLoading={isDeleting}>
        Delete
      </Button>
    </DialogFooter>
  </Dialog>
);

// ─── Main NotesView ───────────────────────────────────────────────

export const NotesView: React.FC = () => {
  const notes = useNoteStore((s) => s.notes);
  const selectedNoteId = useNoteStore((s) => s.selectedNoteId);
  const selectNote = useNoteStore((s) => s.selectNote);
  const fetchNotes = useNoteStore((s) => s.fetchNotes);
  const deleteNote = useNoteStore((s) => s.deleteNote);
  const revealNote = useNoteStore((s) => s.revealNote);
  const clearRevealedContent = useNoteStore((s) => s.clearRevealedContent);
  const revealedContent = useNoteStore((s) => s.revealedContent);
  const isRevealing = useNoteStore((s) => s.isRevealing);
  const isLoadingNotes = useNoteStore((s) => s.isLoadingNotes);
  const appState = useAuthStore((s) => s.appState);

  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // Fetch notes when vault is unlocked
  useEffect(() => {
    if (appState === "unlocked") {
      fetchNotes();
    }
  }, [appState, fetchNotes]);

  // Clear revealed content when selecting a different note
  useEffect(() => {
    clearRevealedContent();
  }, [selectedNoteId, clearRevealedContent]);

  const selectedNote = notes.find((n) => n.id === selectedNoteId) ?? null;

  // Filter notes by search query (client-side, on decrypted titles)
  const filteredNotes = searchQuery.trim()
    ? notes.filter((n) =>
        n.title.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : notes;

  // Handlers
  const handleReveal = useCallback(async () => {
    if (!selectedNoteId) return;
    await revealNote(selectedNoteId);
  }, [selectedNoteId, revealNote]);

  const handleDelete = useCallback(async () => {
    if (!selectedNoteId) return;
    setIsDeleting(true);
    const success = await deleteNote(selectedNoteId);
    setIsDeleting(false);
    if (success) {
      setShowDeleteDialog(false);
    }
  }, [selectedNoteId, deleteNote]);

  return (
    <div className="flex h-full gap-4">
      {/* ── Note List Panel ── */}
      <div className="w-80 flex-shrink-0 space-y-3">
        {/* Search & Add */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              type="search"
              placeholder="Filter notes…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
              aria-label="Filter notes"
            />
          </div>
          <Button
            size="icon"
            variant="outline"
            aria-label="New note"
            onClick={() => setShowCreateDialog(true)}
          >
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        {/* Note list */}
        <div
          className="space-y-1 overflow-y-auto"
          style={{ maxHeight: "calc(100vh - 12rem)" }}
        >
          {isLoadingNotes && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Loading notes…
            </p>
          )}

          {!isLoadingNotes && filteredNotes.length === 0 && (
            <div className="py-8 text-center">
              <FileText className="mx-auto h-8 w-8 text-muted-foreground/50" />
              <p className="mt-2 text-sm text-muted-foreground">
                {searchQuery ? "No notes match your search" : "No notes yet"}
              </p>
              <p className="text-xs text-muted-foreground">
                {searchQuery
                  ? "Try a different search term"
                  : "Create your first secure note"}
              </p>
            </div>
          )}

          {filteredNotes.map((note) => (
            <button
              key={note.id}
              type="button"
              onClick={() => selectNote(note.id)}
              className={cn(
                "flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left transition-colors",
                selectedNoteId === note.id
                  ? "bg-accent text-accent-foreground"
                  : "text-foreground hover:bg-accent/50",
              )}
            >
              <div className="flex h-8 w-8 items-center justify-center rounded bg-secondary text-xs font-medium text-secondary-foreground">
                <FileText className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{note.title}</p>
                <p className="text-xs text-muted-foreground">
                  {formatRelativeTime(note.updated_at)}
                </p>
              </div>
              <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
            </button>
          ))}
        </div>
      </div>

      {/* ── Note Detail Panel ── */}
      <div className="flex-1">
        {selectedNote ? (
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <CardTitle>{selectedNote.title}</CardTitle>
                  <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      Updated {formatRelativeTime(selectedNote.updated_at)}
                    </span>
                    <span>Created {formatRelativeTime(selectedNote.created_at)}</span>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowEditDialog(true)}
                    aria-label="Edit note"
                  >
                    <Edit3 className="mr-1 h-3.5 w-3.5" />
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowDeleteDialog(true)}
                    aria-label="Delete note"
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="mr-1 h-3.5 w-3.5" />
                    Delete
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Content reveal area */}
              {revealedContent && revealedContent.id === selectedNote.id ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 rounded-md border border-green-500/20 bg-green-500/5 px-3 py-2">
                    <Eye className="h-3.5 w-3.5 text-green-500" />
                    <span className="text-xs text-green-600 dark:text-green-400">
                      Content revealed — auto-clears in{" "}
                      {revealedContent.auto_clear_seconds}s
                    </span>
                    <button
                      type="button"
                      onClick={clearRevealedContent}
                      className="ml-auto text-xs text-muted-foreground hover:text-foreground"
                    >
                      <EyeOff className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  <div className="rounded-md border border-border bg-muted/30 p-4">
                    <pre className="whitespace-pre-wrap break-words font-sans text-sm text-foreground">
                      {revealedContent.content}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Content placeholder */}
                  <div className="rounded-md border border-dashed border-border bg-muted/20 p-8 text-center">
                    <Eye className="mx-auto h-8 w-8 text-muted-foreground/40" />
                    <p className="mt-2 text-sm text-muted-foreground">
                      Content is encrypted
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Click the button below to reveal the note content.
                      It will be automatically hidden after 60 seconds.
                    </p>
                  </div>
                  <div className="flex justify-center">
                    <Button
                      onClick={handleReveal}
                      isLoading={isRevealing}
                      className="gap-2"
                    >
                      <Eye className="h-4 w-4" />
                      Reveal Content
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <FileText className="mx-auto h-10 w-10 text-muted-foreground/30" />
              <p className="mt-3 text-sm text-muted-foreground">
                Select a note to view
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => setShowCreateDialog(true)}
              >
                <Plus className="mr-1 h-3.5 w-3.5" />
                New Note
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* ── Dialogs ── */}
      <NoteFormDialog
        open={showCreateDialog}
        onClose={() => setShowCreateDialog(false)}
        mode="create"
      />

      {selectedNote && (
        <>
          <NoteFormDialog
            open={showEditDialog}
            onClose={() => setShowEditDialog(false)}
            mode="edit"
            noteId={selectedNote.id}
            initialTitle={
              revealedContent?.id === selectedNote.id
                ? revealedContent.title
                : selectedNote.title
            }
            initialContent={
              revealedContent?.id === selectedNote.id
                ? revealedContent.content
                : ""
            }
          />
          <DeleteConfirmDialog
            open={showDeleteDialog}
            onClose={() => setShowDeleteDialog(false)}
            noteTitle={selectedNote.title}
            onConfirm={handleDelete}
            isDeleting={isDeleting}
          />
        </>
      )}
    </div>
  );
};
