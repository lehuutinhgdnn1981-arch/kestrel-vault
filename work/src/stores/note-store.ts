/**
 * Note store (Zustand).
 *
 * Manages secure notes state. All mutations go through Tauri
 * commands to the Rust backend. Content is NEVER stored in
 * this store — it's only revealed temporarily via noteReveal.
 */

import { create } from "zustand";
import {
  noteCommands,
  type SecureNoteView,
  type SecureNoteRevealResult,
} from "@/lib/tauri";

interface NoteState {
  /** Secure notes (display data only — no content) */
  notes: SecureNoteView[];
  /** Currently selected note */
  selectedNoteId: string | null;
  /** Loading states */
  isLoadingNotes: boolean;
  /** Revealed content (temporary, auto-cleared) */
  revealedContent: SecureNoteRevealResult | null;
  isRevealing: boolean;
  /** Error state */
  error: string | null;
}

interface NoteActions {
  /** Fetch notes from Rust backend */
  fetchNotes: () => Promise<void>;

  /** Select a note */
  selectNote: (id: string | null) => void;

  /** Create a new note */
  createNote: (
    title: string,
    content: string,
    folderId?: string,
    tags?: string[],
  ) => Promise<SecureNoteView | null>;

  /** Update a note */
  updateNote: (
    id: string,
    updates: {
      title?: string;
      content?: string;
      folderId?: string;
      tags?: string[];
    },
  ) => Promise<SecureNoteView | null>;

  /** Delete a note */
  deleteNote: (id: string) => Promise<boolean>;

  /** Reveal note content (temporary, auto-cleared) */
  revealNote: (id: string) => Promise<SecureNoteRevealResult | null>;

  /** Clear revealed content */
  clearRevealedContent: () => void;

  /** Clear all state on lock */
  clearState: () => void;
}

export const useNoteStore = create<NoteState & NoteActions>((set, get) => ({
  notes: [],
  selectedNoteId: null,
  isLoadingNotes: false,
  revealedContent: null,
  isRevealing: false,
  error: null,

  fetchNotes: async () => {
    set({ isLoadingNotes: true, error: null });
    try {
      const notes = await noteCommands.listNotes();
      set({ notes, isLoadingNotes: false });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to fetch notes",
        isLoadingNotes: false,
      });
    }
  },

  selectNote: (id: string | null) => {
    set({ selectedNoteId: id, revealedContent: null });
  },

  createNote: async (title, content, folderId, tags) => {
    try {
      const note = await noteCommands.createNote(title, content, folderId, tags);
      set((state) => ({
        notes: [note, ...state.notes],
        selectedNoteId: note.id,
        revealedContent: null,
      }));
      return note;
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to create note",
      });
      return null;
    }
  },

  updateNote: async (id, updates) => {
    try {
      const note = await noteCommands.updateNote(id, updates);
      set((state) => ({
        notes: state.notes.map((n) => (n.id === id ? note : n)),
        // Clear revealed content if the note was updated (content may have changed)
        revealedContent:
          state.revealedContent?.id === id ? null : state.revealedContent,
      }));
      return note;
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to update note",
      });
      return null;
    }
  },

  deleteNote: async (id) => {
    try {
      await noteCommands.deleteNote(id, true);
      set((state) => ({
        notes: state.notes.filter((n) => n.id !== id),
        selectedNoteId: state.selectedNoteId === id ? null : state.selectedNoteId,
        revealedContent:
          state.revealedContent?.id === id ? null : state.revealedContent,
      }));
      return true;
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to delete note",
      });
      return false;
    }
  },

  revealNote: async (id) => {
    set({ isRevealing: true, error: null });
    try {
      const result = await noteCommands.revealNote(id);
      set({ revealedContent: result, isRevealing: false });

      // Auto-clear after the specified timeout
      setTimeout(() => {
        const current = get().revealedContent;
        if (current?.id === id) {
          set({ revealedContent: null });
        }
      }, result.auto_clear_seconds * 1000);

      return result;
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to reveal note",
        isRevealing: false,
      });
      return null;
    }
  },

  clearRevealedContent: () => {
    set({ revealedContent: null });
  },

  clearState: () => {
    set({
      notes: [],
      selectedNoteId: null,
      revealedContent: null,
      isRevealing: false,
      error: null,
      isLoadingNotes: false,
    });
  },
}));
