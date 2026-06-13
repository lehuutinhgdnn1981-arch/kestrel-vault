/**
 * Vault store (Zustand).
 *
 * All mutations go through Tauri commands to the Rust backend.
 * This store only holds display data — passwords are NEVER
 * stored in this or any other React state.
 */

import { create } from "zustand";
import { vaultCommands, folderCommands, type VaultEntryView, type FolderView } from "@/lib/tauri";
import type { VaultSortOptions, VaultFilterOptions } from "@/types/vault";

interface VaultState {
  /** Vault entries (display data only — no passwords) */
  entries: VaultEntryView[];
  /** Currently selected entry */
  selectedEntryId: string | null;
  /** Folders */
  folders: FolderView[];
  /** Sort options */
  sort: VaultSortOptions;
  /** Filter options */
  filter: VaultFilterOptions;
  /** Loading states */
  isLoadingEntries: boolean;
  isLoadingFolders: boolean;
  /** Error state */
  error: string | null;
}

interface VaultActions {
  /** Fetch entries from Rust backend */
  fetchEntries: () => Promise<void>;

  /** Fetch folders from Rust backend */
  fetchFolders: () => Promise<void>;

  /** Select an entry */
  selectEntry: (id: string | null) => void;

  /** Update sort options */
  setSort: (sort: Partial<VaultSortOptions>) => void;

  /** Update filter options */
  setFilter: (filter: Partial<VaultFilterOptions>) => void;

  /** Delete an entry (via Rust backend) */
  deleteEntry: (id: string) => Promise<void>;

  /** Search entries */
  searchEntries: (query: string) => Promise<void>;

  /** Clear all state on lock */
  clearState: () => void;
}

export const useVaultStore = create<VaultState & VaultActions>((set, get) => ({
  entries: [],
  selectedEntryId: null,
  folders: [],
  sort: { field: "updated_at", direction: "desc" },
  filter: {
    search: "",
    folder_id: null,
    has_totp: null,
    has_url: null,
  },
  isLoadingEntries: false,
  isLoadingFolders: false,
  error: null,

  fetchEntries: async () => {
    set({ isLoadingEntries: true, error: null });
    try {
      const entries = await vaultCommands.listEntries(
        get().filter.folder_id ?? undefined,
      );
      set({ entries, isLoadingEntries: false });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to fetch entries",
        isLoadingEntries: false,
      });
    }
  },

  fetchFolders: async () => {
    set({ isLoadingFolders: true });
    try {
      const folders = await folderCommands.listFolders();
      set({ folders, isLoadingFolders: false });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to fetch folders",
        isLoadingFolders: false,
      });
    }
  },

  selectEntry: (id: string | null) => {
    set({ selectedEntryId: id });
  },

  setSort: (sort: Partial<VaultSortOptions>) => {
    set((state) => ({
      sort: { ...state.sort, ...sort },
    }));
  },

  setFilter: (filter: Partial<VaultFilterOptions>) => {
    set((state) => ({
      filter: { ...state.filter, ...filter },
    }));
  },

  deleteEntry: async (id: string) => {
    try {
      await vaultCommands.deleteEntry(id, true);
      set((state) => ({
        entries: state.entries.filter((e) => e.id !== id),
        selectedEntryId: state.selectedEntryId === id ? null : state.selectedEntryId,
      }));
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Failed to delete entry",
      });
    }
  },

  searchEntries: async (query: string) => {
    if (!query.trim()) {
      get().fetchEntries();
      return;
    }
    set({ isLoadingEntries: true, error: null });
    try {
      const entries = await vaultCommands.searchEntries(query);
      set({ entries, isLoadingEntries: false });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : "Search failed",
        isLoadingEntries: false,
      });
    }
  },

  clearState: () => {
    set({
      entries: [],
      selectedEntryId: null,
      folders: [],
      filter: {
        search: "",
        folder_id: null,
        has_totp: null,
        has_url: null,
      },
      error: null,
      isLoadingEntries: false,
      isLoadingFolders: false,
    });
  },
}));
