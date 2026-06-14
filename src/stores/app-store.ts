/**
 * App store (Zustand).
 *
 * General application state: navigation, theme, sidebar, etc.
 */

import { create } from "zustand";
import type { Theme } from "@/types/app";
import { DEFAULT_SETTINGS } from "@/lib/constants";

type ActiveModule =
  | "vault"
  | "notes"
  | "files"
  | "scanner"
  | "audit"
  | "security-center"
  | "settings";

interface AppState {
  /** Current active module */
  activeModule: ActiveModule;
  /** Theme preference */
  theme: Theme;
  /** Whether sidebar is collapsed */
  sidebarCollapsed: boolean;
  /** Global search query */
  searchQuery: string;
  /** Toast notifications */
  toasts: Array<{
    id: string;
    variant: "success" | "error" | "warning" | "info";
    title: string;
    description?: string;
    duration?: number;
  }>;
}

interface AppActions {
  /** Set the active module */
  setActiveModule: (module: ActiveModule) => void;

  /** Set theme */
  setTheme: (theme: Theme) => void;

  /** Toggle sidebar collapsed */
  toggleSidebar: () => void;

  /** Set sidebar collapsed */
  setSidebarCollapsed: (collapsed: boolean) => void;

  /** Set global search query */
  setSearchQuery: (query: string) => void;

  /** Add a toast notification */
  addToast: (toast: Omit<AppState["toasts"][number], "id">) => void;

  /** Remove a toast by id */
  removeToast: (id: string) => void;
}

let toastCounter = 0;

export const useAppStore = create<AppState & AppActions>((set) => ({
  activeModule: "vault",
  theme: DEFAULT_SETTINGS.theme,
  sidebarCollapsed: false,
  searchQuery: "",
  toasts: [],

  setActiveModule: (module: ActiveModule) => {
    set({ activeModule: module });
  },

  setTheme: (theme: Theme) => {
    set({ theme });

    // Apply theme class to document
    if (theme === "system") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.documentElement.classList.toggle("dark", prefersDark);
      document.documentElement.classList.toggle("light", !prefersDark);
    } else {
      document.documentElement.classList.remove("dark", "light");
      document.documentElement.classList.add(theme);
    }
  },

  toggleSidebar: () => {
    set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }));
  },

  setSidebarCollapsed: (collapsed: boolean) => {
    set({ sidebarCollapsed: collapsed });
  },

  setSearchQuery: (query: string) => {
    set({ searchQuery: query });
  },

  addToast: (toast) => {
    const id = `toast-${++toastCounter}`;
    set((state) => ({
      toasts: [...state.toasts, { ...toast, id }],
    }));
  },

  removeToast: (id: string) => {
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    }));
  },
}));
