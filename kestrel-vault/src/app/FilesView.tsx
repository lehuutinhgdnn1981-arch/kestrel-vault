/**
 * File Vault view.
 *
 * Encrypted file storage on the local device. Files are encrypted
 * by the Rust backend using AES-256-GCM before being written to
 * disk. The frontend never handles plaintext file data.
 *
 * NOTE: File upload/download requires Tauri file dialog APIs
 * which will be implemented in a future iteration. This view
 * provides the UI shell with file listing and metadata display.
 */

import React, { useState } from "react";
import {
  FolderLock,
  File,
  FileText,
  FileImage,
  FileArchive,
  Upload,
  Download,
  Trash2,
  HardDrive,
  Clock,
  Search,
} from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn, formatRelativeTime } from "@/lib/utils";
import type { FileEntryView } from "@/lib/tauri";

// ─── File type icon helper ────────────────────────────────────────

const getFileIcon = (mimeType: string): React.FC<{ className?: string }> => {
  if (mimeType.startsWith("image/")) return FileImage;
  if (mimeType.startsWith("text/") || mimeType.includes("pdf") || mimeType.includes("document"))
    return FileText;
  if (mimeType.includes("zip") || mimeType.includes("archive") || mimeType.includes("tar"))
    return FileArchive;
  return File;
};

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

// ─── Sample/empty state for now ───────────────────────────────────

// In production, this would come from a file store connected to
// fileCommands.listFiles(). For now, we show the UI shell.

export const FilesView: React.FC = () => {
  const appState = useAuthStore((s) => s.appState);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);

  // TODO: Replace with useFileStore once file commands are registered
  const files: FileEntryView[] = [];

  const filteredFiles = searchQuery.trim()
    ? files.filter((f) =>
        f.filename.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : files;

  const selectedFile = files.find((f) => f.id === selectedFileId) ?? null;

  const totalSize = files.reduce((sum, f) => sum + f.size_bytes, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">File Vault</h2>
          <p className="text-sm text-muted-foreground">
            Encrypted file storage on your device
          </p>
        </div>
        <Button
          onClick={() => {
            // TODO: Implement file upload via Tauri file dialog
            // This will require:
            // 1. Opening a file picker dialog
            // 2. Reading the file in Rust
            // 3. Encrypting with AES-256-GCM
            // 4. Writing to the vault directory
            // 5. Storing metadata in the database
          }}
          disabled={appState !== "unlocked"}
        >
          <Upload className="mr-1 h-4 w-4" />
          Upload File
        </Button>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <FolderLock className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-lg font-bold">{files.length}</p>
              <p className="text-xs text-muted-foreground">Files</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <HardDrive className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-lg font-bold">{formatFileSize(totalSize)}</p>
              <p className="text-xs text-muted-foreground">Total size</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Clock className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-lg font-bold">--</p>
              <p className="text-xs text-muted-foreground">Last upload</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          type="search"
          placeholder="Search files…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
          aria-label="Search files"
        />
      </div>

      {/* File list */}
      {filteredFiles.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-12">
            <FolderLock className="h-12 w-12 text-muted-foreground/30" />
            <div className="text-center">
              <p className="text-sm font-medium text-muted-foreground">
                {searchQuery ? "No files match your search" : "No encrypted files yet"}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                {searchQuery
                  ? "Try a different search term"
                  : "Upload files to encrypt and store them locally. All file encryption is performed by the Rust backend — files are never held in JavaScript memory in plaintext."}
              </p>
            </div>
            {!searchQuery && (
              <Button
                variant="outline"
                onClick={() => {
                  // TODO: File upload
                }}
                disabled={appState !== "unlocked"}
              >
                <Upload className="mr-1 h-4 w-4" />
                Upload Your First File
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {filteredFiles.map((file) => {
            const Icon = getFileIcon(file.mime_type);
            const isSelected = selectedFileId === file.id;

            return (
              <Card
                key={file.id}
                className={cn(
                  "cursor-pointer transition-colors hover:bg-muted/30",
                  isSelected && "ring-1 ring-primary",
                )}
                onClick={() => setSelectedFileId(isSelected ? null : file.id)}
              >
                <CardContent className="flex items-center gap-3 p-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded bg-secondary">
                    <Icon className="h-5 w-5 text-secondary-foreground" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{file.filename}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatFileSize(file.size_bytes)} · {file.mime_type}
                    </p>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-muted-foreground">
                      {formatRelativeTime(file.created_at)}
                    </span>
                    <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Download">
                      <Download className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      aria-label="Delete"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Info notice */}
      <div className="rounded-md border border-border bg-muted/20 px-4 py-3">
        <p className="text-xs text-muted-foreground">
          <strong>How file encryption works:</strong> When you upload a file, the
          Rust backend encrypts it using AES-256-GCM with a file-specific sub-key
          derived from the DEK. The encrypted file is stored on disk, and only
          the encrypted metadata (filename, size, MIME type) is stored in the
          database. Files are decrypted on-demand when you download them — they
          are never held in JavaScript memory in plaintext.
        </p>
      </div>
    </div>
  );
};
