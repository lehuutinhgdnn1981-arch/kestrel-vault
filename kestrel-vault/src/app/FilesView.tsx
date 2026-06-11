/**
 * File vault view (skeleton/placeholder for Phase 06).
 */

import React from "react";
import { FolderLock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const FilesView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">File Vault</h2>
          <p className="text-sm text-muted-foreground">
            Encrypted file storage on your device
          </p>
        </div>
        <Button disabled>
          Upload File
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderLock className="h-5 w-5 text-muted-foreground" />
            Coming in Phase 06
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            File Vault will provide encrypted local storage for sensitive
            documents, images, and other files. All file encryption and
            decryption is performed by the Rust backend using stream
            ciphers — files are never held in JavaScript memory in
            plaintext.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {[
              "AES-256-GCM file encryption",
              "Drag-and-drop upload",
              "File preview for common types",
              "Secure file sharing",
            ].map((feature) => (
              <div
                key={feature}
                className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground"
              >
                {feature}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
