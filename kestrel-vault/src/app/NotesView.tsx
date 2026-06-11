/**
 * Secure notes view (skeleton/placeholder for Phase 05).
 */

import React from "react";
import { FileText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const NotesView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Secure Notes</h2>
          <p className="text-sm text-muted-foreground">
            Encrypted notes stored locally
          </p>
        </div>
        <Button disabled>
          New Note
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-muted-foreground" />
            Coming in Phase 05
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Secure notes will allow you to store sensitive text, markdown,
            and rich content encrypted on your device. All encryption
            and decryption is handled by the Rust backend — React never
            handles cryptographic operations or keys.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {[
              "Encrypted text notes",
              "Markdown support",
              "Folder organization",
              "Full-text search",
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
