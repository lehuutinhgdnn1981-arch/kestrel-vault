/**
 * Audit log view (skeleton/placeholder for Phase 08).
 */

import React from "react";
import { ScrollText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const AuditView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Audit Logs</h2>
          <p className="text-sm text-muted-foreground">
            Track all vault activity and security events
          </p>
        </div>
        <Button variant="outline" disabled>
          Export Logs
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="h-5 w-5 text-muted-foreground" />
            Coming in Phase 08
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Audit Logs will record all vault operations including unlocks,
            entry access, modifications, and security events. Logs are
            stored locally and can be exported for compliance. The Rust
            backend handles all log writing to prevent tampering.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {[
              "Comprehensive event logging",
              "Filterable timeline view",
              "Export to CSV/JSON",
              "Suspicious activity alerts",
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
