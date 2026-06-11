/**
 * Threat scanner view (skeleton/placeholder for Phase 07).
 */

import React from "react";
import { ScanSearch } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const ScannerView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Threat Scanner</h2>
          <p className="text-sm text-muted-foreground">
            Scan for vulnerabilities and compromised credentials
          </p>
        </div>
        <Button disabled>
          Run Scan
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScanSearch className="h-5 w-5 text-muted-foreground" />
            Coming in Phase 07
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            The Threat Scanner will analyze your vault entries for weak
            passwords, reused credentials, and compromised accounts.
            All password strength analysis is performed by the Rust
            backend — passwords are never sent to external services.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {[
              "Password strength analysis",
              "Reuse detection",
              "Breach database lookup (local)",
              "Security score dashboard",
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
