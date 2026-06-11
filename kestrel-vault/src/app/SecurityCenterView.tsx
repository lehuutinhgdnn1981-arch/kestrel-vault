/**
 * Security center view (skeleton/placeholder for Phase 09).
 */

import React from "react";
import { ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const SecurityCenterView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-foreground">Security Center</h2>
        <p className="text-sm text-muted-foreground">
          Overview of your vault security posture
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-muted-foreground" />
            Coming in Phase 09
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            The Security Center will provide a comprehensive dashboard
            showing your overall security score, pending recommendations,
            and actionable items. All security analysis is performed by
            the Rust backend — React only displays the results.
          </p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {[
              "Security score overview",
              "Actionable recommendations",
              "Encryption status monitor",
              "Session management",
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
