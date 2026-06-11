/**
 * Settings view (skeleton/placeholder for Phase 10).
 */

import React from "react";
import { Settings, Palette, Clock, Globe, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

const SETTINGS_SECTIONS = [
  {
    icon: Clock,
    title: "Auto-Lock",
    description: "Configure inactivity timeout before vault locks automatically",
  },
  {
    icon: Palette,
    title: "Appearance",
    description: "Theme and display preferences",
  },
  {
    icon: Globe,
    title: "Language",
    description: "Interface language selection",
  },
  {
    icon: Shield,
    title: "Security",
    description: "Clipboard clear timeout, session management, vault maintenance",
  },
];

export const SettingsView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-foreground">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Configure your vault preferences
        </p>
      </div>

      <div className="grid gap-4">
        {SETTINGS_SECTIONS.map((section) => {
          const Icon = section.icon;
          return (
            <Card key={section.title}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                  {section.title}
                </CardTitle>
                <CardDescription>{section.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground">
                  Configuration options will be available in Phase 10.
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Version info */}
      <div className="border-t border-border pt-4">
        <div className="flex items-center gap-2">
          <Settings className="h-3.5 w-3.5 text-muted-foreground" />
          <p className="text-xs text-muted-foreground">
            KESTREL Vault v0.1.0 · All cryptographic operations are handled by the Rust backend
          </p>
        </div>
      </div>
    </div>
  );
};
