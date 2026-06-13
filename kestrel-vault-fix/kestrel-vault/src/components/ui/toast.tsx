import React, { useEffect, useCallback } from "react";
import { X, CheckCircle2, AlertCircle, AlertTriangle, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/stores/app-store";
import { TIMEOUTS } from "@/lib/constants";

// ─── Toast Item ────────────────────────────────────────────────────

const VARIANT_STYLES = {
  success: {
    container: "border-success/30 bg-success/10",
    icon: "text-success",
    IconComponent: CheckCircle2,
  },
  error: {
    container: "border-destructive/30 bg-destructive/10",
    icon: "text-destructive",
    IconComponent: AlertCircle,
  },
  warning: {
    container: "border-warning/30 bg-warning/10",
    icon: "text-warning",
    IconComponent: AlertTriangle,
  },
  info: {
    container: "border-primary/30 bg-primary/10",
    icon: "text-primary",
    IconComponent: Info,
  },
} as const;

interface ToastItemProps {
  id: string;
  variant: "success" | "error" | "warning" | "info";
  title: string;
  description?: string;
  duration?: number;
}

const ToastItem: React.FC<ToastItemProps> = ({
  id,
  variant,
  title,
  description,
  duration,
}) => {
  const removeToast = useAppStore((s) => s.removeToast);
  const style = VARIANT_STYLES[variant];
  const IconComp = style.IconComponent;

  const handleDismiss = useCallback(() => {
    removeToast(id);
  }, [id, removeToast]);

  useEffect(() => {
    const timeout = duration ?? (variant === "error" ? TIMEOUTS.toastErrorDisplay : TIMEOUTS.toastDisplay);
    const timer = setTimeout(handleDismiss, timeout);
    return () => clearTimeout(timer);
  }, [duration, variant, handleDismiss]);

  return (
    <div
      role="alert"
      className={cn(
        "pointer-events-auto flex w-80 items-start gap-3 rounded-md border p-4 shadow-md animate-slide-in-from-top",
        style.container,
      )}
    >
      <IconComp className={cn("h-4 w-4 mt-0.5 flex-shrink-0", style.icon)} aria-hidden="true" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description && (
          <p className="mt-1 text-xs text-muted-foreground">{description}</p>
        )}
      </div>
      <button
        type="button"
        onClick={handleDismiss}
        className="flex-shrink-0 rounded-sm p-0.5 text-muted-foreground opacity-70 hover:opacity-100 transition-opacity"
        aria-label="Dismiss notification"
      >
        <X className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    </div>
  );
};

// ─── Toast Container ───────────────────────────────────────────────

export const ToastContainer: React.FC = () => {
  const toasts = useAppStore((s) => s.toasts);

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none"
      aria-live="polite"
      aria-label="Notifications"
    >
      {toasts.map((toast) => (
        <ToastItem
          key={toast.id}
          id={toast.id}
          variant={toast.variant}
          title={toast.title}
          description={toast.description}
          duration={toast.duration}
        />
      ))}
    </div>
  );
};

// ─── useToast helper ───────────────────────────────────────────────

export function useToast() {
  const addToast = useAppStore((s) => s.addToast);

  return {
    success: (title: string, description?: string) =>
      addToast({ variant: "success", title, description }),
    error: (title: string, description?: string) =>
      addToast({ variant: "error", title, description }),
    warning: (title: string, description?: string) =>
      addToast({ variant: "warning", title, description }),
    info: (title: string, description?: string) =>
      addToast({ variant: "info", title, description }),
  };
}
