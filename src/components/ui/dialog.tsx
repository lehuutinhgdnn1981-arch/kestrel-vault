import React, { useEffect, useCallback, useRef } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Dialog Overlay ────────────────────────────────────────────────

interface DialogOverlayProps extends React.HTMLAttributes<HTMLDivElement> {
  open: boolean;
}

const DialogOverlay = React.forwardRef<HTMLDivElement, DialogOverlayProps>(
  ({ className, open, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "fixed inset-0 z-40 bg-black/60 transition-opacity duration-200",
        open ? "opacity-100" : "opacity-0 pointer-events-none",
        className,
      )}
      aria-hidden="true"
      {...props}
    />
  ),
);
DialogOverlay.displayName = "DialogOverlay";

// ─── Dialog ────────────────────────────────────────────────────────

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  /** Dialog size variant */
  size?: "sm" | "md" | "lg";
  /** Prevent closing on escape or overlay click */
  persistent?: boolean;
}

const DIALOG_SIZES = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
} as const;

export const Dialog: React.FC<DialogProps> = ({
  open,
  onClose,
  children,
  size = "md",
  persistent = false,
}) => {
  const contentRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  // Save and restore focus
  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement as HTMLElement;
      // Focus the dialog content after it renders
      requestAnimationFrame(() => {
        contentRef.current?.focus();
      });
    } else if (previousFocusRef.current) {
      previousFocusRef.current.focus();
      previousFocusRef.current = null;
    }
  }, [open]);

  // Escape to close
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape" && !persistent) {
        onClose();
      }
    },
    [onClose, persistent],
  );

  useEffect(() => {
    if (open) {
      document.addEventListener("keydown", handleKeyDown);
      return () => document.removeEventListener("keydown", handleKeyDown);
    }
    return undefined;
  }, [open, handleKeyDown]);

  // Focus trap
  const handleTabTrap = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "Tab") return;

    const content = contentRef.current;
    if (!content) return;

    const focusable = content.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    );

    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    }
  }, []);

  // Prevent body scroll when open
  useEffect(() => {
    if (open) {
      document.body.style.overflow = "hidden";
      return () => {
        document.body.style.overflow = "";
      };
    }
    return undefined;
  }, [open]);

  if (!open) return null;

  return (
    <>
      <DialogOverlay open={open} onClick={() => !persistent && onClose()} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          ref={contentRef}
          role="dialog"
          aria-modal="true"
          tabIndex={-1}
          onKeyDown={handleTabTrap}
          className={cn(
            "relative w-full rounded-lg border border-border bg-card text-card-foreground shadow-lg",
            "animate-fade-in",
            DIALOG_SIZES[size],
          )}
        >
          {!persistent && (
            <button
              type="button"
              onClick={onClose}
              className="absolute right-3 top-3 rounded-sm p-1 text-muted-foreground opacity-70 transition-opacity hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label="Close dialog"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
          {children}
        </div>
      </div>
    </>
  );
};

// ─── Dialog Sub-components ─────────────────────────────────────────

export const DialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div
    className={cn("flex flex-col space-y-1.5 p-6 pb-4", className)}
    {...props}
  />
);

export const DialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className,
  ...props
}) => (
  <h2
    className={cn("text-lg font-semibold leading-none tracking-tight", className)}
    {...props}
  />
);

export const DialogDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className,
  ...props
}) => (
  <p
    className={cn("text-sm text-muted-foreground", className)}
    {...props}
  />
);

export const DialogContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={cn("px-6 pb-4", className)} {...props} />
);

export const DialogFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div
    className={cn("flex items-center justify-end gap-2 p-6 pt-4", className)}
    {...props}
  />
);
