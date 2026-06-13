/**
 * Custom hook for async operations.
 *
 * Wraps Tauri commands with loading/error state.
 * Integrates with TanStack Query where appropriate.
 * Shows error toasts on failure.
 */

import { useState, useCallback } from "react";
import { useToast } from "@/components/ui/toast";
import type { AsyncStatus } from "@/types/app";

interface AsyncActionResult<T> {
  /** Current status of the async action */
  status: AsyncStatus;
  /** Result data */
  data: T | null;
  /** Error message if failed */
  error: string | null;
  /** Execute the async action */
  execute: (...args: unknown[]) => Promise<T | null>;
  /** Reset to idle state */
  reset: () => void;
}

interface AsyncActionOptions {
  /** Whether to show error toast on failure (default: true) */
  showErrorToast?: boolean;
  /** Custom error toast title */
  errorToastTitle?: string;
  /** Whether to show success toast */
  successToastTitle?: string;
}

export function useAsyncAction<T = unknown>(
  action: (...args: unknown[]) => Promise<T>,
  options: AsyncActionOptions = {},
): AsyncActionResult<T> {
  const {
    showErrorToast = true,
    errorToastTitle = "Operation failed",
    successToastTitle,
  } = options;

  const toast = useToast();
  const [status, setStatus] = useState<AsyncStatus>("idle");
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  const execute = useCallback(
    async (...args: unknown[]): Promise<T | null> => {
      setStatus("pending");
      setError(null);

      try {
        const result = await action(...args);
        setData(result);
        setStatus("success");

        if (successToastTitle) {
          toast.success(successToastTitle);
        }

        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : "An unexpected error occurred";
        setError(message);
        setStatus("error");

        if (showErrorToast) {
          toast.error(errorToastTitle, message);
        }

        return null;
      }
    },
    [action, showErrorToast, errorToastTitle, successToastTitle, toast],
  );

  const reset = useCallback(() => {
    setStatus("idle");
    setData(null);
    setError(null);
  }, []);

  return { status, data, error, execute, reset };
}

/**
 * Hook for TanStack Query mutation with error toast.
 * Use this when you want automatic cache invalidation after mutations.
 */
export function useMutationWithToast<TData, TVariables>(
  mutationFn: (variables: TVariables) => Promise<TData>,
  options?: {
    onSuccess?: (data: TData) => void;
    successMessage?: string;
    errorMessage?: string;
  },
) {
  const toast = useToast();

  return {
    mutationFn,
    onSuccess: (data: TData) => {
      if (options?.successMessage) {
        toast.success(options.successMessage);
      }
      options?.onSuccess?.(data);
    },
    onError: (error: Error) => {
      toast.error(
        options?.errorMessage ?? "Operation failed",
        error.message,
      );
    },
  };
}
