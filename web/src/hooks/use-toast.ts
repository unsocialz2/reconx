import * as React from "react";

type ToastProps = {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
};

export function useToast() {
  const toast = React.useCallback(({ title, description }: ToastProps) => {
    console.log(`[Toast] ${title}: ${description}`);
  }, []);

  return { toast, toasts: [] };
}
