import { toast as notify } from "sonner";
export function useToast() {
  return {
    toast: ({
      title,
      description,
      variant,
    }: {
      title?: string;
      description?: string;
      variant?: "default" | "destructive";
    }) =>
      variant === "destructive"
        ? notify.error(title, { description })
        : notify(title, { description }),
    toasts: [],
  };
}
