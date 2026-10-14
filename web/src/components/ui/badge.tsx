import * as React from "react";
import { cn } from "@/lib/utils";

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline";
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
        variant === "default" && "border-transparent bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
        variant === "secondary" && "border-transparent bg-gray-800 text-gray-300",
        variant === "destructive" && "border-transparent bg-red-500/10 text-red-400 border-red-500/20",
        variant === "outline" && "border-gray-700 text-gray-300",
        className
      )}
      {...props}
    />
  );
}

export { Badge };
