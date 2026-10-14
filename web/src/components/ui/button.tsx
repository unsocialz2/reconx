import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link";
  size?: "default" | "sm" | "lg" | "icon";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 disabled:pointer-events-none disabled:opacity-50 cursor-pointer",
          variant === "default" && "bg-emerald-600 text-white shadow hover:bg-emerald-500",
          variant === "destructive" && "bg-red-600 text-white shadow-sm hover:bg-red-500",
          variant === "outline" && "border border-gray-700 bg-transparent hover:bg-gray-800 text-gray-200",
          variant === "secondary" && "bg-gray-800 text-gray-100 shadow-sm hover:bg-gray-700",
          variant === "ghost" && "hover:bg-gray-800 text-gray-300 hover:text-white",
          variant === "link" && "text-emerald-400 underline-offset-4 hover:underline",
          size === "default" && "h-9 px-4 py-2",
          size === "sm" && "h-8 rounded-md px-3 text-xs",
          size === "lg" && "h-10 rounded-md px-8",
          size === "icon" && "h-9 w-9",
          className
        )}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
export { Button };
