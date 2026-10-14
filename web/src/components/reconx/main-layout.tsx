"use client";
import type { ReactNode } from "react";
import type { ViewMode } from "@/lib/reconx-types";
export default function MainLayout({
  children,
  activeView,
  onViewChange,
  runningScanId,
}: {
  children: ReactNode;
  activeView: ViewMode;
  onViewChange: (view: ViewMode) => void;
  runningScanId: string | null;
}) {
  return (
    <main className="mx-auto max-w-6xl p-6">
      <header className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-emerald-400">ReconX</h1>
          <p className="text-sm text-slate-400">
            Scoped reconnaissance · Evidence first
          </p>
        </div>
        <nav className="flex gap-3">
          {(
            [
              ["new-scan", "New scan"],
              ["history", "History"],
              ["guide", "Guide"],
            ] as const
          ).map(([view, label]) => (
            <button
              key={view}
              onClick={() => onViewChange(view)}
              className={
                activeView === view ? "text-emerald-400" : "text-slate-400"
              }
            >
              {label}
            </button>
          ))}
          {runningScanId && (
            <span className="text-amber-400">Scan running</span>
          )}
        </nav>
      </header>
      {children}
    </main>
  );
}
