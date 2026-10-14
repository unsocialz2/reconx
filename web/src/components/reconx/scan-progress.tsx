"use client";
import { useEffect, useState } from "react";
import type { ScanMetadata } from "@/lib/reconx-types";
export default function ScanProgress({
  scanId,
  onViewResults,
  onBack,
}: {
  scanId: string;
  onViewResults: (id: string) => void;
  onBack: () => void;
}) {
  const [scan, setScan] = useState<ScanMetadata | null>(null),
    [log, setLog] = useState(""),
    [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const r = await fetch("/api/scans/" + scanId);
        if (!r.ok) throw new Error();
        const d = await r.json();
        if (alive) {
          setScan(d.scan);
          setLog(d.log);
        }
      } catch {
        if (alive) setError("Could not refresh scan");
      }
    };
    void poll();
    const timer = setInterval(poll, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [scanId]);
  return (
    <section>
      <div className="mb-4 flex flex-wrap justify-between gap-3">
        <h2 className="text-xl">Scan · {scan?.status || "Loading"}</h2>
        <div className="flex gap-4">
          <button onClick={onBack}>Back</button>
          <button onClick={() => onViewResults(scanId)}>View results</button>
          {scan?.status === "running" && (
            <button
              className="text-red-400"
              onClick={async () => {
                const r = await fetch("/api/scans/" + scanId, {
                  method: "DELETE",
                });
                if (!r.ok) setError("Could not stop scan");
              }}
            >
              Stop scan
            </button>
          )}
        </div>
      </div>
      <p role="alert">{error}</p>
      <pre className="max-h-[65vh] overflow-auto whitespace-pre-wrap rounded-xl bg-slate-950 p-5 text-xs text-slate-300">
        {log || "Waiting for output…"}
      </pre>
    </section>
  );
}
