"use client";
import { useEffect, useState } from "react";
import type { ScanResult } from "@/lib/reconx-types";
export default function ResultsDashboard({
  scanId,
  onBack,
}: {
  scanId: string;
  onBack: () => void;
}) {
  const [result, setResult] = useState<ScanResult | null>(null),
    [error, setError] = useState("");
  useEffect(() => {
    void fetch("/api/scans/" + scanId)
      .then(async (r) => {
        if (!r.ok) throw new Error();
        const d = await r.json();
        setResult(d.results);
        if (!d.results)
          setError("No results export yet. Check the scan log for errors.");
      })
      .catch(() => setError("Could not load results"));
  }, [scanId]);
  const groups = result
    ? Object.entries(result).filter(([, v]) => Array.isArray(v))
    : [];
  return (
    <section>
      <div className="mb-4 flex justify-between">
        <h2 className="text-xl">Scan results</h2>
        <button onClick={onBack}>Back</button>
      </div>
      <p role="alert">{error}</p>
      {result && (
        <>
          <p className="mb-5 text-slate-400">
            Duration: {result.duration} · Secrets are redacted
          </p>
          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
            {groups.map(([key, items]) => (
              <div key={key} className="rounded-lg border border-slate-800 p-4">
                <p className="text-sm text-slate-400">
                  {key.replaceAll("_", " ")}
                </p>
                <p className="text-2xl text-emerald-400">
                  {(items as unknown[]).length}
                </p>
              </div>
            ))}
          </div>
          {groups.map(([key, items]) => (
            <details key={key} className="mb-3 rounded-lg bg-slate-900 p-4">
              <summary>
                {key.replaceAll("_", " ")} ({(items as unknown[]).length})
              </summary>
              <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap text-xs">
                {JSON.stringify(items, null, 2)}
              </pre>
            </details>
          ))}
        </>
      )}
    </section>
  );
}
