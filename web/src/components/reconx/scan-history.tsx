"use client";
import { useEffect, useState } from "react";
import type { ScanMetadata } from "@/lib/reconx-types";
export default function ScanHistory({
  onViewResults,
  onViewProgress,
  onRefresh,
}: {
  onViewResults: (id: string) => void;
  onViewProgress: (id: string) => void;
  onRefresh: () => void;
}) {
  const [scans, setScans] = useState<ScanMetadata[]>([]),
    [error, setError] = useState("");
  async function load() {
    try {
      const r = await fetch("/api/scans");
      if (!r.ok) throw new Error();
      setScans((await r.json()).scans);
      setError("");
    } catch {
      setError("Could not load scan history");
    }
  }
  useEffect(() => {
    let active = true;
    void fetch("/api/scans")
      .then(async (r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then((d) => {
        if (active) setScans(d.scans);
      })
      .catch(() => {
        if (active) setError("Could not load scan history");
      });
    return () => {
      active = false;
    };
  }, []);
  return (
    <section>
      <div className="mb-4 flex justify-between">
        <h2 className="text-xl">Scan history</h2>
        <button
          onClick={() => {
            void load();
            onRefresh();
          }}
        >
          Refresh
        </button>
      </div>
      <p role="alert">{error}</p>
      {scans.length === 0 && !error ? (
        <p>No scans yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th>Targets</th>
                <th>Started</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-t border-slate-800">
                  <td className="py-4">{s.domains.join(", ")}</td>
                  <td>{new Date(s.startTime).toLocaleString()}</td>
                  <td>{s.status}</td>
                  <td>
                    <button
                      className="text-emerald-400"
                      onClick={() =>
                        s.status === "running"
                          ? onViewProgress(s.id)
                          : onViewResults(s.id)
                      }
                    >
                      {s.status === "running" ? "Monitor" : "Results"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
