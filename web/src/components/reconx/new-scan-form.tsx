"use client";
import { useEffect, useState } from "react";
import type { ScanConfig, SavedSettings } from "@/lib/reconx-types";
const split = (s: string) =>
  s
    .split(/[,\n]+/)
    .map((v) => v.trim())
    .filter(Boolean);
export default function NewScanForm({
  onStartScan,
}: {
  onStartScan: (cfg: ScanConfig) => Promise<void>;
}) {
  const [domains, setDomains] = useState(""),
    [scopeIn, setIn] = useState(""),
    [scopeOut, setOut] = useState(""),
    [busy, setBusy] = useState(false),
    [settings, setSettings] = useState<SavedSettings>({ workers: 10 }),
    [message, setMessage] = useState("");
  const [options, setOptions] = useState<Partial<ScanConfig>>({});
  useEffect(() => {
    void fetch("/api/settings")
      .then((r) => r.json())
      .then((d) => setSettings(d.settings))
      .catch(() => setMessage("Settings could not be loaded"));
  }, []);
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-4 text-xl">Start a scan</h2>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            await onStartScan({
              ...options,
              domains: split(domains),
              scopeIn: split(scopeIn),
              scopeOut: split(scopeOut),
              header: settings.customHeader,
              workers: settings.workers,
              tokens: {
                github: settings.githubToken,
                chaos: settings.chaosKey,
                shodan: settings.shodanKey,
                virustotal: settings.virustotalKey,
                securitytrails: settings.securitytrailsKey,
              },
            });
          } finally {
            setBusy(false);
          }
        }}
        className="grid gap-4"
      >
        <label>
          Recon profile
          <select
            value={options.profile || "standard"}
            onChange={(e) =>
              setOptions({
                ...options,
                profile: e.target.value as ScanConfig["profile"],
              })
            }
            className="mt-2 block w-full rounded bg-slate-950 p-3"
          >
            <option value="quick">Quick · lower recon budgets</option>
            <option value="standard">Standard</option>
            <option value="deep">Deep · longer recon budgets</option>
            <option value="custom">Custom</option>
          </select>
          <p className="text-xs text-slate-400">
            Profiles do not enable ports or Nuclei.
          </p>
        </label>
        <label>
          Authorized domains
          <textarea
            required
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder="example.com"
            className="mt-2 block w-full rounded bg-slate-950 p-3"
          />
        </label>
        <div className="grid gap-4 md:grid-cols-2">
          <label>
            Include scope
            <textarea
              value={scopeIn}
              onChange={(e) => setIn(e.target.value)}
              placeholder="*.example.com"
              className="mt-2 block w-full rounded bg-slate-950 p-3"
            />
          </label>
          <label>
            Exclude scope
            <textarea
              value={scopeOut}
              onChange={(e) => setOut(e.target.value)}
              placeholder="staging.example.com"
              className="mt-2 block w-full rounded bg-slate-950 p-3"
            />
          </label>
        </div>
        <label>
          Workers
          <input
            type="number"
            min={1}
            max={256}
            value={settings.workers || 10}
            onChange={(e) =>
              setSettings({ ...settings, workers: Number(e.target.value) })
            }
            className="ml-3 rounded bg-slate-950 p-2"
          />
        </label>
        <label>
          Testing header
          <input
            value={settings.customHeader || ""}
            onChange={(e) =>
              setSettings({ ...settings, customHeader: e.target.value })
            }
            placeholder="X-Bug-Bounty: researcher"
            className="mt-2 block w-full rounded bg-slate-950 p-3"
          />
        </label>
        <details>
          <summary>Scan phases</summary>
          {(
            [
              ["skipSubs", "Skip subdomain discovery"],
              ["enablePorts", "Opt in: port scanning (only when permitted)"],
              ["enableNuclei", "Opt in: Nuclei scanning (only when permitted)"],
              ["skipJs", "Skip JS analysis"],
              ["skipCors", "Skip CORS checks"],
              ["enableFuzz", "Enable directory discovery"],
              ["enableParams", "Enable parameter discovery"],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="mt-2 block">
              <input
                type="checkbox"
                checked={Boolean(options[key])}
                onChange={(e) =>
                  setOptions({ ...options, [key]: e.target.checked })
                }
                className="mr-2"
              />
              {label}
            </label>
          ))}
        </details>
        <details>
          <summary>API tokens</summary>
          {(
            [
              "githubToken",
              "chaosKey",
              "shodanKey",
              "virustotalKey",
              "securitytrailsKey",
            ] as const
          ).map((key) => (
            <label key={key} className="mt-3 block">
              {key}
              <input
                type="password"
                autoComplete="off"
                value={settings[key] || ""}
                onChange={(e) =>
                  setSettings({ ...settings, [key]: e.target.value })
                }
                className="mt-1 block w-full rounded bg-slate-950 p-2"
              />
            </label>
          ))}
        </details>
        <div className="flex gap-4">
          <button
            disabled={busy}
            className="rounded bg-emerald-400 px-5 py-2 font-semibold text-slate-950"
          >
            {busy ? "Launching…" : "Launch scan"}
          </button>
          <button
            type="button"
            onClick={async () => {
              const r = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(settings),
              });
              setMessage(
                r.ok ? "Settings saved" : "Settings could not be saved",
              );
            }}
          >
            Save settings
          </button>
        </div>
        <p role="status" className="text-sm text-slate-400">
          {message}
        </p>
      </form>
    </section>
  );
}
