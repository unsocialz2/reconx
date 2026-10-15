import { promises as fs, createWriteStream } from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { BINARY_PATH, SCANS_DIR, OUTPUT_DIR } from "./paths";
import type { ScanMetadata } from "./reconx-types";

const clean = z
  .string()
  .max(4096)
  .refine((v) => !/[\r\n\0]/.test(v), "Must be one line");
const domain = z
  .string()
  .max(253)
  .regex(/^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/)
  .refine((v) => v.includes("."), "Expected a domain");
export const scanSchema = z
  .object({
    domains: z.array(domain).min(1).max(100),
    ipRanges: z.array(clean).max(100).optional(),
    asns: z
      .array(z.string().regex(/^AS?\d+$/i))
      .max(20)
      .optional(),
    orgName: clean.optional(),
    scopeIn: z.array(clean).max(1000).optional(),
    scopeOut: z.array(clean).max(1000).optional(),
    header: clean.optional(),
    wordlist: clean.optional(),
    skipSubs: z.boolean().optional(),
    skipAlive: z.boolean().optional(),
    profile: z.enum(["quick", "standard", "deep", "custom"]).optional(),
    skipPorts: z.boolean().optional(),
    enablePorts: z.boolean().optional(),
    enableNuclei: z.boolean().optional(),
    skipUrls: z.boolean().optional(),
    skipJs: z.boolean().optional(),
    skipVuln: z.boolean().optional(),
    enableFuzz: z.boolean().optional(),
    enableParams: z.boolean().optional(),
    skipCloud: z.boolean().optional(),
    skipCors: z.boolean().optional(),
    noTimeout: z.boolean().optional(),
    workers: z.number().int().min(1).max(256).optional(),
    cloudAssets: z.array(z.string().url()).max(100).optional(),
    tokens: z
      .object({
        github: clean.optional(),
        chaos: clean.optional(),
        shodan: clean.optional(),
        virustotal: clean.optional(),
        securitytrails: clean.optional(),
      })
      .optional(),
  })
  .strict();
const state = globalThis as typeof globalThis & {
  reconxChildren?: Map<string, ChildProcess>;
  reconxShutdownInstalled?: boolean;
};
const children = (state.reconxChildren ||= new Map<string, ChildProcess>());
if (!state.reconxShutdownInstalled) {
  state.reconxShutdownInstalled = true;
  const shutdown = () => {
    for (const child of children.values()) child.kill("SIGTERM");
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}
function scanPath(id: string) {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("Invalid scan ID");
  return path.join(SCANS_DIR, id);
}
export async function atomicJSON(file: string, data: unknown) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = file + "." + randomUUID() + ".tmp";
  await fs.writeFile(temp, JSON.stringify(data, null, 2), { mode: 0o600 });
  await fs.rename(temp, file);
}
async function save(meta: ScanMetadata) {
  await atomicJSON(path.join(scanPath(meta.id), "metadata.json"), meta);
}
export async function readScan(id: string): Promise<ScanMetadata> {
  const meta: ScanMetadata = JSON.parse(
    await fs.readFile(path.join(scanPath(id), "metadata.json"), "utf8"),
  );
  if (meta.status === "running" && !children.has(id)) {
    meta.status = "failed";
    meta.endTime = new Date().toISOString();
    await save(meta);
  }
  return meta;
}
export async function listScans() {
  await fs.mkdir(SCANS_DIR, { recursive: true, mode: 0o700 });
  const entries = await fs.readdir(SCANS_DIR);
  const scans: ScanMetadata[] = [];
  for (const id of entries) {
    try {
      scans.push(await readScan(id));
    } catch {
      /* unrelated files */
    }
  }
  return scans.sort((a, b) => b.startTime.localeCompare(a.startTime));
}
export async function launch(input: unknown) {
  const cfg = scanSchema.parse(input);
  if (children.size >= 4) throw new Error("Four scans are already running");
  await fs.access(BINARY_PATH);
  const id = randomUUID(),
    dir = scanPath(id);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const ini = [
    "[scope]",
    "in_scope = " + JSON.stringify(cfg.scopeIn || []),
    "out_of_scope = " + JSON.stringify(cfg.scopeOut || []),
    "[tokens]",
    ...Object.entries(cfg.tokens || {}).map(
      ([k, v]) => k + " = " + JSON.stringify(v),
    ),
    "[output]",
    "output_dir = " + JSON.stringify(OUTPUT_DIR),
  ].join("\n");
  const configFile = path.join(dir, "scan.ini");
  await fs.writeFile(configFile, ini, { mode: 0o600 });
  const args = [
    "--profile",
    cfg.profile || "standard",
    "--config",
    configFile,
    "--output",
    OUTPUT_DIR,
    "--workers",
    String(cfg.workers || 10),
  ];
  for (const d of cfg.domains) args.push("-d", d);
  for (const ip of cfg.ipRanges || []) args.push("--ip", ip);
  for (const asn of cfg.asns || []) args.push("--asn", asn);
  for (const asset of cfg.cloudAssets || []) args.push("--cloud-asset", asset);
  for (const [key, flag] of [
    ["orgName", "org"],
    ["header", "header"],
    ["wordlist", "wordlist"],
  ] as const) {
    if (cfg[key]) args.push("--" + flag, cfg[key]!);
  }
  for (const [key, flag] of [
    ["skipSubs", "skip-subs"],
    ["skipAlive", "skip-alive"],

    ["skipUrls", "skip-urls"],
    ["skipJs", "skip-js"],

    ["enableFuzz", "fuzz"],
    ["enableParams", "params"],
    ["skipCloud", "skip-cloud"],
    ["skipCors", "skip-cors"],
    ["noTimeout", "no-timeout"],
  ] as const)
    if (cfg[key]) args.push("--" + flag);
  args.push(cfg.enablePorts && !cfg.skipPorts ? "--ports" : "--skip-ports");
  args.push(cfg.enableNuclei && !cfg.skipVuln ? "--nuclei" : "--skip-vuln");
  const now = new Date().toISOString();
  const pendingMeta: ScanMetadata = {
    id,
    domains: cfg.domains,
    startTime: new Date().toISOString(),
    status: "running",
    outputDir: "",
  };
  await save(pendingMeta);
  const child = spawn(BINARY_PATH, args, {
    cwd: dir,
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
  });
  children.set(id, child);
  const meta: ScanMetadata = { ...pendingMeta, startTime: now, pid: child.pid };
  const log = createWriteStream(path.join(dir, "scan.log"), { mode: 0o600 });
  child.stdout?.pipe(log, { end: false });
  child.stderr?.pipe(log, { end: false });
  let done = false;
  const finish = async (ok: boolean) => {
    if (done) return;
    done = true;
    children.delete(id);
    log.end();
    const current = await readScan(id).catch(() => meta);
    const details = await scanDetails(id).catch(() => null);
    if (details?.scan.outputDir) current.outputDir = details.scan.outputDir;
    current.status =
      current.status === "stopped"
        ? "stopped"
        : ok
          ? "completed"
          : details?.results
            ? "partial"
            : "failed";
    current.endTime = new Date().toISOString();
    await save(current);
    await fs.rm(configFile, { force: true });
  };
  child.once("error", () => {
    void finish(false);
  });
  child.once("close", (code) => {
    void finish(code === 0);
  });
  return id;
}
export async function stopScan(id: string) {
  const meta = await readScan(id);
  const child = children.get(id);
  if (!child || meta.status !== "running")
    throw new Error("Scan is not running");
  meta.status = "stopped";
  await save(meta);
  child.kill("SIGTERM");
  const timer = setTimeout(() => {
    if (children.get(id) === child) child.kill("SIGKILL");
  }, 10000);
  timer.unref();
}
export async function scanDetails(id: string) {
  const meta = await readScan(id);
  let log = "";
  try {
    const handle = await fs.open(path.join(scanPath(id), "scan.log"), "r");
    try {
      const { size } = await handle.stat();
      const data = Buffer.alloc(Math.min(size, 256 * 1024));
      await handle.read(data, 0, data.length, Math.max(0, size - data.length));
      log = data.toString();
    } finally {
      await handle.close();
    }
  } catch {}
  // Use the CLI's emitted output path, but never accept a client-supplied file path.
  try {
    const h = await fs.open(path.join(scanPath(id), "scan.log"), "r");
    try {
      const data = Buffer.alloc(32768);
      const { bytesRead } = await h.read(data, 0, data.length, 0);
      log = data.subarray(0, bytesRead).toString() + "\n" + log;
    } finally {
      await h.close();
    }
  } catch {}
  const match = log
    .replace(/\x1b\[[0-9;]*m/g, "")
    .match(/Output:\s+([^\r\n]+)/);
  let phases: Record<
    string,
    { status: string; started_at?: string; finished_at?: string }
  > = {};
  let results: Record<string, unknown> | null = null;
  if (match) {
    const out = path.resolve(match[1].replace(/\x1b\[[0-9;]*m/g, "").trim());
    const relative = path.relative(path.resolve(OUTPUT_DIR), out);
    if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
      meta.outputDir = out;
      try {
        const manifest = JSON.parse(
          await fs.readFile(path.join(out, "manifest.json"), "utf8"),
        );
        phases = Object.fromEntries(
          Object.entries(manifest.phases || {}).map(([name, state]) => {
            const s = state as {
              status: string;
              started_at?: string;
              finished_at?: string;
            };
            return [
              name,
              {
                status: s.status,
                started_at: s.started_at,
                finished_at: s.finished_at,
              },
            ];
          }),
        );
      } catch {}

      try {
        results = JSON.parse(
          await fs.readFile(path.join(out, "results.json"), "utf8"),
        );
      } catch {}
    }
  }
  if (results && Array.isArray(results.secrets))
    results.secrets = results.secrets.map((s) => ({
      ...s,
      value: "[REDACTED]",
    }));
  log = log
    .replace(/(ghp_|github_pat_)[A-Za-z0-9_]+/g, "[REDACTED]")
    .replace(/(\[SECRET[^\n]*?)(?:→|—|:)\s*[^\n]+/g, "$1 [REDACTED]");
  return { scan: meta, log, results, phases };
}
