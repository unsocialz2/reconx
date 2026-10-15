// Offline integration tests against the actual production server, with a fake CLI.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import net from "node:net";
let root, server, base;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
before(async () => {
  root = await mkdtemp(path.join(tmpdir(), "reconx-web-test-"));
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  base = `http://127.0.0.1:${port}`;
  const binary = path.join(root, "fake-reconx");
  await writeFile(
    binary,
    `#!/usr/bin/env node
const fs=require('node:fs'),path=require('node:path');
const args=process.argv.slice(2);const out=args[args.indexOf('--output')+1];const dir=path.join(out,path.basename(process.cwd()));fs.mkdirSync(dir,{recursive:true});
fs.writeFileSync(path.join(process.cwd(),'args.json'),JSON.stringify(args));
console.log('Output: '+dir);
fs.writeFileSync(path.join(dir,'results.json'),JSON.stringify({scan_id:'fixture',secrets:[{type:'fixture',value:'private-test-secret'}],urls:['https://example.com/'],coverage:['fixture only']}));
if(args.includes('slow.example.com')) setInterval(()=>console.log('working'),1000);else setTimeout(()=>process.exit(0),100);
`,
    { mode: 0o700 },
  );
  server = spawn(process.execPath, [".next/standalone/server.js"], {
    env: {
      ...process.env,
      HOSTNAME: "127.0.0.1",
      PORT: String(port),
      RECONX_BINARY: binary,
      RECONX_PROJECT_ROOT: root,
      RECONX_SCANS_DIR: path.join(root, "scans"),
      RECONX_OUTPUT_DIR: path.join(root, "output"),
      NEXT_TELEMETRY_DISABLED: "1",
    },
    stdio: "pipe",
  });
  let logs = "";
  server.stdout.on("data", (v) => (logs += v));
  server.stderr.on("data", (v) => (logs += v));
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(base + "/api/scans")).ok) return;
    } catch {}
    await delay(100);
  }
  throw new Error("Server failed to start: " + logs);
});
after(async () => {
  server?.kill("SIGTERM");
  if (server && server.exitCode === null)
    await new Promise((resolve) => server.once("exit", resolve));
  if (root) await rm(root, { recursive: true, force: true });
});
async function post(url, body, headers = {}) {
  return fetch(base + url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
test("settings are validated, persisted and private", async () => {
  assert.equal((await post("/api/settings", { workers: 0 })).status, 400);
  assert.equal(
    (await post("/api/settings", { workers: 2, githubToken: "fixture" }))
      .status,
    200,
  );
  assert.equal(
    (await (await fetch(base + "/api/settings")).json()).settings.workers,
    2,
  );
  assert.equal(
    (await stat(path.join(root, "scans", "reconx-gui-settings.json"))).mode &
      0o777,
    0o600,
  );
});
test("cross-origin write and malformed scan input are rejected", async () => {
  assert.equal(
    (
      await post(
        "/api/settings",
        { workers: 2 },
        { Origin: "https://attacker.invalid" },
      )
    ).status,
    403,
  );
  assert.equal(
    (await post("/api/scans", { domains: ["example.com; touch /tmp/nope"] }))
      .status,
    400,
  );
  assert.equal(
    (await post("/api/scans", { domains: ["example.com"], workers: 0 })).status,
    400,
  );
  assert.equal((await fetch(base + "/api/scans/not-a-valid-id")).status, 404);
});
test("scan launches, reaches completion and returns redacted results", async () => {
  const response = await post("/api/scans", {
    domains: ["example.com"],
    skipCloud: true,
    tokens: { github: "fixture" },
  });
  assert.equal(response.status, 201);
  const { scanId } = await response.json();
  let details;
  for (let i = 0; i < 100; i++) {
    details = await (await fetch(base + "/api/scans/" + scanId)).json();
    if (details.scan.status !== "running") break;
    await delay(50);
  }
  assert.equal(details.scan.status, "completed");
  assert.equal(details.results.secrets[0].value, "[REDACTED]");
  assert.equal(details.results.urls.length, 1);
  assert.equal(
    (await (await fetch(base + "/api/scans")).json()).scans.some(
      (s) => s.id === scanId,
    ),
    true,
  );
  assert.equal(JSON.stringify(details.scan).includes("fixture"), false);
});
test("stop terminates an owned running scan", async () => {
  const { scanId } = await (
    await post("/api/scans", { domains: ["slow.example.com"] })
  ).json();
  await delay(100);
  assert.equal(
    (await fetch(base + "/api/scans/" + scanId, { method: "DELETE" })).status,
    200,
  );
  await delay(200);
  assert.equal(
    (await (await fetch(base + "/api/scans/" + scanId)).json()).scan.status,
    "stopped",
  );
});

test("port and nuclei scans require explicit opt in", async () => {
  for (const enabled of [false, true]) {
    const response = await post("/api/scans", {
      domains: ["example.com"],
      enablePorts: enabled,
      enableNuclei: enabled,
    });
    assert.equal(response.status, 201);
    const { scanId } = await response.json();
    let args;
    for (let i = 0; i < 100; i++) {
      try {
        args = JSON.parse(
          await readFile(path.join(root, "scans", scanId, "args.json"), "utf8"),
        );
        break;
      } catch {
        await delay(20);
      }
    }
    assert.ok(args.includes(enabled ? "--ports" : "--skip-ports"));
    assert.ok(args.includes(enabled ? "--nuclei" : "--skip-vuln"));
    await delay(200);
  }
});
