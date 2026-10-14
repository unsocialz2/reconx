# ReconX

ReconX orchestrates scoped bug bounty reconnaissance with a Go CLI, a local web dashboard, complete scan checkpoints, and HTML/JSON reports. Scanner matches and secret patterns are candidates that require impact validation.

## Build and install

For step-by-step setup, dependency checks, an offline CLI smoke test, and troubleshooting, see [INSTALLATION.md](INSTALLATION.md).

Requirements: Go 1.22+ for ReconX; Node 22+ for the dashboard. Linux and macOS are supported. The subprocess runner uses POSIX process groups; Windows is not supported.

```bash
git clone https://github.com/unsocialz2/reconx.git
cd reconx
make build
./reconx --help
```

To install only ReconX into `~/.local/bin`:

```bash
bash install.sh --binary-only
```

`bash install.sh` additionally installs pinned core tools through Go's checksum-verified module downloads. Some tools require a newer Go toolchain and naabu requires libpcap headers. The installer reports failures, does not remove system packages, and does not edit shell profiles. Set `RECONX_GO` or `RECONX_BIN_DIR` to override Go or the installation directory. Update nuclei templates explicitly with `nuclei -update-templates`; record the template version when comparing runs.

## CLI

```bash
./reconx -d example.com --scope scope.txt --workers 5
./reconx -d example.com --skip-ports --skip-vuln
./reconx --init
./reconx -d example.com --config reconx.ini
./reconx --resume ./reconx-output/example.com-SCANID
```

Include/exclude scope file:

```text
+*.example.com
-staging.example.com
```

Deny rules take precedence. Domain rules include their subdomains; CIDR rules match IP addresses. Scope is host-based: URL paths are not authorization boundaries. Userinfo URLs are rejected. A discovered hostname, certificate SAN or bucket keyword is not proof of authorization.

Active HTTP tool adapters use a local scope-checking HTTP/CONNECT proxy. Built-in HTTP requests and JS downloads validate scope before requests and at redirects. httpx and nuclei redirect following is disabled. Passive intelligence services are queried outside target scope as data providers; DNS/port tools operate on supplied target assets. Arbitrary user-supplied binaries/templates are not sandboxed: keep their capabilities within the program policy.

Cloud checks are opt-in and require exact asset URLs:

```bash
./reconx -d example.com --skip-cloud=false \
  --cloud-asset https://example-assets.s3.amazonaws.com/
```

Cloud probes use HEAD and record reachability, not a claim of bucket exposure. CORS observations are informational candidates; wildcard ACAO plus credentials is not reported as credentialed access. Secret detection runs without automatic credential verification against third-party APIs.

API tokens can be supplied using `GITHUB_TOKEN`, `PDCP_API_KEY`, `SHODAN_API_KEY`, `VT_API_KEY`, and `SECURITYTRAILS_API_KEY`. Prefer environment variables to CLI tokens. Scan outputs and settings are private; raw evidence/checkpoints may contain credentials and must not be shared unredacted.

## Dashboard

Build the Go CLI first, then:

```bash
cd web
npm ci
npm run dev
```

Open http://127.0.0.1:3000. Configure domains and include/exclude scope, launch scans, monitor logs, stop scans, browse history, and review redacted results. Production: `npm run build && npm start`.

Paths can be overridden with `RECONX_PROJECT_ROOT`, `RECONX_BINARY`, `RECONX_SCANS_DIR`, and `RECONX_OUTPUT_DIR`. Defaults work when running from `web/`. The dashboard binds to loopback. If deliberately exposing it remotely, require HTTPS and set `RECONX_WEB_TOKEN`; HTTP Basic authentication accepts any username and this token as the password. Cross-origin writes are rejected. Run a single dashboard process; scans from a previous process are marked failed rather than trusting stale PIDs.

## Configuration

Configuration is INI, not YAML. CLI values override configuration, which overrides defaults.

```ini
[runtime]
workers = 5
header = "X-Bug-Bounty: researcher"

[output]
output_dir = ./reconx-output
html_report = true
json_report = true
save_raw = true

[phases]
cloud_enum = false
params = false
dir_fuzz = false

[tool.nuclei]
enabled = true
timeout = 1800
rate_limit = 10
flags = ["-severity", "critical,high,medium"]

[scope]
in_scope = ["*.example.com"]
out_of_scope = ["staging.example.com"]
```

`enabled`, binary `path`, flags and timeout are enforced centrally for subprocesses. `workers` bounds concurrent subprocesses and supported tool-internal parallelism; built-in probes use the same worker count. `rate_limit` is supported for httpx, nuclei, naabu, katana, ffuf and feroxbuster. Unsupported per-tool rate limits are rejected rather than silently ignored. Directory/parameter discovery is opt-in.

## Pipeline and sources

1. Subdomains: subfinder, assetfinder, findomain, amass, chaos, github-subdomains; puredns/shuffledns/dnsx fallback; DNS permutations; crt.sh, certspotter, hackertarget, Anubis, RapidDNS, subdomain.center, AlienVault OTX, urlscan; token-gated VirusTotal, Shodan, SecurityTrails and Censys.
2. HTTP probing: httpx with a scoped Go fallback; optional WAF/TLS/takeover enrichment.
3. Ports: naabu, followed by HTTP probing of common discovered web ports.
4. URLs: waybackurls, gau, gauplus, katana, hakrawler, gospider, paramspider and OTX, merged and scope-filtered.
5. Optional directory/parameter discovery, explicit cloud checks, and CORS candidates.
6. JS discovery/downloads and candidate secret detection with installed scanners.
7. Nuclei HTTP categories, raw JSONL evidence, JSON and HTML reports.

Optional binaries are not all installed automatically. Missing/disabled tools and truncation limits appear in coverage. Host identity includes scheme and port. JSON/checkpoints retain all discovered URLs; HTML limits its displayed URL list to 5,000 and discloses that limit.

## Checkpoints and results

Each scan has a unique directory containing `manifest.json` and private `checkpoint.json`, plus enabled reports and raw evidence. The versioned checkpoint preserves hosts, ports, URLs, JS files, sources, findings/evidence, secrets, WAF, directories, cloud, CORS and parameter results. Writes are atomic.

Phases are `running`, `completed`, `partial`, or `skipped`. Completed zero-result phases are valid checkpoints. Partial and skipped phases retry on resume. Resume requires the same target, scope and tool configuration; scope is reapplied during restoration. Legacy TXT-only scans do not have trustworthy completion metadata and must be started again. `--save-raw=false` removes intermediate/raw outputs after reporting; private checkpoints remain necessary for resume. `--json-report=false` disables the public JSON export, not the private checkpoint.

## Verification

```bash
make build
make test
make lint
cd web
npm run lint
npm run typecheck
npm run build
npm test
```

Tests are offline by default and use local HTTP servers/fake binaries. The old live subfinder check only runs with `RECONX_LIVE_TESTS=1` and without `-short`. CI builds the actual CLI and production dashboard, runs Go race tests/vet, and exercises the web API lifecycle with a fake CLI. These checks do not prove compatibility with every optional external tool version or establish vulnerability impact.

## License

MIT — see [LICENSE](LICENSE). Use only within an authorized assessment scope.
