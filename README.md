# ReconX 1.2

ReconX orchestrates scoped bug bounty reconnaissance with a Go CLI, a local web dashboard, complete scan checkpoints, and HTML/JSON reports. Scanner matches and secret patterns are candidates that require impact validation. **Port scanning and Nuclei are off by default in both CLI and dashboard.**

## Install

```bash
git clone https://github.com/unsocialz2/reconx.git
cd reconx
bash install.sh
```

The installer handles OS prerequisites, user-local Go/Node when needed, the CLI, pinned tools (including Gitleaks), nuclei templates, dashboard build, offline checks, and Bash/Zsh PATH setup. It does not scan a target. Linux apt/dnf and macOS with Homebrew/Apple command-line tools are supported; Windows is not supported.

Start the dashboard with `~/.local/bin/reconx-web`, or use `./reconx --help` from the repository. For CLI-only setup: `bash install.sh --cli-only`. See [INSTALLATION.md](INSTALLATION.md) for the short guide, options, and log locations.

## CLI

```bash
./reconx -d example.com --scope scope.txt --workers 5
./reconx -d example.com --profile quick
./reconx --doctor
# Explicit opt-in only when the program permits these checks:
./reconx -d example.com --ports --nuclei
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

Cloud probes use HEAD and record reachability, not a claim of bucket exposure. CORS observations are informational candidates; wildcard ACAO plus credentials is not reported as credentialed access. Secret detection runs without automatic credential verification against third-party APIs. The installer supplies Gitleaks; other secret scanners and screenshots are optional.

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

Additional optional binaries are not all installed automatically. Missing/disabled tools and truncation limits appear in coverage. Host identity includes scheme and port. JSON/checkpoints retain all discovered URLs; HTML limits its displayed URL list to 5,000 and discloses that limit.

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

## Version 1.2 workflow

- Recon profiles: `--profile quick|standard|deep|custom`. Quick limits source budgets and disables the slow Amass/Gospider/Hakrawler/ParamSpider adapters. Deep extends total recon budgets. Profiles never enable ports or Nuclei. Explicit INI settings override profile defaults; explicit CLI phase switches override INI settings.
- Read-only preflight: `./reconx --doctor` prints resolved tool paths, availability, worker settings and optional scanner state. It also runs bounded local help/version checks for supported adapters; it does not scan targets or prove provider/API access.
- HTTPx and supported stdin/file crawlers run in batches of 32 inputs. Successful batches are owner-private journal entries in `tasks/`; resume retries incomplete batches and restores successful parser output. `timeout` is the per-batch tool timeout; `total_timeout` bounds the source as a whole (HTTPx defaults to 60 minutes, supported URL sources to 30). This hard source budget still applies under `--no-timeout`.
- WAF checks use bounded per-host jobs (45 seconds maximum per host), a 30-minute total default budget, and preserve completed host results. Untested or failed hosts remain unknown.
- Amass retains partial output; completed domain results are reused on resume. The default collection timeout is 30 minutes. Remote provider limits and tool deadlines can still leave partial coverage: these are reported, never re-labelled as complete.
- `events.jsonl` contains structured phase/tool completion events. Dashboard phase status comes from the manifest instead of guessing it from log text.

### The HTML report is the primary offline reference

The report includes the entire collected dataset, paginated tables, global table search and sorting, complete matching CSV exports, a masked JSON export, asset profiles, HTTP endpoints, ports, networks, JavaScript, parameter mappings, scanner/secret candidates, CORS/cloud/WAF observations, source/phase coverage, batch journals, screenshots and raw evidence links. Known secret values are scrubbed from embedded evidence and metadata. Raw linked files remain private.

Candidates can be marked reviewed, false positive or confirmed, with notes. Those labels are manual local browser annotations, not automated verification. Export JSON to preserve or move your annotations.

Rebuild a saved scan's report without performing new network tests:

```bash
./reconx --report-only ./reconx-output/EXISTING-SCAN
```

Compare it with an earlier saved checkpoint:

```bash
./reconx --report-only ./reconx-output/CURRENT-SCAN --compare-with ./reconx-output/PREVIOUS-SCAN
```

The comparison uses **added** and **unobserved**, not "removed": skipped or partial checks cannot establish that an asset disappeared. Review scope and coverage on both scans.

### HTTP availability in reports

Reports separate HTTP observations from live discovery seeds. `2xx` is **available**, `3xx` a **redirect**, `401/403` **restricted**, other `4xx` a **client error**, `429` **rate limited**, and `5xx` (including `503`) **unavailable**. Missing or invalid status codes are **unknown**. A response can come from an edge proxy/WAF and does not establish origin health.

`alive.txt` and live-seed counts exclude `5xx`, `429`, and unknown statuses. All observations remain in the checkpoint and report; `http_responded.txt`, `http_unavailable.txt`, and `http_rate_limited.txt` preserve separate endpoint lists. Active host discovery uses live seeds, while passive URL archives can still discover historical URLs for unavailable hosts. Independently collected URLs and JS files remain evidence and may still be processed by later phases.

The offline report includes emoji navigation, light/dark themes, HTTP availability charts, clickable counts, live/unavailable/rate-limit filters, and local review notes. To upgrade an existing report without rescanning, rebuild the CLI, then run `reconx --report-only PATH_TO_SCAN_DIRECTORY`. Classification is recomputed from saved status codes; no network recheck is implied.

### Scope CSV, traffic controls and tool preflight

```bash
# Inspect scope without network requests or scan output:
./reconx --scope-csv scope.csv --scope-preview
# Check installed tools using bounded local help/version probes:
./reconx --scope-csv scope.csv --doctor
# Scan the imported targets (ports/Nuclei remain disabled):
./reconx --scope-csv scope.csv --host-rps 2 --http-retries 1
```

HackerOne scope CSV uses `asset_identifier`, optional `asset_type`, and **`eligible_for_submission`**. `eligible_for_bounty=false` does not exclude a VDP asset. Normalized Bugcrowd target-group CSV uses `target` (or `url`), optional `category`, and **`in_scope`**. Eligibility must be explicit; unknown or conflicting values stop the import. Arbitrary submission CSV exports are not scope exports. Unsupported mobile/source/hardware rows are listed in the preview, not converted to web targets. Program instructions are retained for manual review; free text does not enable scanners or override structured exclusions.

Imported bare hosts match exactly; `*.example.com` matches subdomains and **does not include the apex**. IPs/CIDRs retain network boundaries. Root HTTP URLs retain exact scheme/host/port. Path/query-specific URLs stop the import because encrypted subprocess tunnels cannot enforce path restrictions. Imported origins cannot be combined with raw port scanning. Exclusions win; existing text/INI scope can further narrow the CSV. Legacy `--scope` domain-tree semantics are unchanged. With no explicit `-d`/`--ip`, seeds are derived from the imported assets; explicit targets select a subset and are checked against the CSV. Wildcard base names are discovery seeds only. Review scope before running; DNS enumeration can discover excluded names, which are filtered from HTTP target lists.

Built-in scoped HTTP clients share a per-host limiter across modules, schemes and ports. Defaults: `--host-rps 2`, `--http-retries 1`, `--http-max-backoff 30`. Only replayable GET/HEAD requests retry on 429/503. Numeric/date `Retry-After` is honored; a delay beyond the automatic retry budget returns the original response and defers further requests to that host. Cancellation and client/phase deadlines still apply. Plain HTTP through the scan proxy uses these controls too. HTTPS subprocess traffic remains encrypted: native rate flags are applied per process where supported, **not a universal per-host request/response governor**. Native tools use an integer rate (minimum 1); sub-1 rates apply only to built-in HTTP. Tool-specific configured rates can lower this cap, not raise it. Providers and tools that do not use the scoped HTTP transport retain their own rate behavior. Conservative limits can increase scan duration; partial coverage is still retained when phase budgets expire.

INI equivalents live under `[runtime]`: `host_rps`, `http_retries`, `http_max_backoff`. `--doctor` checks listed adapter flags plus effective custom flags and reports `compatible`, `incompatible`, `check_failed` or `not_checked`. Missing optional tools remain skipped. Enabled, available tools with incompatible flags or failed probes produce a nonzero exit. Disabled ports/Nuclei binaries are never probed. Each probe has a two-second hard limit with a 15-second overall preflight budget; no target URLs are supplied. Help compatibility is not a provider/API access test.
