# ReconX — Automated Bug Bounty Recon Framework

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝
```

> Give it a domain. Walk away. Come back to findings.

---

## Architecture

```
Input (domains / IPs / ASNs / scope)
        │
        ▼
┌─────────────────────────────────────────────┐
│              Pipeline Engine                │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Phase 1  │ │ Phase 2  │ │  Phase 3    │ │
│  │ Subdomain│→│  Alive   │→│  Port Scan  │ │
│  │   Enum   │ │  Check   │ │   (naabu)   │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Phase 4  │ │ Phase 5  │ │  Phase 6    │ │
│  │   URL    │→│    JS    │→│    Vuln     │ │
│  │Discovery │ │ Secrets  │ │   Scanning  │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
└─────────────────────────────────────────────┘
        │
        ▼
  ┌──────────────────┐
  │  Central Store   │  (thread-safe in-memory)
  │  subdomains      │
  │  live hosts      │
  │  ports           │
  │  URLs            │
  │  JS files        │
  │  findings        │
  │  secrets         │
  └──────────────────┘
        │
        ▼
  Output: colored terminal + HTML report + raw TXT files
```

## Installation

```bash
git clone https://github.com/yourorg/reconx
cd reconx
bash install.sh
```

The installer:
1. Installs all Go-based tools (subfinder, httpx, nuclei, katana, etc.)
2. Downloads nuclei templates
3. Downloads fresh DNS resolvers
4. Builds the `reconx` binary and puts it in PATH

## Quick Start

```bash
# Single domain, full auto
reconx -d example.com

# Multiple domains
reconx -d example.com -d api.example.com -d dev.example.com

# With scope enforcement
reconx -d example.com --scope scope.txt

# With IP ranges and ASN
reconx -d example.com --ip 10.20.0.0/16 --asn AS12345

# Skip slow phases for quick recon
reconx -d example.com --skip-ports --skip-vuln

# Full run with API tokens
reconx -d example.com \
  --github-token ghp_xxxx \
  --chaos-key your_chaos_key \
  --output ./my-scans \
  --verbose
```

## Scope File Format

Create a `scope.txt`:
```
# Lines starting with + are IN scope
# Lines starting with - are OUT OF scope
# Bare lines are treated as in-scope

+*.example.com
+api.example.com
+example.com
-staging.example.com
-dev.example.com
-internal.example.com
```

Then run:
```bash
reconx -d example.com --scope scope.txt
```

## Config File (`reconx.yaml`)

Generate a default config:
```bash
reconx -init
```

Load a config file at runtime (new — was previously write-only):
```bash
reconx -d example.com --config reconx.yaml
```

Config uses INI-style sections. CLI flags override config values, which
override defaults. Example:

```ini
[output]
output_dir       = ./reconx-output
html_report      = true
verbose          = false

[phases]
subdomain_enum = true
port_scan      = true
vuln_scan      = true

[tokens]
github          = ""
chaos           = ""
shodan          = ""
virustotal      = ""
securitytrails  = ""

[paths]
# Optional — override the auto-detected DNS brute wordlist and resolvers
# wordlist  = /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
# resolvers = /home/user/.config/reconx/resolvers.txt

# Per-tool config — flags use JSON array syntax. Inline # comments OK.
[tool.subfinder]
enabled = true
flags   = ["-all", "-recursive"]
timeout = 600   # 10 min

[tool.nuclei]
enabled = true
flags   = ["-severity", "critical,high,medium"]
timeout = 3600  # 60 min

[scope]
in_scope     = ["*.example.com"]
out_of_scope = ["staging.example.com"]
```

## CLI Flags (new in this version)

| Flag | Purpose |
|------|---------|
| `--config PATH` | Load a `reconx.yaml` config file |
| `--wordlist PATH` | DNS brute wordlist (overrides SecLists auto-detection) |
| `--resolvers PATH` | DNS resolvers file (overrides reconx auto-detection) |
| `--shodan-key KEY` | Shodan API key (subdomains + port enrichment) |
| `--vt-key KEY` | VirusTotal API key (free tier works) |
| `--securitytrails-key KEY` | SecurityTrails API key (50 free queries/month) |

All existing flags (`-d`, `--scope`, `--header`, `--no-timeout`, `--resume`,
`--skip-*`, etc.) work unchanged.

## Subdomain Sources (max coverage)

The subdomain phase now runs **25+ sources in parallel** and deduplicates
results. Sources are skipped automatically when their binary or token is
missing — the rest still run.

**Binary-backed:**
- subfinder, assetfinder, amass, findomain, chaos (PD), github-subdomains,
  puredns (brute), dnsx (brute), **crobat** (new), **shuffledns** (new, massdns-backed)

**Free HTTP APIs (no token, no binary):**
- crt.sh (with 3x retry on 502/504)
- Google Certificate Transparency
- certspotter
- hackertarget
- **Anubis (jldc.me)** — new
- **RapidDNS** — new
- **AlienVault OTX passive DNS** — new (was URL-only before)
- **ThreatCrowd** — new
- **urlscan.io** — new
- **DNSDumpster** — new
- **Sonar (omnisint.io)** — new

**Token-gated HTTP APIs:**
- VirusTotal (`--vt-key`)
- Shodan (`--shodan-key`)
- SecurityTrails (`--securitytrails-key`)
- Censys (`CENSYS_API_ID:SECRET` token format)
- Chaos (`--chaos-key`)
- github-subdomains (`--github-token`)

**Local permutation (new — pure Go, no binary):**
- Generates candidate names from known prefixes × common suffixes
  (api-dev, admin-staging, etc.) and resolves them via the system resolver.
- Finds "hidden" subdomains that no passive source has indexed.

## Phase Details

| Phase | Tools Used | Output Files |
|-------|-----------|--------------|
| **Subdomain Enum** | subfinder, assetfinder, amass, findomain, chaos, github-subdomains, puredns, dnsx, crobat, shuffledns, crt.sh, Google-CT, certspotter, hackertarget, Anubis, RapidDNS, OTX, ThreatCrowd, urlscan, DNSDumpster, Sonar, VirusTotal, Shodan, SecurityTrails, Censys, **DNS permutation** | `subdomains.txt` |
| **Alive Check** | httpx (with curl fallback) | `alive.txt` |
| **Port Scan** | naabu | `ports.txt` (new — saved for resume + downstream tools) |
| **URL Discovery** | waybackurls, gau, gauplus, katana, hakrawler, gospider, paramspider, OTX | `urls.txt`, `urls_js.txt`, `urls_admin.txt`, etc. |
| **JS Analysis** | mantra, jsecret, trufflehog, subjs | `js_files.txt`, `secrets.txt` (new — saved for resume) |
| **Vuln Scan** | nuclei (exposures, CVEs, misconfigs, takeovers, default-logins, tech-detect) | `findings.txt` (new — saved for resume) |
| **Report** | built-in | `report.html`, `results.json` |

## Output Structure

```
reconx-output/
└── example.com-1714000000/
    ├── report.html          ← full interactive HTML report
    ├── results.json         ← machine-readable JSON
    ├── subdomains.txt       ← all unique subdomains
    ├── alive.txt            ← live hosts
    ├── urls.txt             ← all discovered URLs
    ├── urls_js.txt          ← JS files only
    ├── urls_admin.txt       ← admin panel URLs
    ├── urls_login.txt       ← login/auth URLs
    ├── urls_params.txt      ← parameterized URLs
    ├── urls_api.txt         ← API endpoints
    ├── urls_sensitive.txt   ← .env, .bak, .sql etc.
    ├── urls_idor.txt        ← numeric ID URLs
    ├── js_files.txt         ← JS file URLs
    ├── ports.txt            ← open ports (new — for resume + ffuf, etc.)
    ├── secrets.txt          ← secrets discovered (new — for resume)
    ├── findings.txt         ← nuclei findings (new — for resume)
    └── nuclei_targets.txt   ← targets fed to nuclei
```

## Environment Variables

```bash
export GITHUB_TOKEN=ghp_xxxx                # github-subdomains + trufflehog-github
export PDCP_API_KEY=your_key                # chaos dataset
export SHODAN_API_KEY=xxxx                  # shodan subdomain + port enrichment
export VT_API_KEY=xxxx                      # VirusTotal (free tier OK)
export SECURITYTRAILS_API_KEY=xxxx          # SecurityTrails (50 free reqs/month)
# Censys: pass via --config as censys = "API_ID:API_SECRET"
```

## Bugs Fixed (in this revision)

This revision fixes every bug found during a full code review. Highlights:

**Build-breaking:**
- `pkg/runner/runner.go`: removed unused `"os"` import that prevented compilation
  on a fresh checkout.

**Silent data loss:**
- `internal/pipeline/pipeline.go` `loadExistingResults`: alive.txt was loaded as
  `Domain: "https://sub.example.com"` and `Meta["url"]: "https://https://..."`.
  The double-prefixed URL broke URL discovery on `--resume`. Fixed to parse the
  URL properly with a new `stripURLToHost` helper.
- `internal/modules/subdomain/subdomain.go` `runASNMap`: asnmap results were
  fetched but never added to the store. ASN-derived IP ranges were silently
  discarded. Fixed to add results via the scope filter.
- `internal/modules/alive/alive.go` `parseHTTPXLine`: `host.IP` was set from
  httpx's `"host"` JSON field, which is the input hostname — not an IP. Fixed
  to use `"a"` (first A record) / `"ip"` / `"IP"` only.

**Misleading / wrong logs:**
- `internal/modules/urls/urls.go` `runWayback`: logged `ToolTimeout(5*time.Minute)`
  but no timeout was ever passed to `runner.Run`. Now sets an explicit 30-minute
  timeout (configurable via `[tool.waybackurls] timeout`).

**Duplicate flags:**
- `internal/modules/portscan/portscan.go`: passed `-rate 2000` then appended
  `tcfg.Flags` (which also had `-rate 2000`). naabu accepted the duplicate but
  the redundant flag could confuse users. Fixed to only use `tcfg.Flags`.

**Hardcoded paths bypassing config:**
- `runDnsxBrute`, `runPuredns`, `runGithubSubs`, `runShuffleDNS` all used
  hardcoded binary names instead of `tcfg.Path`. Fixed to honor `[tool.X].path`
  config overrides.
- `findWordlist` / `findResolvers` ignored user-supplied paths. Fixed to
  respect `--wordlist` / `--resolvers` flags and `[paths]` config section.

**Logic bugs:**
- `internal/modules/subdomain/subdomain.go` `runAmass`: wrapped the context
  with `WithTimeout` AND passed `WithTimeout` to `runner.Run` — double
  cancellation. Removed the redundant context wrap.
- `internal/pipeline/pipeline.go` JS/Vuln phases: leaked goroutines because
  the `<-ctx.Done()` watcher had no exit path after `jsCancel()`. Fixed with
  a `stopWait` channel.
- `internal/pipeline/pipeline.go` Phase 3 (port scan) never checked resume
  mode — every `--resume` re-scanned ports. Now skips if `ports.txt` exists.
- Same issue for JS phase (now skips if `js_files.txt` exists).

**Missing config loading:**
- `reconx -init` wrote a config file but no code path ever read it back. Added
  `config.Load()` (INI-style parser with inline comments + JSON-array flags)
  and a `--config` flag.

**Resume fragility:**
- Resume mode now also restores `ports.txt`, `secrets.txt`, `findings.txt`
  into the store so the JSON/HTML report includes them on resume.

**Public-suffix bug:**
- `internal/modules/urls/urls.go` `extractRootDomains`: treated `bbc.co.uk` as
  root `co.uk`. Added a multi-part TLD list (>80 entries) so `bbc.co.uk` →
  `bbc.co.uk`, `shop.company.com.au` → `company.com.au`, etc.

**crt.sh reliability:**
- `runCrtSh` gave up on the first 502/504. crt.sh is one of the best free
  CT sources but is frequently overloaded. Added 3 retries with backoff.

## Adding Custom Modules

The pipeline is modular. To add a new phase:

1. Create `internal/modules/yourmodule/yourmodule.go`
2. Implement `func (m *Module) Run(ctx context.Context) error`
3. Register it in `internal/pipeline/pipeline.go`

## Legal Notice

This tool is for authorized security testing only. Only run against
targets you have explicit written permission to test. The authors
assume no liability for misuse.

## License

MIT
