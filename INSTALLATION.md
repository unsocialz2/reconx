# ReconX installation and checks

Follow the sections in order. Sections 1–8 install and verify the project without scanning a public target. Tool installation and nuclei template updates download dependencies; the smoke test itself makes no target requests.

## 1. Requirements

| Component | Requirement |
|---|---|
| Operating system | Linux or macOS; Windows is not supported by the POSIX subprocess runner |
| Go | 1.22+ for ReconX itself; 1.25.3 is the version used in CI and is a suitable starting point for installing the pinned tools |
| Node.js | 22+ and npm, only if using the web dashboard |
| Build tools | Git, Make, and a C compiler for race tests/native dependencies |
| Port scanner dependency | libpcap development headers for naabu |

Run installation as your normal user. The ReconX installer writes to your user directory; only OS package installation needs `sudo`.

### Ubuntu / Debian / Kali

```bash
sudo apt update
sudo apt install -y git make build-essential libpcap-dev curl ca-certificates pkg-config
```

Install a suitable Go version using the [official Go installation guide](https://go.dev/doc/install). Install Node.js 22+ using the [official Node.js download instructions](https://nodejs.org/en/download). Distro packages can provide different versions, so check the versions before proceeding.

### Fedora

```bash
sudo dnf install -y git make gcc gcc-c++ libpcap-devel curl ca-certificates pkgconf-pkg-config golang nodejs npm
```

Check the installed Go and Node versions below. If they are too old, use the official installation guides linked above. Node/npm are unnecessary for CLI-only use.

### macOS

Install Apple's command-line build tools if they are not already present:

```bash
xcode-select --install
```

With Homebrew already installed:

```bash
brew install git go node@22 libpcap
export PATH="$(brew --prefix node@22)/bin:$PATH"
```

### Confirm prerequisites

```bash
git --version
make --version
go version
cc --version
```

For the dashboard, also run:

```bash
node --version
npm --version
```

**Pass:** commands exist; Go meets the requirement; Node is v22 or newer. Do not continue with a missing or incompatible toolchain.

## 2. Clone the project

```bash
git clone https://github.com/unsocialz2/reconx.git
cd reconx
```

Confirm the source directories are present:

```bash
ls cmd/reconx/main.go
ls web/src/components/reconx/main-layout.tsx
ls web/src/app/api/scans/route.ts
```

**Pass:** all three paths exist. These were absent in the initial repository because of overly broad ignore rules.

If you already cloned the repository, update from its root with:

```bash
git pull --ff-only
```

If this reports local changes or divergence, resolve those changes before updating; do not discard your work to force the update.

## 3. Build and install the CLI

First, build the repository-local binary. The dashboard uses this binary by default.

```bash
make build
./reconx --version
./reconx --help
```

**Pass:** `make build` succeeds, the version is printed, and the help lists the CLI options. Help/version commands do not scan a target.

Install ReconX in your user binary directory:

```bash
bash install.sh --binary-only
export PATH="$HOME/.local/bin:$PATH"
hash -r
command -v reconx
reconx --version
```

The default installation path is `~/.local/bin/reconx`. An existing `GOBIN` or `RECONX_BIN_DIR` overrides that path; add the actual directory printed by the installer to `PATH`.

To keep the default PATH change after opening a new terminal, add this line to `~/.bashrc` for Bash or `~/.zshrc` for Zsh:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

The installer does not edit shell profiles automatically.

## 4. Install the core reconnaissance tools

From the repository root:

```bash
bash install.sh
export PATH="$HOME/.local/bin:$PATH"
hash -r
```

The script installs the following pinned tools:

| Tool | Pinned version | Role |
|---|---|---|
| subfinder | v2.9.0 | Passive subdomain collection |
| httpx | v1.7.1 | HTTP endpoint probing |
| nuclei | v3.4.10 | Template-based HTTP checks |
| naabu | v2.3.5 | Port discovery |
| katana | v1.1.2 | Crawling and URL discovery |
| dnsx | v1.2.2 | DNS enumeration |
| gau | v2.2.4 | Archived URL collection |

**Pass:** the installer exits successfully and does not list failed tools. It builds ReconX before installing the optional dependencies, reports installation errors, and does not remove system packages.

The project also has adapters for additional binaries that this installer does **not** install. In particular, JS secret detection requires a supported scanner such as Gitleaks, TruffleHog, or SecretFinder. Screenshots require gowitness plus a working browser. A successful core installation does not mean every optional phase is available. Missing tools are recorded in scan coverage.

## 5. Check tool paths and help output

```bash
for tool in reconx subfinder httpx nuclei naabu katana dnsx gau; do
  printf '\n%s: ' "$tool"
  command -v "$tool" || true
done
```

Then inspect each tool's help without supplying targets:

```bash
subfinder -h
httpx -h
nuclei -h
naabu -h
katana -h
dnsx -h
gau --help
```

**Pass:** every installed binary resolves to the intended location and prints its own help.

`httpx` must be the **ProjectDiscovery reconnaissance tool**, not the Python HTTP client. Its help should contain reconnaissance options such as `-status-code` and `-tech-detect`.

ReconX also checks standard Go/system binary locations when resolving tools. If multiple versions exist, set an explicit path in your configuration rather than relying on PATH alone:

```ini
[tool.httpx]
enabled = true
path = /home/YOUR_USER/.local/bin/httpx
```

Replace `YOUR_USER` with your username. Configuration paths do not expand `~` or `$HOME`; use the actual absolute path.

## 6. Install nuclei templates

```bash
nuclei -update-templates
```

This downloads templates; it does not scan a target. Record the downloaded template version if you need reproducible results.

Check that the categories ReconX uses exist in the template directory reported by nuclei:

```text
http/takeovers
http/misconfiguration
http/exposures
http/default-logins
http/cves
```

If using a custom template directory, configure the nuclei installation appropriately and verify it can resolve these category paths. New templates and older pinned binaries can have compatibility differences; successful downloading alone does not prove every template can execute.

## 7. Run the offline project checks

From the repository root:

```bash
make test
make lint
bash -n install.sh
```

**Pass:** Go tests pass with the race detector, vet reports no issues, and the installer has no Bash syntax errors.

The normal test target uses `-short`, local HTTP servers, and fake tool binaries. It skips the opt-in live subfinder test. Leave `RECONX_LIVE_TESTS` unset for ordinary verification.

### Smoke-test the actual CLI without scanning

This command disables **every active/discovery phase**. `example.com` is only a label for the output directory.

```bash
reconx_check_dir=$(mktemp -d)
./reconx -d example.com \
  --output "$reconx_check_dir" \
  --workers 1 \
  --skip-subs \
  --skip-alive \
  --skip-ports \
  --skip-urls \
  --skip-js \
  --skip-vuln \
  --skip-cloud \
  --skip-cors
ls "$reconx_check_dir"/example.com-*/
```

**Pass:** the command exits successfully and the scan directory contains `manifest.json`, `checkpoint.json`, `results.json`, `report.html`, and `reconx.log`. Open `report.html`: counts should be zero and phases should be skipped.

This verifies CLI wiring, output creation, checkpointing, and reporting. It does not verify a real scan or external scanner compatibility. `doctor` and `--dry-run` have not been implemented; this smoke test is not a substitute for those proposed features.

## 8. Install and check the dashboard

Keep the repository-local binary from `make build`, then:

```bash
cd web
npm ci
npm run lint
npm run typecheck
npm run build
npm test
```

**Pass:** lint/type checks and the production build succeed, and all four API integration tests pass. These tests use a fake CLI and temporary local files.

### Development server

```bash
npm run dev
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). In another terminal:

```bash
curl -fsS http://127.0.0.1:3000/api/scans
curl -fsS http://127.0.0.1:3000/api/settings
```

**Pass:** the homepage loads, history/settings endpoints return JSON, and saving settings produces a visible confirmation. The dashboard's default Go binary path is `<repository>/reconx`; a user-local installation alone does not create that repository-local binary.

### Production server

Stop the development server with Ctrl+C before reusing port 3000:

```bash
npm run build
npm start
```

Run one dashboard process. Remote exposure requires HTTPS and `RECONX_WEB_TOKEN`; ordinary local installation needs neither. Starting a scan in the UI performs real network testing, so do that only after setup verification and scope configuration.

## 9. Prepare your first authorized scan

Return to the repository root:

```bash
cd ..
./reconx --init
```

This writes `reconx.ini` in the current directory; it replaces an existing file of that name, so preserve an existing configuration first.

Edit the configuration and create `scope.txt` with the actual allowed/excluded assets. Start with a small authorized asset, low concurrency, and unnecessary phases disabled. Domain include rules also include subdomains; scope is host-based, not URL-path-based.

For a first single-domain HTTP/URL run, the following is an **active scan**. Replace the placeholder with your authorized domain and prepare `scope.txt` before running it:

```bash
./reconx -d YOUR_AUTHORIZED_DOMAIN \
  --config reconx.ini \
  --scope scope.txt \
  --workers 3 \
  --skip-subs \
  --skip-ports \
  --skip-vuln \
  --skip-js \
  --skip-cloud \
  --skip-cors
```

`workers` controls concurrency; it is not a requests-per-second limit. Configure supported tools' `rate_limit` values to match the program's rules. A first successful scan must be reviewed for skipped/partial phases, not just finding counts.

## Troubleshooting

| Problem | Check / fix |
|---|---|
| `go: command not found` | Install Go, reopen the terminal, and check `go version`. A custom executable can be selected with `RECONX_GO=/absolute/path/to/go bash install.sh`. |
| Tool installation says a newer Go version is required | Upgrade Go or use Go's automatic toolchain selection if permitted. Do not assume the Go version required by ReconX is sufficient for all dependencies. |
| `pcap.h` missing when installing naabu | Install `libpcap-dev` on Debian-family systems, `libpcap-devel` on Fedora, or `libpcap` with Homebrew; rerun the installer. |
| `reconx: command not found` | Add the actual installer output directory to PATH and run `hash -r`. `./reconx` works from the repository after `make build`. |
| Wrong `httpx` or other tool version runs | Inspect `command -v`, existing Go/system copies, and per-tool absolute `path` overrides. |
| Race tests require CGO/compiler | Install a C compiler and run with `CGO_ENABLED=1`; avoid overriding CGO to zero for race tests. |
| Dashboard says it cannot start a scan | Run `make build` at the repository root, or set `RECONX_BINARY` to the actual absolute executable path. |
| Port 3000 is already in use | Stop your previous server or use `npm run dev -- --port 3001`, then open port 3001. |
| Dashboard API returns 403 | Use the loopback URL. Remote hosts require `RECONX_WEB_TOKEN`; cross-origin write requests are rejected. |
| JS or screenshot phase is skipped | Install its optional scanner/browser dependencies, or disable the phase deliberately. Core installation does not supply them all. |
| Resume rejects a directory | It requires a versioned manifest/checkpoint and matching target, scope, and tool configuration. Legacy TXT-only scans cannot be resumed reliably. |
| Scan has zero findings | Check `manifest.json`, coverage, and `reconx.log` for failures or skipped tools. Zero findings do not prove full coverage. |

## Official references

- [Go installation](https://go.dev/doc/install)
- [Go toolchain selection](https://go.dev/doc/toolchain)
- [Node.js downloads and installation](https://nodejs.org/en/download)
- [Naabu prerequisites](https://github.com/projectdiscovery/naabu#prerequisite)
- [Nuclei documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Project configuration and scope behavior](README.md)
