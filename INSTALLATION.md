# Install ReconX

## Already cloned the repository?

From the `reconx` directory:

```bash
git pull --ff-only
bash install.sh
```

## First installation

```bash
git clone https://github.com/unsocialz2/reconx.git
cd reconx
bash install.sh
```

Use your normal user account. On Linux, the installer asks for sudo access to install OS prerequisites. It supports apt-based systems (Ubuntu/Debian/Kali) and Fedora/dnf. On macOS, Homebrew and Apple's command-line tools must be available.

## What the script does

- Installs OS build dependencies; libpcap headers are included only with optional scanners.
- Uses a suitable existing Go/Node installation or downloads a user-local runtime with SHA-256 verification.
- Builds ReconX both in the repository and in `~/.local/bin`.
- Installs pinned subfinder, httpx, katana, dnsx, gau, and Gitleaks into `~/go/bin` by default. Naabu/Nuclei are optional with `--with-scanners`.
- Checks tool help output. Nuclei templates are downloaded only with `--with-scanners`.
- Installs a checksum-verified SecLists DNS wordlist (5,000 names); preserves an existing custom wordlist.
- Installs and builds the dashboard.
- Runs offline Go, installer, and dashboard checks, plus a CLI smoke test with every scan phase disabled.
- Configures PATH in your Bash/Zsh startup file and creates a dashboard launcher.

Installation downloads dependencies and templates. It does **not** scan a target. Screenshots and additional optional scanners remain separate installs.

## Use it

CLI, from the repository:

```bash
./reconx --help
```

Dashboard:

```bash
~/.local/bin/reconx-web
```

Open **http://127.0.0.1:3000**. Keep the repository in place: the launcher uses its production build. A new terminal will pick up the PATH setup; to update the current terminal, run the `source` command printed by the installer.

## Optional shortcuts

| Command | Behavior |
|---|---|
| `bash install.sh --cli-only` | Install CLI/tools and run checks; skip the dashboard and Node |
| `bash install.sh --binary-only` | Build/install only ReconX; requires existing Go 1.22+ |
| `bash install.sh --skip-system-deps` | Skip apt/dnf/Homebrew when prerequisites are already installed |
| `bash install.sh --skip-checks` | Skip test suites; still run the CLI smoke test |
| `bash install.sh --no-profile` | Keep shell startup files unchanged |
| `bash install.sh --help` | Show all options |

Repeated runs do not duplicate the shell PATH entry. Existing files in the repository are retained, while dependencies/build outputs may be refreshed. Failed installation exits nonzero and identifies the failed step.

## If installation fails

Read the error and the log:

```bash
cat ~/.config/reconx/install.log
```

Fix the reported dependency/download problem and rerun `bash install.sh`. The installer saves runtime/build information in `~/.config/reconx/install-receipt.txt`.

### Old binary or `--report-only` not recognized

From the cloned repository, refresh just the CLI (existing Go required):

```bash
git pull --ff-only
bash install.sh --binary-only
./reconx --version
```

The installer builds and checks a fresh temporary executable before replacing each installed copy, restores executable permissions, and keeps the previous binaries if compilation fails. An existing directory named `reconx` at either binary destination must be moved aside first; its contents are never overwritten.

Then, from the directory containing your scan's `reconx-output` folder, use the rebuilt executable's absolute path. For example, if cloned into `~/Downloads/reconx`:

```bash
~/Downloads/reconx/reconx --report-only reconx-output/aegeanair.com-2298197030
```

This regenerates reports from the saved checkpoint without scanning. Run it as your normal user. `/home/...` is an absolute path; `./home/...` instead searches inside the current directory.

For custom locations, set `RECONX_BIN_DIR`, `RECONX_TOOLS_DIR`, `RECONX_SETUP_DIR`, or `RECONX_RUNTIME_DIR`. `RECONX_GO` selects an existing Go executable; `RECONX_GO_VERSION` selects a release when Go needs downloading. The final output prints the actual installed paths.

## Reading scan results

- `[REQUEST]` shows module arguments; `[CMD]` shows the resolved binary and arguments actually executed, including configured workers, rate and scope proxy. Headers/tokens are redacted.
- A phase marked **partial**, cancelled, or timed out has incomplete coverage. Zero findings is not a clean security assessment.
- Nuclei logs progress, request/error counts, and a category budget. `[nuclei] timeout = 3600` gives each category one hour; set it explicitly in `reconx.ini` if another budget is needed. The category budget remains a hard limit under `--no-timeout`. Large endpoint lists and broad template sets may need several hours.
- JS downloads prioritize discoveries from live pages, then a deterministic archive list. The 2,500-file cap and failures (HTTP status, request errors, HTML responses, oversized files) appear in coverage notes.
- Secret scanners report **candidates**. Review the original file and detector match before treating one as a usable credential.
- Missing optional API tokens, provider `403`/`429` responses and unused optional binaries appear as coverage limitations. `429` is not retried immediately.
- DNS brute force needs a wordlist. `dnsx` can use system DNS; puredns/shuffledns additionally need massdns and a resolvers file. The latter are optional and do not suppress the dnsx fallback when their prerequisites are missing.

After updating, rebuild with `bash install.sh --cli-only` on a VPS. Scan manifests protect resume compatibility: if scope/tool settings changed, start a new output directory instead of reusing the old scan.

## ParamSpider progress and runtime limits

ParamSpider starts when a core URL source first returns useful URLs (or when all core sources finish). It prioritizes parameter-bearing URLs, hosts with discovered URLs, API hosts and application/login/admin hosts. At most 100 additional low-signal hosts are tried by default. It does not expand hosts to their parent domains.

Add this section to `reconx.ini` to change the defaults (all times are seconds):

```ini
[tool.paramspider]
enabled = true
timeout = 300
total_timeout = 2700
late_timeout = 120
fallback_hosts = 100
```

`timeout` applies per host. `total_timeout` caps the entire ParamSpider run at 45 minutes, including queued jobs, even under `--no-timeout`. Once core URL discovery finishes, `late_timeout` allows at most two additional minutes before stopping enrichment and continuing to JS. The first budget reached wins. Set `fallback_hosts = 0` to process only hosts with a useful signal; disable ParamSpider with `enabled = false`.

Progress shows `850/2437 hosts | 1240 URLs`. Processed hosts count finished attempts; failed or timed-out attempts are disclosed. URLs stream into the results store, so cancellation preserves them. A budget stop, failed host or host-selection cap marks coverage **partial** and does not cancel the parent pipeline.

URL source summaries are printed at phase end and saved in `data/url_discovery_summary.json`, including terminal status, counts and frozen start/finish times. A quiet live subprocess is shown as **running/silent**; lack of output alone no longer implies a stuck process.

URL discovery uses `--workers` for local queues and runner slots. GAU/GAUPlus use one thread per host subprocess to avoid multiplying the worker limit; Katana crawls one input at a time with bounded request concurrency, and Gospider uses one site worker with bounded request concurrency.

## Optional scanners and upgrade

Port scanning and Nuclei are disabled by default, including in all profiles. Their installation is optional too:

```bash
bash install.sh --cli-only --with-scanners
```

Only enable execution when the target program permits it: `--ports` and `--nuclei` (or explicit `[phases] port_scan = true` / `vuln_scan = true`). Existing INI files with those values set to true are explicit opt-ins; change them to false for recon-only operation. Existing installed scanners are not uninstalled.

After upgrading, `./reconx --version` should print `v1.2.0`. A binary built before the Mantra worker fix can still emit `-threads`; rebuild or rerun the installer. Version 1.2 also migrates legacy Mantra/Naabu thread aliases in custom flags.

Use `./reconx --doctor` for a local tool/settings inventory and bounded help/version compatibility checks. Use `--scope-csv scope.csv --scope-preview` to inspect imported scope without any network requests. For a new HTML report from an old run, use `--report-only PATH`; this does not scan again.
