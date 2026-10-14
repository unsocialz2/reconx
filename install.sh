#!/usr/bin/env bash
# One-command setup. No target scans are performed during installation.
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${RECONX_SETUP_DIR:-$HOME/.config/reconx}"
RUNTIME_DIR="${RECONX_RUNTIME_DIR:-$HOME/.local/share/reconx}"
INSTALL_DIR="${RECONX_BIN_DIR:-$HOME/.local/bin}"
TOOLS_DIR="${RECONX_TOOLS_DIR:-${GOBIN:-$HOME/go/bin}}"
SKIP_SYSTEM=0 SKIP_TOOLS=0 SKIP_WEB=0 SKIP_CHECKS=0 NO_PROFILE=0 BINARY_ONLY=0

usage() {
  cat <<'HELP'
Usage: bash install.sh [options]

Default: system prerequisites, Go/Node if needed, ReconX, core tools,
         nuclei templates, dashboard, offline checks, and shell PATH setup.

  --cli-only          Skip Node.js and the dashboard
  --binary-only       Build/install ReconX only (Go must already be available)
  --skip-system-deps  Do not run apt/dnf/Homebrew
  --skip-tools        Skip external tools and template downloads
  --skip-checks       Skip test suites (always run the CLI smoke test)
  --no-profile        Do not edit shell startup files
  -h, --help          Show this help

Overrides: RECONX_GO, RECONX_GO_VERSION, RECONX_BIN_DIR,
           RECONX_TOOLS_DIR, RECONX_SETUP_DIR, RECONX_RUNTIME_DIR.
HELP
}
for arg in "$@"; do
  case "$arg" in
    --cli-only) SKIP_WEB=1 ;;
    --binary-only) BINARY_ONLY=1; SKIP_SYSTEM=1; SKIP_TOOLS=1; SKIP_WEB=1; SKIP_CHECKS=1; NO_PROFILE=1 ;;
    --skip-system-deps) SKIP_SYSTEM=1 ;;
    --skip-tools) SKIP_TOOLS=1 ;;
    --skip-checks) SKIP_CHECKS=1 ;;
    --no-profile) NO_PROFILE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
case "$OS" in Linux|Darwin) ;; *) printf 'Unsupported OS: %s (Linux/macOS required)\n' "$OS" >&2; exit 1 ;; esac
case "$(uname -m)" in
  x86_64|amd64) GO_ARCH=amd64; NODE_ARCH=x64 ;;
  aarch64|arm64) GO_ARCH=arm64; NODE_ARCH=arm64 ;;
  *) printf 'Unsupported architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$STATE_DIR" "$RUNTIME_DIR" "$INSTALL_DIR" "$TOOLS_DIR"
LOG_FILE="$STATE_DIR/install.log"
exec > >(tee -a "$LOG_FILE") 2>&1
trap 'code=$?; printf "\nInstallation failed at line %s (exit %s). Log: %s\n" "$LINENO" "$code" "$LOG_FILE"; exit "$code"' ERR
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
step() { printf '\n== %s ==\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { printf 'Missing prerequisite: %s\n' "$1" >&2; return 1; }; }
fetch() { curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 --silent --show-error "$1" -o "$2"; }
verify_sha() {
  local actual
  if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$1" | awk '{print $1}')";
  else actual="$(shasum -a 256 "$1" | awk '{print $1}')"; fi
  [[ "$actual" == "$2" ]] || { printf 'Checksum mismatch: %s\n' "$1" >&2; return 1; }
}

step 'System prerequisites'
if (( ! SKIP_SYSTEM )); then
  if [[ "$OS" == Linux ]]; then
    PRIVILEGE=()
    if (( EUID != 0 )); then need sudo; sudo -v; PRIVILEGE=(sudo); fi
    if command -v apt-get >/dev/null 2>&1; then
      "${PRIVILEGE[@]}" apt-get update
      packages=(git make build-essential curl ca-certificates pkg-config python3 xz-utils)
      (( SKIP_TOOLS )) || packages+=(libpcap-dev)
      "${PRIVILEGE[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
      packages=(git make gcc gcc-c++ curl ca-certificates pkgconf-pkg-config python3 xz)
      (( SKIP_TOOLS )) || packages+=(libpcap-devel)
      "${PRIVILEGE[@]}" dnf install -y "${packages[@]}"
    else
      printf 'No apt/dnf found. Install Git, Make, C compiler, curl, Python 3, xz and libpcap headers; rerun with --skip-system-deps.\n' >&2
      exit 1
    fi
  else
    if ! xcode-select -p >/dev/null 2>&1; then
      printf 'Apple command-line tools are required. Starting their installer; rerun ReconX setup once it finishes.\n'
      xcode-select --install
      exit 1
    fi
    need brew
    packages=(git make curl python xz)
    (( SKIP_TOOLS )) || packages+=(libpcap)
    brew install "${packages[@]}"
  fi
else
  printf 'System package installation skipped.\n'
fi
need make
need tar

step 'Go toolchain'
GO_BIN="${RECONX_GO:-$(command -v go || true)}"
# A managed runtime from an earlier run is preferred over an outdated system Go.
if [[ -z "${RECONX_GO:-}" && -x "$RUNTIME_DIR/go/bin/go" ]]; then GO_BIN="$RUNTIME_DIR/go/bin/go"; fi
if [[ -n "${RECONX_GO:-}" ]]; then [[ -x "$GO_BIN" ]] || { printf 'RECONX_GO is not executable: %s\n' "$GO_BIN" >&2; exit 1; }; fi
GO_OK=0
if [[ -n "$GO_BIN" ]]; then
  version="$("$GO_BIN" version | awk '{print $3}' | sed 's/^go//')"
  major="${version%%.*}"; rest="${version#*.}"; minor="${rest%%.*}"
  minimum=25; (( BINARY_ONLY || SKIP_TOOLS )) && minimum=22
  if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] && (( major > 1 || (major == 1 && minor >= minimum) )); then GO_OK=1; fi
fi
if (( ! GO_OK )); then
  if (( BINARY_ONLY )); then printf 'Binary-only installation requires an existing Go 1.22+ toolchain.\n' >&2; exit 1; fi
  need curl; need python3
  fetch 'https://go.dev/dl/?mode=json&include=all' "$WORK_DIR/go-downloads.json"
  go_os=linux; [[ "$OS" != Darwin ]] || go_os=darwin
  # Official metadata supplies both the selected archive and its SHA-256.
  python3 - "$WORK_DIR/go-downloads.json" "$go_os" "$GO_ARCH" "${RECONX_GO_VERSION:-}" > "$WORK_DIR/go-selection" <<'PY'
import json,re,sys
releases=json.load(open(sys.argv[1]));os_name,arch,wanted=sys.argv[2:]
if wanted and not re.fullmatch(r'(?:go)?\d+\.\d+(?:\.\d+)?',wanted):raise SystemExit('Invalid RECONX_GO_VERSION')
for release in releases:
    if not release.get('stable'):continue
    if wanted and release['version'] != 'go'+(wanted[2:] if wanted.startswith('go') else wanted):continue
    for item in release['files']:
        if item['os']==os_name and item['arch']==arch and item['kind']=='archive':
            print(item['filename']);print(item['sha256']);raise SystemExit(0)
raise SystemExit('No matching official Go archive')
PY
  go_archive="$(sed -n '1p' "$WORK_DIR/go-selection")"
  go_sha="$(sed -n '2p' "$WORK_DIR/go-selection")"
  fetch "https://go.dev/dl/$go_archive" "$WORK_DIR/$go_archive"
  verify_sha "$WORK_DIR/$go_archive" "$go_sha"
  mkdir -p "$WORK_DIR/go-unpacked"
  tar -xzf "$WORK_DIR/$go_archive" -C "$WORK_DIR/go-unpacked"
  rm -rf "$RUNTIME_DIR/go.previous"
  if [[ -d "$RUNTIME_DIR/go" ]]; then mv "$RUNTIME_DIR/go" "$RUNTIME_DIR/go.previous"; fi
  mv "$WORK_DIR/go-unpacked/go" "$RUNTIME_DIR/go"
  GO_BIN="$RUNTIME_DIR/go/bin/go"
fi
export PATH="$(dirname "$GO_BIN"):$TOOLS_DIR:$INSTALL_DIR:$PATH"
"$GO_BIN" version

step 'Build and install ReconX'
cd "$ROOT_DIR"
"$GO_BIN" build -trimpath -o "$ROOT_DIR/reconx" ./cmd/reconx
# Keep the repository-local binary for the dashboard and install a user-facing copy.
if [[ "$INSTALL_DIR/reconx" != "$ROOT_DIR/reconx" ]]; then cp "$ROOT_DIR/reconx" "$INSTALL_DIR/reconx"; fi
"$ROOT_DIR/reconx" --version
"$ROOT_DIR/reconx" --help > "$WORK_DIR/reconx-help.txt" 2>&1

if (( ! SKIP_TOOLS )); then
  step 'Pinned reconnaissance tools'
  export GOBIN="$TOOLS_DIR"
  TOOLS=(
    'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0'
    'github.com/projectdiscovery/httpx/cmd/httpx@v1.7.1'
    'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10'
    'github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.5'
    'github.com/projectdiscovery/katana/cmd/katana@v1.1.2'
    'github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2'
    'github.com/lc/gau/v2/cmd/gau@v2.2.4'
    'github.com/zricethezav/gitleaks/v8@v8.24.2'
  )
  failed=()
  for tool in "${TOOLS[@]}"; do
    printf 'Installing %s\n' "$tool"
    if ! "$GO_BIN" install "$tool"; then failed+=("$tool"); fi
  done
  if (( ${#failed[@]} )); then printf 'Failed tools: %s\n' "${failed[*]}" >&2; exit 1; fi
  for tool in subfinder httpx nuclei naabu katana dnsx; do "$TOOLS_DIR/$tool" -h > "$WORK_DIR/$tool-help.txt" 2>&1; done
  "$TOOLS_DIR/gitleaks" --help > "$WORK_DIR/gitleaks-help.txt" 2>&1
  "$TOOLS_DIR/gau" --help > "$WORK_DIR/gau-help.txt" 2>&1
  step 'DNS brute-force wordlist'
  # Immutable SecLists revision + SHA-256; never overwrite a custom wordlist.
  mkdir -p "$STATE_DIR/wordlists"
  dns_wordlist="$STATE_DIR/wordlists/subdomains.txt"
  if [[ ! -s "$dns_wordlist" ]]; then
    fetch 'https://raw.githubusercontent.com/danielmiessler/SecLists/d85fec3ba57153e52ac71f32cbf86e6fbb5e1585/Discovery/DNS/subdomains-top1million-5000.txt' "$WORK_DIR/subdomains.txt"
    verify_sha "$WORK_DIR/subdomains.txt" 'e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19'
    cp "$WORK_DIR/subdomains.txt" "$dns_wordlist"
  fi
  printf 'DNS wordlist: %s (dnsx uses the system resolver unless --resolvers is supplied).\n' "$dns_wordlist"
  step 'Nuclei templates (download only)'
  "$TOOLS_DIR/nuclei" -update-templates
  printf 'Core tools (including Gitleaks) and help checks passed. Screenshots and additional scanners are optional.\n'
fi

if (( ! SKIP_WEB )); then
  step 'Node.js and npm'
  NODE_OK=0
  if [[ -x "$RUNTIME_DIR/node/bin/node" ]]; then export PATH="$RUNTIME_DIR/node/bin:$PATH"; fi
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    node_major="$(node -p 'process.versions.node.split(".")[0]')"
    (( node_major >= 22 )) && NODE_OK=1
  fi
  if (( ! NODE_OK )); then
    need curl; need python3
    node_os=linux; [[ "$OS" != Darwin ]] || node_os=darwin
    fetch 'https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt' "$WORK_DIR/node-checksums"
    python3 - "$WORK_DIR/node-checksums" "$node_os" "$NODE_ARCH" > "$WORK_DIR/node-selection" <<'PY'
import re,sys
pattern=re.compile(r'node-v22\.\d+\.\d+-'+re.escape(sys.argv[2])+'-'+re.escape(sys.argv[3])+r'\.tar\.gz$')
for line in open(sys.argv[1]):
    fields=line.split()
    if len(fields)==2 and pattern.fullmatch(fields[1]):
        print(fields[1]);print(fields[0]);raise SystemExit(0)
raise SystemExit('No matching official Node 22 archive')
PY
    node_archive="$(sed -n '1p' "$WORK_DIR/node-selection")"
    node_sha="$(sed -n '2p' "$WORK_DIR/node-selection")"
    node_version="${node_archive#node-}"; node_version="${node_version%%-*}"
    fetch "https://nodejs.org/dist/$node_version/$node_archive" "$WORK_DIR/$node_archive"
    verify_sha "$WORK_DIR/$node_archive" "$node_sha"
    mkdir -p "$WORK_DIR/node-unpacked"
    tar -xzf "$WORK_DIR/$node_archive" -C "$WORK_DIR/node-unpacked"
    rm -rf "$RUNTIME_DIR/node.previous"
    if [[ -d "$RUNTIME_DIR/node" ]]; then mv "$RUNTIME_DIR/node" "$RUNTIME_DIR/node.previous"; fi
    mv "$WORK_DIR/node-unpacked/${node_archive%.tar.gz}" "$RUNTIME_DIR/node"
    export PATH="$RUNTIME_DIR/node/bin:$PATH"
  fi
  node --version; npm --version
  step 'Dashboard dependencies and production build'
  export NEXT_TELEMETRY_DISABLED=1
  (cd "$ROOT_DIR/web"; npm ci; npm run build)
fi

if (( ! SKIP_CHECKS )); then
  step 'Offline verification'
  need cc
  "$GO_BIN" test -short -race ./cmd/... ./internal/... ./pkg/...
  "$GO_BIN" vet ./cmd/... ./internal/... ./pkg/...
  bash "$ROOT_DIR/tests/install_test.sh"
  if (( ! SKIP_WEB )); then (cd "$ROOT_DIR/web"; npm run lint; npm run typecheck; npm test); fi
fi

step 'CLI smoke test (all scan phases disabled)'
"$ROOT_DIR/reconx" -d example.com --output "$WORK_DIR/smoke" --workers 1 \
  --skip-subs --skip-alive --skip-ports --skip-urls --skip-js --skip-vuln --skip-cloud --skip-cors \
  > "$WORK_DIR/smoke.log" 2>&1
for file in manifest.json checkpoint.json results.json report.html reconx.log; do
  matches=("$WORK_DIR"/smoke/example.com-*/"$file")
  [[ -f "${matches[0]}" ]] || { printf 'Smoke test missing %s\n' "$file" >&2; exit 1; }
done
printf 'Smoke test passed. No target was scanned.\n'

step 'Shell environment and launchers'
ENV_FILE="$STATE_DIR/env.sh"
printf 'export PATH=%q:%q:%q:%q:"$PATH"\n' "$(dirname "$GO_BIN")" "$RUNTIME_DIR/node/bin" "$TOOLS_DIR" "$INSTALL_DIR" > "$ENV_FILE"
if (( ! NO_PROFILE )); then
  profile="$HOME/.bashrc"
  case "${SHELL:-}" in */zsh) profile="$HOME/.zshrc" ;; esac
  profile="${RECONX_PROFILE_FILE:-$profile}"
  # Readable marker and exact line matching make repeated runs idempotent.
  source_line="$(printf '. %q' "$ENV_FILE")"
  touch "$profile"
  if ! grep -Fqx "$source_line" "$profile"; then printf '\n# ReconX environment\n%s\n' "$source_line" >> "$profile"; fi
  printf 'PATH configured in %s.\n' "$profile"
fi
if (( ! SKIP_WEB )); then
  LAUNCHER="$INSTALL_DIR/reconx-web"
  {
    printf '#!/usr/bin/env bash\nset -e\n'
    printf '. %q\ncd %q\n' "$ENV_FILE" "$ROOT_DIR/web"
    printf 'exec npm start\n'
  } > "$LAUNCHER"
  chmod 700 "$LAUNCHER"
fi
{
  printf 'Installed: %s\n' "$(date -u +%FT%TZ)"
  printf 'Repository: %s\nCLI: %s/reconx\nTools: %s\n' "$ROOT_DIR" "$INSTALL_DIR" "$TOOLS_DIR"
  "$GO_BIN" version
  (( SKIP_WEB )) || node --version
  printf 'Tools skipped: %s\nDashboard skipped: %s\nTest suites skipped: %s\n' "$SKIP_TOOLS" "$SKIP_WEB" "$SKIP_CHECKS"
} > "$STATE_DIR/install-receipt.txt"

step 'Setup complete'
printf 'CLI: %s/reconx --help\n' "$INSTALL_DIR"
if (( ! SKIP_WEB )); then
  printf 'Dashboard: %s/reconx-web\nOpen: http://127.0.0.1:3000\n' "$INSTALL_DIR"
fi
printf 'For commands in this terminal: source %q\n' "$ENV_FILE"
printf 'Log: %s\n' "$LOG_FILE"
