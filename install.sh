#!/usr/bin/env bash
# User-local, reproducible installer. Never removes system packages or edits profiles.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="${RECONX_GO:-$(command -v go || true)}"
if [[ -z "$GO_BIN" ]]; then echo 'Go 1.22+ is required. Install Go, then rerun this script.' >&2; exit 1; fi
cd "$ROOT_DIR"
INSTALL_DIR="${RECONX_BIN_DIR:-${GOBIN:-$HOME/.local/bin}}"
mkdir -p "$INSTALL_DIR"
export GOBIN="$INSTALL_DIR"
# Build the product first: a broken checkout must fail before optional dependencies change.
"$GO_BIN" build -trimpath -o "$INSTALL_DIR/reconx" "$ROOT_DIR/cmd/reconx"
printf 'Built %s/reconx\n' "$INSTALL_DIR"
if [[ "${1:-}" == "--binary-only" ]]; then exit 0; fi
# Known tagged versions; Go verifies module checksums through its checksum database.
# naabu needs libpcap development headers on Linux; failures are surfaced below.
TOOLS=(
 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0'
 'github.com/projectdiscovery/httpx/cmd/httpx@v1.7.1'
 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10'
 'github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.5'
 'github.com/projectdiscovery/katana/cmd/katana@v1.1.2'
 'github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2'
 'github.com/lc/gau/v2/cmd/gau@v2.2.4'
)
FAILED=()
for tool in "${TOOLS[@]}"; do
 printf 'Installing %s\n' "$tool"
 if ! "$GO_BIN" install "$tool"; then FAILED+=("$tool"); fi
done
if (( ${#FAILED[@]} )); then printf 'Failed tools:\n%s\n' "${FAILED[*]}" >&2; exit 1; fi
# Template updates are an explicit choice: they change scan behavior.
printf 'Installed tools in %s. Add that directory to PATH.\n' "$INSTALL_DIR"
printf 'Before a vulnerability scan, install/update templates explicitly: nuclei -update-templates\n'
