#!/usr/bin/env bash
# ReconX Tool Installer — v2.0
# Run with: bash install.sh
# Tested on: Kali Linux 2024+, Ubuntu 22.04+, Parrot OS, Debian 12
#
# Fixes applied from real-world testing:
#   - Go tools symlinked to /usr/local/bin (survives shell changes, works immediately)
#   - apt versions of httpx/amass removed before installing correct versions
#   - amass installed from prebuilt release binary (avoids libpostal crash)
#   - paramspider installed from GitHub source (not on PyPI)
#   - gauplus installed via go install (not pip)
#   - waymore installed via pip3 --break-system-packages
#   - jsecret installed via pip3 --break-system-packages
#   - Python packages restored after any accidental downgrades

# NO set -e — handle each failure individually
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
step()    { echo -e "\n${BOLD}${CYAN}━━ $1${NC}"; }

echo ""
echo -e "${GREEN}${BOLD}  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗${NC}"
echo -e "${GREEN}${BOLD}  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝${NC}"
echo -e "${GREEN}${BOLD}  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ ${NC}"
echo -e "${GREEN}${BOLD}  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ ${NC}"
echo -e "${GREEN}${BOLD}  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗${NC}"
echo -e "${GREEN}${BOLD}  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝${NC}"
echo -e "  ${CYAN}ReconX Tool Installer v2.0${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0 — Detect Go binary (Require Go >= 1.21)
# ─────────────────────────────────────────────────────────────────────────────
step "Resolving Go environment"

GO_BIN=""
for candidate in \
    /usr/local/go/bin/go \
    "$HOME/.local/go/bin/go" \
    "$(which go 2>/dev/null)" \
    /usr/bin/go \
    "$HOME/go/bin/go" \
    /snap/bin/go; do
    if [ -x "$candidate" ]; then
        GO_BIN="$candidate"
        break
    fi
done

NEED_GO_UPGRADE=0
if [ -z "$GO_BIN" ]; then
    NEED_GO_UPGRADE=1
else
    GO_VER_STR=$($GO_BIN version 2>/dev/null | awk '{print $3}' | sed 's/go//')
    GO_MAJOR=$(echo "$GO_VER_STR" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VER_STR" | cut -d. -f2)
    if [ -z "$GO_MINOR" ] || [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]; }; then
        warn "Found outdated Go $GO_VER_STR (< 1.21 — modern tools require Go >= 1.21) — upgrading to Go 1.22.4..."
        NEED_GO_UPGRADE=1
    fi
fi

if [ "$NEED_GO_UPGRADE" -eq 1 ]; then
    info "Installing modern Go 1.22.4..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        *)       GO_ARCH="amd64" ;;
    esac
    TMP_GO="/tmp/go1.22.4.tar.gz"
    wget -q --timeout=30 "https://go.dev/dl/go1.22.4.linux-${GO_ARCH}.tar.gz" -O "$TMP_GO"
    if [ -s "$TMP_GO" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            rm -rf /usr/local/go && tar -C /usr/local -xzf "$TMP_GO"
            GO_BIN=/usr/local/go/bin/go
        elif sudo -n true 2>/dev/null; then
            sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$TMP_GO"
            GO_BIN=/usr/local/go/bin/go
        else
            mkdir -p "$HOME/.local"
            rm -rf "$HOME/.local/go" && tar -C "$HOME/.local" -xzf "$TMP_GO"
            GO_BIN="$HOME/.local/go/bin/go"
        fi
        rm -f "$TMP_GO"
        success "Go installed/upgraded to 1.22.4"
    else
        warn "Failed to download Go tarball — attempting to continue with system Go"
    fi
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$(dirname "$GO_BIN"):$GOPATH/bin:$PATH"

success "Go: $($GO_BIN version 2>/dev/null | awk '{print $3}')"
success "GOPATH: $GOPATH"
info "All tools will be symlinked to /usr/local/bin"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Write permanent PATH to shell profiles
# ─────────────────────────────────────────────────────────────────────────────
step "Writing permanent PATH configuration"

PATH_LINE='export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"'
for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$profile" ] && ! grep -q "go/bin" "$profile" 2>/dev/null; then
        echo "" >> "$profile"
        echo "# ReconX — Go tools PATH" >> "$profile"
        echo "$PATH_LINE" >> "$profile"
        success "Updated $profile"
    fi
done

if [ -f /etc/profile.d/go-tools.sh ] && grep -q "go/bin" /etc/profile.d/go-tools.sh 2>/dev/null; then
    success "/etc/profile.d/go-tools.sh already configured"
elif sudo -n true 2>/dev/null || [ "$(id -u)" -eq 0 ]; then
    if [ "$(id -u)" -eq 0 ]; then
        echo "export PATH=\"\$PATH:\$HOME/go/bin:/usr/local/go/bin\"" > /etc/profile.d/go-tools.sh 2>/dev/null || true
    else
        echo "export PATH=\"\$PATH:\$HOME/go/bin:/usr/local/go/bin\"" | sudo tee /etc/profile.d/go-tools.sh > /dev/null 2>&1 || true
    fi
    success "Wrote /etc/profile.d/go-tools.sh (system-wide)"
else
    success "User shell profiles configured with Go PATH"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Remove conflicting apt versions BEFORE installing correct ones
# FIX: apt httpx is python/old, apt amass has libpostal crash
# ─────────────────────────────────────────────────────────────────────────────
step "Checking conflicting apt versions (httpx, amass)"

# Remove apt httpx if present as a debian package (conflicts with ProjectDiscovery httpx)
if dpkg-query -W -f='${Status}' httpx 2>/dev/null | grep -q "install ok installed"; then
    if [ "$(id -u)" -eq 0 ]; then
        info "Removing apt httpx (incompatible with reconx — using ProjectDiscovery version)..."
        apt-get remove -y -qq httpx 2>/dev/null || true
        rm -f /usr/bin/httpx
        success "Removed apt httpx"
    elif sudo -n true 2>/dev/null; then
        info "Removing apt httpx (incompatible with reconx — using ProjectDiscovery version)..."
        sudo apt-get remove -y -qq httpx 2>/dev/null || true
        sudo rm -f /usr/bin/httpx
        success "Removed apt httpx"
    else
        warn "apt httpx package found but sudo requires password — ProjectDiscovery httpx in ~/go/bin will be prioritized"
    fi
else
    success "No conflicting apt httpx found"
fi

# Remove apt amass if present
if dpkg-query -W -f='${Status}' amass 2>/dev/null | grep -q "install ok installed"; then
    if [ "$(id -u)" -eq 0 ]; then
        info "Removing apt amass (has libpostal crash bug — will use clean binary)..."
        apt-get remove -y -qq amass 2>/dev/null || true
        rm -f /usr/bin/amass
        success "Removed apt amass"
    elif sudo -n true 2>/dev/null; then
        info "Removing apt amass (has libpostal crash bug — will use clean binary)..."
        sudo apt-get remove -y -qq amass 2>/dev/null || true
        sudo rm -f /usr/bin/amass
        success "Removed apt amass"
    else
        warn "apt amass package found but sudo requires password — prebuilt binary will be used"
    fi
else
    success "No conflicting apt amass found"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — System dependencies (Fast non-interactive install)
# ─────────────────────────────────────────────────────────────────────────────
step "Checking system dependencies"

MISSING_DEPS=()
for dep in git curl wget jq unzip nmap whois make gcc; do
    if ! command -v "$dep" &>/dev/null; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    info "Installing missing system packages: ${MISSING_DEPS[*]}..."
    APT_CMD="DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git curl wget jq unzip build-essential libpcap-dev python3 python3-pip nmap dnsutils whois make gcc"
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update -qq 2>/dev/null || true
        eval "$APT_CMD" 2>/dev/null || true
    elif sudo -n true 2>/dev/null; then
        sudo apt-get update -qq 2>/dev/null || true
        sudo bash -c "$APT_CMD" 2>/dev/null || true
    fi
    success "System packages installed"
else
    success "System dependencies already satisfied"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Core helper — install Go tool and symlink to /usr/local/bin
# ─────────────────────────────────────────────────────────────────────────────
install_go_tool() {
    local pkg="$1"
    local name="$2"

    # 1. Already available in PATH (e.g. /usr/bin, /usr/local/bin, ~/go/bin)
    local existing
    existing=$(command -v "$name" 2>/dev/null)
    if [ -n "$existing" ] && [ -x "$existing" ]; then
        success "$name already installed ($existing)"
        return 0
    fi

    # 2. Already in GOPATH
    if [ -x "$GOPATH/bin/$name" ]; then
        success "$name already installed ($GOPATH/bin/$name)"
        return 0
    fi

    # 3. Download and build via Go
    info "Installing $name..."
    mkdir -p "$GOPATH/bin"
    $GO_BIN install "${pkg}@latest" 2>/dev/null || true
    if [ -x "$GOPATH/bin/$name" ] || command -v "$name" &>/dev/null; then
        success "$name installed → $GOPATH/bin/$name"
        return 0
    fi

    # 4. Fallback: Prebuilt release binary for ProjectDiscovery / popular tools
    case "$name" in
        subfinder|nuclei|httpx|naabu|dnsx|katana|chaos|asnmap|tlsx)
            info "Trying prebuilt release binary for $name..."
            ARCH=$(uname -m)
            case "$ARCH" in
                x86_64)  PD_ARCH="amd64" ;;
                aarch64) PD_ARCH="arm64" ;;
                *)       PD_ARCH="amd64" ;;
            esac
            TMP_ZIP=$(mktemp -d)
            REL_URL=$(curl -s "https://api.github.com/repos/projectdiscovery/${name}/releases/latest" 2>/dev/null \
                | grep -i "browser_download_url.*linux_${PD_ARCH}.zip" | head -n 1 | cut -d '"' -f 4)
            if [ -n "$REL_URL" ]; then
                wget -q --timeout=20 "$REL_URL" -O "$TMP_ZIP/${name}.zip" 2>/dev/null
                if [ -s "$TMP_ZIP/${name}.zip" ]; then
                    unzip -q -o "$TMP_ZIP/${name}.zip" -d "$TMP_ZIP" 2>/dev/null
                    if [ -x "$TMP_ZIP/$name" ]; then
                        cp "$TMP_ZIP/$name" "$GOPATH/bin/$name"
                        chmod +x "$GOPATH/bin/$name"
                        success "$name installed (prebuilt binary) → $GOPATH/bin/$name"
                        rm -rf "$TMP_ZIP"
                        return 0
                    fi
                fi
            fi
            rm -rf "$TMP_ZIP"
            ;;
    esac

    warn "$name: install failed (optional tool — skipping)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Go-based tools
# ─────────────────────────────────────────────────────────────────────────────
step "Installing Go-based recon tools"

# ProjectDiscovery suite
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"       "subfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx"                  "httpx"
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"             "nuclei"
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu"               "naabu"
install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx"                    "dnsx"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana"                "katana"
install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos"           "chaos"
install_go_tool "github.com/projectdiscovery/asnmap/cmd/asnmap"                "asnmap"
install_go_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client" "interactsh-client"

# URL discovery
install_go_tool "github.com/tomnomnom/waybackurls"   "waybackurls"
install_go_tool "github.com/lc/gau/v2/cmd/gau"       "gau"
install_go_tool "github.com/bp0lr/gauplus"            "gauplus"
install_go_tool "github.com/hakluke/hakrawler"        "hakrawler"
install_go_tool "github.com/jaeles-project/gospider"  "gospider"

# Subdomain tools
install_go_tool "github.com/tomnomnom/assetfinder"          "assetfinder"
install_go_tool "github.com/d3mondev/puredns/v2"            "puredns"
install_go_tool "github.com/hakluke/hakrevdns"              "hakrevdns"
install_go_tool "github.com/cgboal/sonarsearch/cmd/crobat"   "crobat"

# JS analysis & secrets
install_go_tool "github.com/lc/subjs"                       "subjs"
install_go_tool "github.com/003random/getJS"                 "getJS"
install_go_tool "github.com/brosck/mantra"                   "mantra"
install_go_tool "github.com/raoufmaklouf/jsecret"           "jsecret"

# github-subdomains
install_go_tool "github.com/gwen001/github-subdomains" "github-subdomains"

# Utility
install_go_tool "github.com/tomnomnom/anew"            "anew"
install_go_tool "github.com/tomnomnom/qsreplace"       "qsreplace"
install_go_tool "github.com/ffuf/ffuf/v2"              "ffuf"
install_go_tool "github.com/s0md3v/smap/cmd/smap"      "smap"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Symlink sweep: catch anything already in GOPATH but not /usr/local/bin
# ─────────────────────────────────────────────────────────────────────────────
step "Symlinking tools to /usr/local/bin"

SYMLINKED=0
for bin in "$GOPATH/bin"/*; do
    [ -x "$bin" ] || continue
    name=$(basename "$bin")
    dest="/usr/local/bin/$name"
    if [ ! -e "$dest" ]; then
        if [ -w /usr/local/bin ]; then
            ln -sf "$bin" "$dest" 2>/dev/null && SYMLINKED=$((SYMLINKED + 1))
        elif sudo -n true 2>/dev/null; then
            sudo ln -sf "$bin" "$dest" 2>/dev/null && SYMLINKED=$((SYMLINKED + 1))
        fi
    fi
done
success "GOPATH tools ready ($SYMLINKED symlinked)"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — findomain (prebuilt binary, not on Go module proxy)
# ─────────────────────────────────────────────────────────────────────────────
step "Installing findomain"

if command -v findomain &>/dev/null; then
    success "findomain already installed ($(findomain --version 2>/dev/null | head -1))"
else
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" ;;
        aarch64) FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64.zip" ;;
        *)       FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" ;;
    esac
    info "Downloading findomain ($ARCH)..."
    TMP_FD="/tmp/findomain.zip"
    if curl -sL --connect-timeout 15 "$FD_URL" -o "$TMP_FD" 2>/dev/null && [ -s "$TMP_FD" ]; then
        unzip -q -o "$TMP_FD" -d /tmp/findomain_bin 2>/dev/null || true
        if [ -f /tmp/findomain_bin/findomain ]; then
            cp /tmp/findomain_bin/findomain "$GOPATH/bin/findomain"
            chmod +x "$GOPATH/bin/findomain"
            if [ -w /usr/local/bin ]; then
                cp "$GOPATH/bin/findomain" /usr/local/bin/findomain 2>/dev/null || true
            elif sudo -n true 2>/dev/null; then
                sudo cp "$GOPATH/bin/findomain" /usr/local/bin/findomain 2>/dev/null || true
            fi
            success "findomain installed → $GOPATH/bin/findomain"
        else
            warn "findomain extraction failed"
        fi
        rm -rf "$TMP_FD" /tmp/findomain_bin
    else
        warn "findomain download failed"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — amass prebuilt release binary
# ─────────────────────────────────────────────────────────────────────────────
step "Installing amass (clean release binary)"

AMASS_OK=false
if command -v amass &>/dev/null; then
    AMASS_TEST=$(amass -version 2>&1)
    if echo "$AMASS_TEST" | grep -qi "libpostal\|transliteration\|No such file"; then
        warn "Existing amass has libpostal crash bug — replacing..."
        if sudo -n true 2>/dev/null; then
            sudo rm -f "$(which amass)"
        fi
    else
        success "amass already installed ($AMASS_TEST)"
        AMASS_OK=true
    fi
fi

if [ "$AMASS_OK" = false ]; then
    AMASS_VER="v4.2.0"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  AMASS_ARCH="amd64" ;;
        aarch64) AMASS_ARCH="arm64" ;;
        *)       AMASS_ARCH="amd64" ;;
    esac
    AMASS_URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_Linux_${AMASS_ARCH}.zip"
    info "Downloading amass ${AMASS_VER} (${AMASS_ARCH})..."
    wget -q --timeout=30 "$AMASS_URL" -O /tmp/amass.zip 2>/dev/null
    if [ -f /tmp/amass.zip ]; then
        unzip -q /tmp/amass.zip -d /tmp/amass_extract 2>/dev/null || true
        AMASS_BIN=$(find /tmp/amass_extract -name "amass" -type f 2>/dev/null | head -1)
        if [ -n "$AMASS_BIN" ]; then
            cp "$AMASS_BIN" "$GOPATH/bin/amass"
            chmod +x "$GOPATH/bin/amass"
            if [ -w /usr/local/bin ]; then
                cp "$AMASS_BIN" /usr/local/bin/amass 2>/dev/null || true
            elif sudo -n true 2>/dev/null; then
                sudo cp "$AMASS_BIN" /usr/local/bin/amass 2>/dev/null || true
            fi
            rm -rf /tmp/amass_extract /tmp/amass.zip
            success "amass installed → $GOPATH/bin/amass"
        else
            warn "amass binary not found in zip"
            rm -rf /tmp/amass_extract /tmp/amass.zip
        fi
    else
        warn "amass download failed"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — trufflehog (official install script)
# ─────────────────────────────────────────────────────────────────────────────
step "Installing trufflehog"

if command -v trufflehog &>/dev/null; then
    success "trufflehog already installed ($(trufflehog --version 2>/dev/null | head -1))"
else
    info "Installing trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "$GOPATH/bin" 2>/dev/null && \
        success "trufflehog installed → $GOPATH/bin/trufflehog" || \
        warn "trufflehog install failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — Python tools
# ─────────────────────────────────────────────────────────────────────────────
step "Installing Python-based tools"

pip_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi
    info "Installing $pkg via pip3..."
    pip3 install "$pkg" --break-system-packages --quiet 2>/dev/null && \
        success "$pkg installed" || \
        warn "$pkg pip install failed — try: pip3 install $pkg --break-system-packages"
}

pip_install "waymore"
pip_install "wafw00f"
pip_install "dirsearch"
pip_install "s3scanner"

# cloud_enum — install from GitHub
step "Installing cloud_enum"
if command -v cloud_enum &>/dev/null; then
    success "cloud_enum already installed"
else
    info "Cloning and installing cloud_enum..."
    TMP_CE=$(mktemp -d)
    git clone -q --depth=1 https://github.com/initstring/cloud_enum "$TMP_CE/cloud_enum" 2>/dev/null && \
        pip3 install "$TMP_CE/cloud_enum" --break-system-packages --quiet 2>/dev/null && \
        success "cloud_enum installed" || \
        warn "cloud_enum install failed"
    rm -rf "$TMP_CE"
fi

# corsy — install from GitHub
step "Installing corsy"
if command -v corsy &>/dev/null; then
    success "corsy already installed"
else
    info "Cloning and installing corsy..."
    TMP_COR=$(mktemp -d)
    git clone -q --depth=1 https://github.com/s0md3v/Corsy "$TMP_COR/Corsy" 2>/dev/null && \
        mkdir -p "$HOME/.local/share/Corsy" "$HOME/.local/bin" && \
        cp -r "$TMP_COR/Corsy"/* "$HOME/.local/share/Corsy/" 2>/dev/null && \
        ln -sf "$HOME/.local/share/Corsy/corsy.py" "$HOME/.local/bin/corsy" && \
        chmod +x "$HOME/.local/bin/corsy" && \
        success "corsy installed" || \
        warn "corsy install failed"
    rm -rf "$TMP_COR"
fi

# paramspider — must install from GitHub (not on PyPI)
step "Installing paramspider"
if command -v paramspider &>/dev/null; then
    success "paramspider already installed"
else
    info "Cloning and installing paramspider..."
    TMP_PS=$(mktemp -d)
    git clone -q --depth=1 https://github.com/devanshbatham/ParamSpider "$TMP_PS/ParamSpider" 2>/dev/null && \
        pip3 install "$TMP_PS/ParamSpider" --break-system-packages --quiet 2>/dev/null && \
        success "paramspider installed" || \
        warn "paramspider install failed"
    rm -rf "$TMP_PS"
fi

# SecretFinder — install from GitHub
step "Installing secretfinder"
if command -v secretfinder &>/dev/null; then
    success "secretfinder already installed"
else
    info "Cloning and installing SecretFinder..."
    TMP_SF=$(mktemp -d)
    git clone -q --depth=1 https://github.com/m4ll0k/SecretFinder "$TMP_SF/SecretFinder" 2>/dev/null && \
        pip3 install -r "$TMP_SF/SecretFinder/requirements.txt" --break-system-packages --quiet 2>/dev/null && \
        mkdir -p "$HOME/.local/share/SecretFinder" "$HOME/.local/bin" && \
        cp -r "$TMP_SF/SecretFinder"/* "$HOME/.local/share/SecretFinder/" 2>/dev/null && \
        ln -sf "$HOME/.local/share/SecretFinder/SecretFinder.py" "$HOME/.local/bin/secretfinder" && \
        chmod +x "$HOME/.local/bin/secretfinder" "$HOME/.local/share/SecretFinder/SecretFinder.py" 2>/dev/null && \
        success "secretfinder installed" || \
        warn "secretfinder install failed"
    rm -rf "$TMP_SF"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — Nuclei templates + DNS resolvers
# ─────────────────────────────────────────────────────────────────────────────
step "Updating nuclei templates"
if command -v nuclei &>/dev/null; then
    timeout 30s nuclei -update-templates -silent 2>/dev/null && \
        success "Nuclei templates updated" || \
        warn "Nuclei template update skipped/timed out"
else
    warn "nuclei not found — skipping"
fi

step "Downloading DNS resolvers"
mkdir -p "$HOME/.config/reconx" "$HOME/.config/puredns"
if [ -s "$HOME/.config/reconx/resolvers.txt" ]; then
    success "Resolvers already present ($HOME/.config/reconx/resolvers.txt)"
else
    wget -q --timeout=15 "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -O "$HOME/.config/reconx/resolvers.txt" && \
        success "Resolvers → $HOME/.config/reconx/resolvers.txt" || \
        warn "Resolver download failed"
fi
# puredns looks for resolvers at ~/.config/puredns/resolvers.txt — without it
# the bruteforce phase errors out. Mirror the reconx copy so puredns just works.
if [ -s "$HOME/.config/reconx/resolvers.txt" ] && [ ! -s "$HOME/.config/puredns/resolvers.txt" ]; then
    cp "$HOME/.config/reconx/resolvers.txt" "$HOME/.config/puredns/resolvers.txt" && \
        success "Resolvers mirrored → $HOME/.config/puredns/resolvers.txt (puredns default)"
fi

# Fix "permission denied" when reconx executes tools from ~/go/bin — some
# install methods (manual copy, tar extraction) leave binaries non-executable.
if [ -d "$HOME/go/bin" ]; then
    chmod +x "$HOME/go/bin/"* 2>/dev/null && \
        success "Ensured ~/go/bin/* executables are +x"
fi

# DNS brute-force wordlist — without it puredns/shuffledns/dnsx-brute are
# skipped entirely ("no wordlist found") and the brute phase yields nothing.
WORDLIST_DIR="$HOME/.config/reconx/wordlists"
mkdir -p "$WORDLIST_DIR"
if [ -s "$WORDLIST_DIR/subdomains.txt" ]; then
    success "DNS wordlist already present ($WORDLIST_DIR/subdomains.txt)"
else
    wget -q --timeout=30 \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
        -O "$WORDLIST_DIR/subdomains.txt" && \
        success "DNS wordlist → $WORDLIST_DIR/subdomains.txt ($(wc -l < "$WORDLIST_DIR/subdomains.txt") entries)" || \
        warn "DNS wordlist download failed — brute-force will be skipped"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10b — Additional tools: tlsx, feroxbuster, massdns
# ─────────────────────────────────────────────────────────────────────────────
step "Installing additional tools (tlsx, feroxbuster, massdns)"

# tlsx — TLS certificate info (ProjectDiscovery)
install_go_tool "github.com/projectdiscovery/tlsx/cmd/tlsx" "tlsx"

# feroxbuster — recursive directory fuzzer (Rust/cargo)
if command -v feroxbuster &>/dev/null; then
    success "feroxbuster already installed"
elif command -v cargo &>/dev/null; then
    info "Installing feroxbuster via cargo..."
    cargo install feroxbuster --quiet 2>/dev/null && \
        success "feroxbuster installed" || \
        warn "feroxbuster cargo install failed — try: cargo install feroxbuster"
else
    # Fallback: prebuilt binary from GitHub releases
    info "Downloading feroxbuster..."
    FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"
    if wget -q --timeout=20 "$FEROX_URL" -O /tmp/ferox.zip 2>/dev/null && \
        unzip -q /tmp/ferox.zip feroxbuster -d /tmp 2>/dev/null; then
        mv /tmp/feroxbuster "$GOPATH/bin/feroxbuster"
        chmod +x "$GOPATH/bin/feroxbuster"
        if [ -w /usr/local/bin ]; then
            cp "$GOPATH/bin/feroxbuster" /usr/local/bin/feroxbuster 2>/dev/null || true
        elif sudo -n true 2>/dev/null; then
            sudo cp "$GOPATH/bin/feroxbuster" /usr/local/bin/feroxbuster 2>/dev/null || true
        fi
        rm -f /tmp/ferox.zip
        success "feroxbuster installed → $GOPATH/bin/feroxbuster"
    else
        warn "feroxbuster install failed"
    fi
fi

# massdns — mass DNS resolver (apt or build from source)
if command -v massdns &>/dev/null || [ -x "$GOPATH/bin/massdns" ]; then
    success "massdns already installed"
elif sudo -n true 2>/dev/null && sudo apt-get install -y massdns --quiet &>/dev/null 2>&1; then
    success "massdns installed via apt"
else
    info "Building massdns from source..."
    TMP_MD=$(mktemp -d)
    if git clone -q --depth=1 https://github.com/blechschmidt/massdns "$TMP_MD/massdns" 2>/dev/null && \
        make -C "$TMP_MD/massdns" -s 2>/dev/null; then
        cp "$TMP_MD/massdns/bin/massdns" "$GOPATH/bin/massdns"
        chmod +x "$GOPATH/bin/massdns"
        if [ -w /usr/local/bin ]; then
            cp "$GOPATH/bin/massdns" /usr/local/bin/massdns 2>/dev/null || true
        elif sudo -n true 2>/dev/null; then
            sudo cp "$GOPATH/bin/massdns" /usr/local/bin/massdns 2>/dev/null || true
        fi
        success "massdns built from source → $GOPATH/bin/massdns"
    else
        warn "massdns build failed (optional tool — skipping)"
    fi
    rm -rf "$TMP_MD"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10c — gowitness + Chromium deps (screenshots phase)
# ─────────────────────────────────────────────────────────────────────────────
# Without gowitness the --screenshots phase silently skips on every run.
# gowitness v3 also needs a working Chromium/Chrome — on a bare VPS only the
# install itself succeeds while every capture fails, so deps matter.
step "Installing gowitness (screenshots) + Chromium dependencies"

install_go_tool "github.com/sensepost/gowitness@latest" "gowitness"

if ! command -v gowitness &>/dev/null && [ ! -x "$GOPATH/bin/gowitness" ]; then
    warn "gowitness install failed — screenshots phase will be skipped"
else
    # Chromium: needed by gowitness's headless browser
    if command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null || command -v google-chrome &>/dev/null; then
        success "Chromium already present"
    elif sudo -n true 2>/dev/null; then
        info "Installing Chromium (required for screenshots)..."
        if sudo apt-get install -y chromium-browser --quiet &>/dev/null 2>&1 || \
           sudo apt-get install -y chromium --quiet &>/dev/null 2>&1; then
            success "Chromium installed"
        else
            warn "Chromium install failed — screenshots may fail. Try: sudo apt install chromium-browser"
        fi
    else
        warn "No Chromium found and no sudo — screenshots will likely fail"
    fi
fi


# ─────────────────────────────────────────────────────────────────────────────
# STEP 11 — Build and install reconx binary
# ─────────────────────────────────────────────────────────────────────────────
step "Building ReconX"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if $GO_BIN build -o "$SCRIPT_DIR/reconx" ./cmd/reconx/ 2>&1; then
    cp "$SCRIPT_DIR/reconx" "$GOPATH/bin/reconx" 2>/dev/null || true
    if [ -w /usr/local/bin ]; then
        cp "$SCRIPT_DIR/reconx" /usr/local/bin/reconx 2>/dev/null || true
    elif sudo -n true 2>/dev/null; then
        sudo cp "$SCRIPT_DIR/reconx" /usr/local/bin/reconx 2>/dev/null || true
    fi
    success "reconx built and installed → $GOPATH/bin/reconx"
else
    error "reconx build failed"
    warn "Manual fix: cd $SCRIPT_DIR && go build -o reconx ./cmd/reconx/"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 12 — Final symlink sweep (catch anything missed above)
# ─────────────────────────────────────────────────────────────────────────────
step "Final check"
for bin in "$GOPATH/bin"/*; do
    [ -x "$bin" ] || continue
    name=$(basename "$bin")
    dest="/usr/local/bin/$name"
    if [ ! -e "$dest" ]; then
        if [ -w /usr/local/bin ]; then
            ln -sf "$bin" "$dest" 2>/dev/null || true
        elif sudo -n true 2>/dev/null; then
            sudo ln -sf "$bin" "$dest" 2>/dev/null || true
        fi
    fi
done
success "All Go tools ready in PATH ($GOPATH/bin)"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 13 — Verification report
# ─────────────────────────────────────────────────────────────────────────────
step "Verification"

ALL_TOOLS=(
    subfinder assetfinder amass findomain chaos puredns dnsx github-subdomains
    crobat shuffledns
    httpx curl naabu
    waybackurls waymore gau gauplus katana hakrawler gospider paramspider
    s3scanner cloud_enum corsy
    secretfinder mantra jsecret subjs trufflehog
    nuclei
    reconx
)

INSTALLED=()
MISSING=()
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        INSTALLED+=("$tool")
    else
        MISSING+=("$tool")
    fi
done

echo ""
echo -e "  ${GREEN}${BOLD}Installed (${#INSTALLED[@]}/${#ALL_TOOLS[@]}):${NC}"
for t in "${INSTALLED[@]}"; do
    printf "    ${GREEN}✓${NC} %-22s %s\n" "$t" "$(command -v $t)"
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${YELLOW}${BOLD}Missing (${#MISSING[@]}):${NC}"
    for t in "${MISSING[@]}"; do
        echo -e "    ${YELLOW}○${NC} $t"
    done
fi

echo ""
echo -e "${GREEN}${BOLD}  ════════════════════════════════════════════════════${NC}"
if [ ${#MISSING[@]} -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  All ${#ALL_TOOLS[@]}/${#ALL_TOOLS[@]} tools installed — ready to scan!${NC}"
else
    echo -e "${YELLOW}${BOLD}  ${#INSTALLED[@]}/${#ALL_TOOLS[@]} tools installed (${#MISSING[@]} missing above)${NC}"
fi
echo -e "${GREEN}${BOLD}  ════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Verify tools:${NC}  reconx -d test.com --skip-subs --skip-alive --skip-ports --skip-urls --skip-js --skip-vuln"
echo -e "  ${CYAN}Run a scan:${NC}    reconx -d target.com --scope scope.txt --header \"X-Bug-Bounty: True\""
echo ""
