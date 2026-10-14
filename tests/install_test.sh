#!/usr/bin/env bash
# Isolated installer tests: fake binaries/downloads; no sudo, provider APIs or target scans.
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/project/web" "$FIXTURE/fake-bin" "$FIXTURE/download/go/bin"
cp "$SOURCE_DIR/install.sh" "$FIXTURE/project/install.sh"
case "$(uname -s)" in Darwin) os_name=darwin ;; *) os_name=linux ;; esac
case "$(uname -m)" in arm64|aarch64) go_arch=arm64; node_arch=arm64 ;; *) go_arch=amd64; node_arch=x64 ;; esac

cat > "$FIXTURE/fake-bin/fake-go" <<'GO'
#!/usr/bin/env bash
set -e
case "$1" in
 version) printf 'go version go%s test/arch\n' "${FAKE_GO_VERSION:-1.25.3}" ;;
 build)
  shift
  while (( $# )); do
   if [[ "$1" == -o ]]; then out="$2";break;fi
   shift
  done
  mkdir -p "$(dirname "$out")"
  cat > "$out" <<'CLI'
#!/usr/bin/env bash
set -e
if [[ "$1" == --version ]]; then echo 'v1.1.0';exit;fi
if [[ "$1" == --help ]]; then echo 'ReconX help';exit;fi
all_args=" $* "
for phase in subs alive ports urls js vuln cloud cors;do
 [[ "$all_args" == *" --skip-$phase "* ]] || exit 42
done
while (( $# ));do
 if [[ "$1" == --output ]];then out="$2";break;fi
 shift
done
mkdir -p "$out/example.com-fixture"
for file in checkpoint.json manifest.json results.json report.html reconx.log;do
 printf '{}\n' > "$out/example.com-fixture/$file"
done
CLI
  chmod +x "$out" ;;
 *) exit 3 ;;
esac
GO
chmod +x "$FIXTURE/fake-bin/fake-go"
cp "$FIXTURE/fake-bin/fake-go" "$FIXTURE/download/go/bin/go"
# The downloaded toolchain has a distinct marker/version from the existing fake Go.
python3 - "$FIXTURE/download/go/bin/go" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);p.write_text(p.read_text().replace('${FAKE_GO_VERSION:-1.25.3}','1.25.3'))
PY
go_archive="go1.25.3.$os_name-$go_arch.tar.gz"
tar -czf "$FIXTURE/download/$go_archive" -C "$FIXTURE/download" go
python3 - "$FIXTURE/download" "$go_archive" "$os_name" "$go_arch" <<'PY'
import hashlib,json,sys,pathlib
root=pathlib.Path(sys.argv[1]);name,os_name,arch=sys.argv[2:]
checksum=hashlib.sha256((root/name).read_bytes()).hexdigest()
(root/'go.json').write_text(json.dumps([{'version':'go1.25.3','stable':True,'files':[{'filename':name,'sha256':checksum,'kind':'archive','os':os_name,'arch':arch}]}]))
PY
cat > "$FIXTURE/fake-bin/curl" <<'CURL'
#!/usr/bin/env bash
set -e
url=;out=
while (( $# ));do
 case "$1" in -o) out="$2";shift ;; https://*) url="$1" ;; esac
 shift
done
case "$url" in
 *'mode=json'*) cp "$FAKE_DOWNLOADS/go.json" "$out" ;;
 https://go.dev/dl/*.tar.gz) cp "$FAKE_DOWNLOADS/${url##*/}" "$out" ;;
 https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt) cp "$FAKE_DOWNLOADS/node-checksums" "$out" ;;
 https://nodejs.org/dist/v22.*/*.tar.gz) cp "$FAKE_DOWNLOADS/${url##*/}" "$out" ;;
 *) echo "Unexpected download: $url" >&2;exit 8 ;;
esac
CURL
chmod +x "$FIXTURE/fake-bin/curl"
export PATH="$FIXTURE/fake-bin:$PATH"
export FAKE_DOWNLOADS="$FIXTURE/download"
export RECONX_BIN_DIR="$FIXTURE/bin"
export RECONX_TOOLS_DIR="$FIXTURE/tools"
export RECONX_SETUP_DIR="$FIXTURE/setup"
export RECONX_RUNTIME_DIR="$FIXTURE/runtime"
export RECONX_PROFILE_FILE="$FIXTURE/profile"
export RECONX_GO="$FIXTURE/fake-bin/fake-go"

# CLI-only setup must stay local, validate the smoke command, and add PATH exactly once.
for attempt in 1 2;do
 bash "$FIXTURE/project/install.sh" --skip-system-deps --skip-tools --cli-only --skip-checks > "$FIXTURE/setup-$attempt.log" 2>&1
done
[[ -x "$FIXTURE/bin/reconx" && -f "$FIXTURE/setup/install-receipt.txt" ]]
[[ "$(grep -c '^\. ' "$FIXTURE/profile")" == 1 ]]
[[ ! -e "$FIXTURE/bin/reconx-web" ]]

# Unknown options fail before installation; checksum failures never execute extracted Go.
if bash "$FIXTURE/project/install.sh" --bad-option > "$FIXTURE/bad-option.log" 2>&1;then echo 'Unknown option accepted' >&2;exit 1;fi
export FAKE_GO_VERSION=1.20.0
bash "$FIXTURE/project/install.sh" --skip-system-deps --skip-tools --cli-only --skip-checks --no-profile > "$FIXTURE/bootstrap.log" 2>&1
[[ -x "$FIXTURE/runtime/go/bin/go" ]]
python3 - "$FIXTURE/download/go.json" <<'PY'
from pathlib import Path
import json,sys
p=Path(sys.argv[1]);data=json.loads(p.read_text());data[0]['files'][0]['sha256']='0'*64;p.write_text(json.dumps(data))
PY
rm -rf "$FIXTURE/runtime/go"
if bash "$FIXTURE/project/install.sh" --skip-system-deps --skip-tools --cli-only --skip-checks --no-profile > "$FIXTURE/checksum.log" 2>&1;then echo 'Checksum mismatch accepted' >&2;exit 1;fi
grep -q 'Checksum mismatch' "$FIXTURE/checksum.log"
[[ ! -e "$FIXTURE/runtime/go/bin/go" ]]
# Bootstrap Node/npm from a checksum-verified local archive and exercise the launcher.
export FAKE_GO_VERSION=1.25.3
cat > "$FIXTURE/fake-bin/node" <<'NODE'
#!/usr/bin/env bash
if [[ "$1" == -p ]];then echo 20;else echo v20.0.0;fi
NODE
cat > "$FIXTURE/fake-bin/npm" <<'NPM'
#!/usr/bin/env bash
set -e
case "$1" in
 --version) echo 10.0.0 ;;
 ci) touch .fixture-npm-ci ;;
 run) [[ "$2" == build ]];mkdir -p .next/standalone;printf 'fixture' > .next/standalone/server.js ;;
 start) echo 'Fixture dashboard launcher works' ;;
 *) exit 4 ;;
esac
NPM
chmod +x "$FIXTURE/fake-bin/node" "$FIXTURE/fake-bin/npm"
node_archive="node-v22.0.1-$os_name-$node_arch.tar.gz"
mkdir -p "$FIXTURE/download/${node_archive%.tar.gz}/bin"
cat > "$FIXTURE/download/${node_archive%.tar.gz}/bin/node" <<'NODE'
#!/usr/bin/env bash
if [[ "$1" == -p ]];then echo 22;else echo v22.0.1;fi
NODE
cp "$FIXTURE/fake-bin/npm" "$FIXTURE/download/${node_archive%.tar.gz}/bin/npm"
chmod +x "$FIXTURE/download/${node_archive%.tar.gz}/bin/node"
tar -czf "$FIXTURE/download/$node_archive" -C "$FIXTURE/download" "${node_archive%.tar.gz}"
python3 - "$FIXTURE/download" "$node_archive" <<'PYNODE'
import hashlib,sys,pathlib
root=pathlib.Path(sys.argv[1]);name=sys.argv[2]
(root/'node-checksums').write_text(hashlib.sha256((root/name).read_bytes()).hexdigest()+'  '+name+'\n')
PYNODE
bash "$FIXTURE/project/install.sh" --skip-system-deps --skip-tools --skip-checks --no-profile > "$FIXTURE/node-bootstrap.log" 2>&1
[[ -x "$FIXTURE/runtime/node/bin/node" && -x "$FIXTURE/bin/reconx-web" ]]
"$FIXTURE/bin/reconx-web" > "$FIXTURE/launcher.log"
grep -q 'Fixture dashboard launcher works' "$FIXTURE/launcher.log"
printf 'Installer tests passed: repeat runs, safe smoke flags, options, Go/Node bootstrap, checksum rejection, and web launcher.\n'
