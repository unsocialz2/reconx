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

- Installs OS build dependencies, including libpcap headers.
- Uses a suitable existing Go/Node installation or downloads a user-local runtime with SHA-256 verification.
- Builds ReconX both in the repository and in `~/.local/bin`.
- Installs pinned subfinder, httpx, nuclei, naabu, katana, dnsx, gau, and Gitleaks into `~/go/bin` by default.
- Downloads nuclei templates and checks tool help output.
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

For custom locations, set `RECONX_BIN_DIR`, `RECONX_TOOLS_DIR`, `RECONX_SETUP_DIR`, or `RECONX_RUNTIME_DIR`. `RECONX_GO` selects an existing Go executable; `RECONX_GO_VERSION` selects a release when Go needs downloading. The final output prints the actual installed paths.
