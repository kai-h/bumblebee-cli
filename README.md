# bumblebee-cli

A terminal interface for [bumblebee](https://github.com/perplexityai/bumblebee), Perplexity's supply-chain security scanner. Streams NDJSON output from the scanner and presents findings and packages in a formatted, colour-coded display.

## Features

- Automatically downloads the `bumblebee` binary and threat intel catalog on first run — no manual setup required
- Keeps the threat intel catalog up to date from the `main` branch (independent of binary releases)
- Severity-coded finding badges (critical / high / medium / low)
- Packages grouped by ecosystem; full package list shown only when findings are present
- Exit codes suitable for CI: `0` = clean, `1` = error, `2` = findings present

## Installation

Download the latest release for your platform from the [releases page](https://github.com/kai-h/bumblebee-cli/releases), extract, and place the binary on your `PATH`. The `bumblebee` scanner binary and threat intel catalog are downloaded automatically on first run.

## Quick start

```sh
# Scan a project (bumblebee binary and catalog are downloaded automatically if needed)
./bumblebee-cli --root /path/to/project

# Scan with a specific profile
./bumblebee-cli --root /path/to/project --profile deep

# Update the threat intel catalog
./bumblebee-cli --update-catalog

# Print version
./bumblebee-cli --version
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--root` | | Directory to scan. Required for `project` and `deep` profiles. |
| `--profile` | `project` | Scan profile: `project`, `baseline`, or `deep`. |
| `--catalog` | _(auto)_ | Path to threat intel catalog directory. Skips auto-management when set. |
| `--binary` | _(auto)_ | Path to `bumblebee` binary. Skips auto-download when set. |
| `--update-catalog` | | Fetch the latest threat intel catalog from GitHub and exit. |
| `--version` | | Print version and exit. |

## Output

A clean scan shows a per-ecosystem package count and a summary line — no noise when there's nothing to act on:

```
Packages (159)

  npm (159)

Clean — 159 package(s) scanned, no findings
```

When findings are present the full package list is shown alongside the findings, sorted by severity:

```
Findings (2)

  CRITICAL  evil-pkg  1.0.0
            npm · mini-shai-hulud · malicious_package

Packages (159)

  npm (159)
    evil-pkg        1.0.0 · package-lock.json
    lodash          4.17.21 · package-lock.json
    ...

2 finding(s)  ·  159 package(s)
```

## Auto-provisioning

On first run, `bumblebee-cli` will:

1. Download the `bumblebee` binary for the current platform from the latest [GitHub release](https://github.com/perplexityai/bumblebee/releases)
2. Download the threat intel catalog from the `main` branch

Both are stored in the platform data directory:

| Platform | Location |
|---|---|
| Linux | `$XDG_DATA_HOME/bumblebee/` (default `~/.local/share/bumblebee/`) |
| macOS | `~/Library/Application Support/bumblebee/` |
| Windows | `%LOCALAPPDATA%\bumblebee\` |

On subsequent runs, the catalog is checked against GitHub once every 24 hours. If a newer commit to `threat_intel/` is found you will be prompted to update. Pass `--catalog /path` to manage the catalog yourself and skip all network checks.

## Building from source

```sh
go build -o bumblebee-cli .
```

To build a release binary with version embedded and debug info stripped:

```sh
go build -ldflags "-s -w -X main.version=v1.0.0" -trimpath -o bumblebee-cli .
```

To cross-compile for another platform:

```sh
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=v1.0.0" -trimpath -o bumblebee-cli .
```

See `release.sh` for the full multi-platform build and publish workflow.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Error (binary not found, scan failed, etc.) |
| `2` | Scan completed, findings present |

## Requirements

- Go 1.21+ to build from source
- No runtime dependencies — the `bumblebee` binary and threat intel catalog are fetched automatically
