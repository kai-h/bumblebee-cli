#!/usr/bin/env bash
# release.sh — build multi-platform binaries and publish a GitHub release
#
# Prerequisites: go (≥1.21), gh (GitHub CLI), git
# On macOS with the default Go install: /usr/local/go/bin must be on PATH,
# or pass GO=/usr/local/go/bin/go before the script.
#
# Usage:
#   ./release.sh v0.1.0

set -euo pipefail

VERSION="${1:?Usage: ./release.sh <version>  e.g. ./release.sh v0.1.0}"
# strip leading 'v' for filenames — matches bumblebee naming convention
VER="${VERSION#v}"

APP="bumblebee-cli"
DIST="dist"
GO="${GO:-go}"
LDFLAGS="-s -w -X main.version=${VERSION}"

TARGETS=(
    "darwin  amd64"
    "darwin  arm64"
    "linux   amd64"
    "linux   arm64"
    "windows amd64"
    "windows arm64"
)

# ── Preflight ─────────────────────────────────────────────────────────────────

for cmd in "$GO" gh git; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "error: $cmd not found"; exit 1; }
done

if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working directory is not clean — commit or stash changes first"
    exit 1
fi

if git rev-parse "${VERSION}" >/dev/null 2>&1; then
    echo "error: tag ${VERSION} already exists locally"
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────

rm -rf "$DIST"
mkdir -p "$DIST"

echo "==> Building ${VERSION}"

for entry in "${TARGETS[@]}"; do
    read -r os arch <<< "$entry"
    name="${APP}_${VER}_${os}_${arch}"

    printf "    %-20s" "${os}/${arch}…"

    if [[ "$os" == "windows" ]]; then
        GOOS="$os" GOARCH="$arch" "$GO" build \
            -ldflags "$LDFLAGS" -trimpath \
            -o "${DIST}/${APP}.exe" .
        (cd "$DIST" && zip -q "${name}.zip" "${APP}.exe" && rm "${APP}.exe")
        echo "${name}.zip"
    else
        GOOS="$os" GOARCH="$arch" "$GO" build \
            -ldflags "$LDFLAGS" -trimpath \
            -o "${DIST}/${APP}" .
        tar -czf "${DIST}/${name}.tar.gz" -C "$DIST" "$APP"
        rm "${DIST}/${APP}"
        echo "${name}.tar.gz"
    fi
done

# ── Checksums ─────────────────────────────────────────────────────────────────

echo "==> Checksums"
(
    cd "$DIST"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- *.tar.gz *.zip
    else
        shasum -a 256 -- *.tar.gz *.zip
    fi
) | tee "${DIST}/checksums.txt"

# ── Tag and push ──────────────────────────────────────────────────────────────

echo "==> Tagging ${VERSION}"
git tag -a "${VERSION}" -m "Release ${VERSION}"
git push origin "${VERSION}"

# ── GitHub release ────────────────────────────────────────────────────────────

echo "==> Publishing GitHub release ${VERSION}"
gh release create "${VERSION}" \
    "${DIST}/"*.tar.gz \
    "${DIST}/"*.zip \
    "${DIST}/checksums.txt" \
    --title "bumblebee-cli ${VERSION}" \
    --generate-notes

echo ""
echo "Released: $(gh release view "${VERSION}" --json url -q .url)"
