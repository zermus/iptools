#!/bin/bash
# Build a release tarball: releases/ip-tools-<version>.tar.gz
# Run from the project root on a machine with tar.
set -euo pipefail

VERSION="0.1.1"
STAGE="ip-tools-${VERSION}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/releases"

cd "$ROOT"

echo ">> Staging ${STAGE}/ ..."
TMP="$(mktemp -d)"
DEST="${TMP}/${STAGE}"
mkdir -p "$DEST"

# What ships in a release: the tools, the shared layer, the deploy shim,
# and the docs. Not the website, build script, git metadata, or runtime dirs.
cp -- *.php "$DEST/"
cp -- subnets.html "$DEST/"
cp -- .htaccess README.md CHANGELOG.md LICENSE.txt "$DEST/"

# Scrub anything that shouldn't ship.
find "$DEST" -name '.DS_Store' -delete 2>/dev/null || true

mkdir -p "$OUT"
echo ">> Creating ${OUT}/${STAGE}.tar.gz ..."
tar -czf "${OUT}/${STAGE}.tar.gz" -C "$TMP" "$STAGE"

rm -rf "$TMP"
echo ">> Done: releases/${STAGE}.tar.gz"
ls -lh "${OUT}/${STAGE}.tar.gz"
