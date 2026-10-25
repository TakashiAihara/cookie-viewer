#!/usr/bin/env bash
# Builds the extension zip so that the same source always gives the same bytes: fixed timestamps, file
# modes and file order. Anyone can rebuild a release from its tag and compare the sha256.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$(realpath -m "${1:-$root/secure-cookie-viewer.zip}")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -R "$root/extension/." "$work/"
find "$work" -type d -exec chmod 755 {} +
find "$work" -type f -exec chmod 644 {} +
find "$work" -exec touch -h -d '1980-01-01 00:00:00 UTC' {} +

rm -f "$out"
(cd "$work" && find . -type f | LC_ALL=C sort | TZ=UTC zip -qX -@ "$out")
sha256sum "$out" | cut -d' ' -f1
