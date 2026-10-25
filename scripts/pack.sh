#!/usr/bin/env bash
# Builds the extension zip so that the same commit always gives the same bytes: files come from git (not the
# working tree), with fixed timestamps, modes and order, stored without compression so the zip version does
# not change the output. Anyone can rebuild a release from its tag and compare the sha256.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/secure-cookie-viewer.zip}"
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

if [ -n "$(git -C "$root" status --porcelain -- extension)" ]; then
  echo "extension/ has uncommitted changes; commit them first so the zip matches a commit" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git -C "$root" archive HEAD extension | tar -x -C "$work"

cd "$work/extension"
find . -type d -exec chmod 755 {} +
find . -type f -exec chmod 644 {} +
find . -exec env TZ=UTC touch -h -t 198001010000 {} +
rm -f "$out"
find . -type f | LC_ALL=C sort | TZ=UTC zip -q -X -0 -@ "$out"
shasum -a 256 "$out" | cut -d' ' -f1
