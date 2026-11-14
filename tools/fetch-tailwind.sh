#!/usr/bin/env sh
# Fetch the pinned Tailwind CSS standalone CLI into tools/tailwindcss.
#
# tools/tailwindcss is gitignored: every CI system downloads the same release
# and verifies the same checksum, so a local build, a Forgejo run and a GitHub
# run all compile input.css with an identical binary. Keep TAILWIND_VERSION and
# TAILWIND_SHA256 in step with each other (the checksum comes from the
# release's sha256sums.txt).
set -eu

TAILWIND_VERSION="v4.3.3"
TAILWIND_SHA256="dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a"

cd "$(dirname "$0")/.."

CLI="tools/tailwindcss"
if [ -x "$CLI" ]; then
  echo "$CLI already present"
  exit 0
fi

mkdir -p tools
echo "downloading tailwindcss ${TAILWIND_VERSION}"
curl -fsSL --retry 3 -o "$CLI" \
  "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64"

echo "${TAILWIND_SHA256}  ${CLI}" | sha256sum -c -
chmod +x "$CLI"
