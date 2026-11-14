#!/usr/bin/env sh
# Build the Passage UI stylesheet.
#
# Compiles internal/web/ui/input.css (Tailwind v4 + passage tokens/components)
# to internal/web/static/passage.css using the tailwindcss standalone CLI
# binary (no Node/npm required). The binary is not committed; fetch it from
# https://github.com/tailwindlabs/tailwindcss/releases (tailwindcss-linux-x64)
# and place it at tools/tailwindcss.
set -eu

cd "$(dirname "$0")/.."

CLI="tools/tailwindcss"
if [ ! -x "$CLI" ]; then
  echo "error: $CLI not found or not executable" >&2
  echo "download tailwindcss-linux-x64 from github.com/tailwindlabs/tailwindcss releases" >&2
  exit 1
fi

exec "$CLI" --input internal/web/ui/input.css --output internal/web/static/passage.css --minify "$@"
