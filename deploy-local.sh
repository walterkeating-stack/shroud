#!/usr/bin/env bash
# Build and deploy shroud to local OpenClaw extension dir (no npm publish needed)
#
# Since v2.1, Shroud patches EventStream.prototype.push at runtime —
# no file modifications to OpenClaw's node_modules are needed.
# This script only builds and copies files.
set -e
cd "$(dirname "$0")"
npm run build

DEST="$HOME/.openclaw/extensions/shroud-privacy"
mkdir -p "$DEST"
cp -r dist package.json openclaw.plugin.json "$DEST/"

# Clear Node.js V8 compile cache so the updated plugin is loaded from disk.
NODE_CACHE_DIR="${NODE_COMPILE_CACHE:-/tmp/node-compile-cache}"
if [ -d "$NODE_CACHE_DIR" ]; then
  for d in "$NODE_CACHE_DIR"/v*-"$(id -u)" "$NODE_CACHE_DIR"/v*; do
    rm -rf "$d" 2>/dev/null || true
  done
  sudo rm -rf "$NODE_CACHE_DIR"/v*-0 2>/dev/null || true
  echo "Cleared Node.js compile cache."
fi

echo "Deployed shroud plugin. Restart OpenClaw to pick up changes."
