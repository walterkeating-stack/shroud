#!/usr/bin/env bash
# Build and deploy shroud to local OpenClaw extension dir (no npm publish needed)
set -e
cd "$(dirname "$0")"
npm run build
cp -r dist package.json openclaw.plugin.json "$HOME/.openclaw/extensions/shroud-privacy/"
echo "Deployed shroud plugin."

# ---------------------------------------------------------------------------
# Patch pi-ai EventStream.push() to call globalThis.__shroudStreamDeobfuscate
#
# This enables streaming deobfuscation — fake values in LLM responses are
# replaced with real values as they stream. Without this patch, deobfuscation
# only happens after the full response is received.
#
# The outbound direction (obfuscation before the LLM sees PII) is handled by
# the fetch intercept in hooks.ts — no patching needed for that.
# ---------------------------------------------------------------------------

# Derive OpenClaw install root from the extensions directory
EXTENSIONS_DIR="$HOME/.openclaw/extensions"
if [ ! -d "$EXTENSIONS_DIR" ]; then
  echo "Warning: Extensions directory not found at $EXTENSIONS_DIR — skipping EventStream patch."
  exit 0
fi

# Find event-stream.js relative to the openclaw binary
EVENT_STREAM=""
OPENCLAW_BIN="$(command -v openclaw 2>/dev/null || true)"
if [ -n "$OPENCLAW_BIN" ]; then
  OPENCLAW_BIN_DIR="$(dirname "$(readlink -f "$OPENCLAW_BIN")")"
  for candidate in \
    "$OPENCLAW_BIN_DIR/../lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js" \
    "$OPENCLAW_BIN_DIR/../node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js" \
    "$HOME/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js"; do
    if [ -f "$candidate" ]; then
      EVENT_STREAM="$(readlink -f "$candidate")"
      break
    fi
  done
fi

if [ ! -f "$EVENT_STREAM" ]; then
  echo "Warning: event-stream.js not found — skipping EventStream patch."
  echo "  Streaming deobfuscation will not work until this is patched."
  NEED_ES_PATCH=0
fi

# Idempotency check: don't re-patch if already patched
NEED_ES_PATCH=1
if grep -q '__shroudStreamDeobfuscate' "$EVENT_STREAM"; then
  echo "EventStream already patched — skipping."
  NEED_ES_PATCH=0
fi

if [ "$NEED_ES_PATCH" = "1" ]; then
  # Back up the original if not already backed up
  if [ ! -f "${EVENT_STREAM}.shroud-backup" ]; then
    cp "$EVENT_STREAM" "${EVENT_STREAM}.shroud-backup"
    echo "Backed up original event-stream.js to ${EVENT_STREAM}.shroud-backup"
  fi

  # Patch: inject the deobfuscation hook into push(event) {
  sed -i.tmp '/push(event)\s*{/a\
          // Shroud deobfuscation hook\
          const deob = globalThis.__shroudStreamDeobfuscate;\
          if (deob \&\& event \&\& typeof event === '\''object'\'') {\
              event = deob(this, event);\
          }' "$EVENT_STREAM"
  rm -f "${EVENT_STREAM}.tmp"

  echo "Patched EventStream.push() with Shroud deobfuscation hook."
fi

# ---------------------------------------------------------------------------
# Clear Node.js V8 compile cache so the patched file is loaded from disk.
# Node 22+ caches compiled ESM bytecode; without clearing, the old unpatched
# version is loaded from cache even after the file changes.
#
# Clears both user and root caches (gateway runs as root via systemd).
# ---------------------------------------------------------------------------
NODE_CACHE_DIR="${NODE_COMPILE_CACHE:-/tmp/node-compile-cache}"
if [ -d "$NODE_CACHE_DIR" ]; then
  # User cache
  for d in "$NODE_CACHE_DIR"/v*-"$(id -u)" "$NODE_CACHE_DIR"/v*; do
    rm -rf "$d" 2>/dev/null || true
  done
  # Root cache (gateway runs as root via systemd)
  sudo rm -rf "$NODE_CACHE_DIR"/v*-0 2>/dev/null || true
  echo "Cleared Node.js compile cache."
fi

echo "Restart OpenClaw to pick up changes."
