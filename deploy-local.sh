#!/usr/bin/env bash
# Build and deploy shroud to local OpenClaw extension dir (no npm publish needed)
set -e
cd "$(dirname "$0")"
npm run build
cp -r dist package.json openclaw.plugin.json "$HOME/.openclaw/extensions/shroud-privacy/"
echo "Deployed shroud plugin."

# ---------------------------------------------------------------------------
# Patch pi-ai EventStream.push() to call globalThis.__shroudStreamDeobfuscate
# ---------------------------------------------------------------------------

# Derive OpenClaw install root from the extensions directory
EXTENSIONS_DIR="$HOME/.openclaw/extensions"
if [ ! -d "$EXTENSIONS_DIR" ]; then
  echo "Warning: Extensions directory not found at $EXTENSIONS_DIR — skipping EventStream patch."
  exit 0
fi

# The OpenClaw install root is two levels up from the extensions dir,
# or we can find it via the openclaw binary, but the safest approach is
# to look for the node_modules tree that contains pi-ai relative to openclaw.
# OpenClaw stores its install root in ~/.openclaw; node_modules lives alongside it.
# Find event-stream.js relative to the openclaw binary
EVENT_STREAM=""
OPENCLAW_BIN="$(command -v openclaw 2>/dev/null || true)"
if [ -n "$OPENCLAW_BIN" ]; then
  OPENCLAW_BIN_DIR="$(dirname "$(readlink -f "$OPENCLAW_BIN")")"
  # openclaw binary is in .npm-global/bin/, node_modules is in .npm-global/lib/node_modules/openclaw/
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
  echo "  Looked at: $EVENT_STREAM"
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
  # We look for "push(event) {" or "push(event){" and add the hook after the opening brace.
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
# Patch before_prompt_build to support { prompt } return (prompt replacement)
#
# Without this patch, OpenClaw ALWAYS sends the raw user prompt to the LLM
# alongside the obfuscated prependContext — defeating Shroud's privacy guarantee.
#
# The patch:
#   1. resolvePromptBuildHookResult() — pass through the `prompt` field
#   2. effectivePrompt assignment — use hookResult.prompt when present
# ---------------------------------------------------------------------------
OPENCLAW_DIST=""
if [ -n "$EVENT_STREAM" ] && [ -f "$EVENT_STREAM" ]; then
  OPENCLAW_DIST="$(readlink -f "$(dirname "$EVENT_STREAM")/../../../../..")/dist"  # up from pi-ai/dist/utils/ → openclaw/dist/
fi
if [ ! -d "$OPENCLAW_DIST" ]; then
  # Fallback: find via openclaw bin
  if [ -n "$OPENCLAW_BIN_DIR" ]; then
    OPENCLAW_DIST="$OPENCLAW_BIN_DIR/../lib/node_modules/openclaw/dist"
  else
    OPENCLAW_DIST="$HOME/.npm-global/lib/node_modules/openclaw/dist"
  fi
fi

PATCHED_PROMPT=0
for PI_EMBEDDED in "$OPENCLAW_DIST"/pi-embedded-*.js; do
  [ -f "$PI_EMBEDDED" ] || continue

  # Idempotency: skip if already patched
  if grep -q 'hookResult\.prompt' "$PI_EMBEDDED" 2>/dev/null; then
    echo "  $(basename "$PI_EMBEDDED"): prompt override already patched — skipping."
    PATCHED_PROMPT=1
    continue
  fi

  # Back up
  if [ ! -f "${PI_EMBEDDED}.shroud-backup" ]; then
    cp "$PI_EMBEDDED" "${PI_EMBEDDED}.shroud-backup"
  fi

  # Patch 1: resolvePromptBuildHookResult — add prompt field to return object
  # Before: return { systemPrompt: promptBuildResult?.systemPrompt ...
  # After:  return { prompt: ..., systemPrompt: ...
  sed -i.tmp 's/systemPrompt: promptBuildResult?.systemPrompt/prompt: promptBuildResult?.prompt ?? legacyResult?.prompt, systemPrompt: promptBuildResult?.systemPrompt/' "$PI_EMBEDDED"

  # Patch 2: effectivePrompt — use hookResult.prompt when present
  # Before: if (hookResult?.prependContext) { effectivePrompt = `${hookResult.prependContext}\n\n${params.prompt}`;
  # After:  if (hookResult?.prompt) { effectivePrompt = hookResult.prompt; } else if (hookResult?.prependContext) { ...
  sed -i.tmp 's/if (hookResult?.prependContext) {/if (hookResult?.prompt) { effectivePrompt = hookResult.prompt; } else if (hookResult?.prependContext) {/g' "$PI_EMBEDDED"

  rm -f "${PI_EMBEDDED}.tmp"

  if grep -q 'hookResult\.prompt' "$PI_EMBEDDED" 2>/dev/null; then
    echo "  $(basename "$PI_EMBEDDED"): patched prompt override ✓"
    PATCHED_PROMPT=1
  else
    echo "  WARNING: $(basename "$PI_EMBEDDED"): prompt override patch FAILED — review manually"
  fi
done

if [ "$PATCHED_PROMPT" = "0" ]; then
  echo "Warning: No pi-embedded files found or patched for prompt override."
fi

# ---------------------------------------------------------------------------
# Clear Node.js V8 compile cache so the patched file is loaded from disk.
# Node 22+ caches compiled ESM bytecode; without clearing, the old unpatched
# version is loaded from cache even after the file changes.
# ---------------------------------------------------------------------------
NODE_CACHE_DIR="${NODE_COMPILE_CACHE:-/tmp/node-compile-cache}"
if [ -d "$NODE_CACHE_DIR" ]; then
  rm -rf "$NODE_CACHE_DIR/$(node -e 'process.stdout.write(process.versions.v8.split(".").slice(0,2).join("."))')"-* 2>/dev/null || true
  # Fallback: remove uid-specific cache dirs
  for d in "$NODE_CACHE_DIR"/v*-"$(id -u)" "$NODE_CACHE_DIR"/v*; do
    rm -rf "$d" 2>/dev/null || true
  done
  echo "Cleared Node.js compile cache."
fi

echo "Restart OpenClaw to pick up changes."
