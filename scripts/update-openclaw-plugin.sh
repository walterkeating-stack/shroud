#!/usr/bin/env bash
# Update shroud-privacy plugin on OpenClaw to the latest npm version.
#
# OpenClaw's `plugins install` won't overwrite an existing plugin directory,
# so this script removes the old install, reinstalls from npm, re-applies your
# existing plugin config, and restarts the gateway.
#
# Usage:
#   bash scripts/update-openclaw-plugin.sh            # update to latest
#   bash scripts/update-openclaw-plugin.sh 2.0.1      # update to specific version
set -euo pipefail

PLUGIN_NAME="shroud-privacy"
EXT_DIR="$HOME/.openclaw/extensions/$PLUGIN_NAME"
CONFIG_FILE="$HOME/.openclaw/openclaw.json"
VERSION="${1:-}"

# Check prerequisites
if ! command -v openclaw &>/dev/null; then
  echo "Error: openclaw not found in PATH" >&2
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "Error: jq is required (apt install jq)" >&2
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Error: OpenClaw config not found at $CONFIG_FILE" >&2
  exit 1
fi

# Save current plugin config (the user's custom settings)
SAVED_CONFIG=$(jq -r ".plugins.entries.\"$PLUGIN_NAME\" // empty" "$CONFIG_FILE")
if [ -n "$SAVED_CONFIG" ]; then
  echo "Saved existing plugin config."
else
  echo "No existing plugin config found — will use defaults."
fi

# Show current version
if [ -f "$EXT_DIR/package.json" ]; then
  OLD_VERSION=$(jq -r '.version' "$EXT_DIR/package.json")
  echo "Current version: $OLD_VERSION"
else
  echo "No existing install found."
fi

# Remove old extension directory
if [ -d "$EXT_DIR" ]; then
  echo "Removing old install at $EXT_DIR..."
  rm -rf "$EXT_DIR"
fi

# Remove stale install record so config validation doesn't block
# (openclaw plugins install will re-add it)
TEMP_CONFIG=$(mktemp)
jq "del(.plugins.installs.\"$PLUGIN_NAME\")" "$CONFIG_FILE" > "$TEMP_CONFIG"
mv "$TEMP_CONFIG" "$CONFIG_FILE"

# Install from npm
SPEC="$PLUGIN_NAME"
if [ -n "$VERSION" ]; then
  SPEC="${PLUGIN_NAME}@${VERSION}"
fi
echo "Installing $SPEC from npm..."
openclaw plugins install "$SPEC"

# Re-apply saved config (openclaw install resets to {enabled: true})
if [ -n "$SAVED_CONFIG" ]; then
  echo "Restoring plugin config..."
  TEMP_CONFIG=$(mktemp)
  jq ".plugins.entries.\"$PLUGIN_NAME\" = $SAVED_CONFIG" "$CONFIG_FILE" > "$TEMP_CONFIG"
  mv "$TEMP_CONFIG" "$CONFIG_FILE"
fi

# Show new version
if [ -f "$EXT_DIR/package.json" ]; then
  NEW_VERSION=$(jq -r '.version' "$EXT_DIR/package.json")
  echo "Updated to version: $NEW_VERSION"
fi

# Restart gateway
echo "Restarting OpenClaw gateway..."
openclaw gateway restart 2>/dev/null || openclaw gateway stop 2>/dev/null && openclaw gateway start 2>/dev/null

echo "Done. Plugin updated and gateway restarted."
