#!/usr/bin/env bash
# Build and deploy shroud to local OpenClaw extension dir (no npm publish needed)
set -e
cd "$(dirname "$0")"
npm run build
cp -r dist package.json openclaw.plugin.json /home/ka/.openclaw/extensions/openclaw-shroud/
echo "Deployed. Restart OpenClaw to pick up changes."
