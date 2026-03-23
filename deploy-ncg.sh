#!/usr/bin/env bash
# Build and deploy shroud to local NCG plugin system (no npm publish needed)
set -e
cd "$(dirname "$0")"
npm run build
python3 "$HOME/ncg/agent.py" plugin install .
echo "Deployed. Restart NCG agent to pick up changes."
