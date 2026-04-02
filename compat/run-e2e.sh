#!/bin/bash
# Thin wrapper: build Shroud, pack, invoke shroud-e2e harness.
#
# Usage:
#   bash compat/run-e2e.sh latest              # Test against latest OC
#   bash compat/run-e2e.sh 2026.3.28           # Test against specific OC
#   bash compat/run-e2e.sh latest --sandbox    # Sandbox mode
#
# Requires shroud-e2e repo alongside this repo (../shroud-e2e).
# Override with SHROUD_E2E_PATH env var.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
E2E_DIR="${SHROUD_E2E_PATH:-$(cd "${REPO_ROOT}/../shroud-e2e" 2>/dev/null && pwd)}"

if [ ! -f "${E2E_DIR}/compat/run-compat.sh" ]; then
  echo "ERROR: shroud-e2e repo not found at ${E2E_DIR}"
  echo "  Clone it:  git clone git@github.com:wkeything/shroud-e2e.git ../shroud-e2e"
  echo "  Or set:    SHROUD_E2E_PATH=/path/to/shroud-e2e"
  exit 1
fi

cd "${REPO_ROOT}"

# Build and pack
echo "Building Shroud..."
npm run build --silent

echo "Packing tarball..."
rm -f shroud-privacy-*.tgz
npm pack --silent
SHROUD_TGZ="$(pwd)/$(ls -t shroud-privacy-*.tgz | head -1)"
echo "Packed: ${SHROUD_TGZ}"

# Pass branch-specific scenarios if they exist
SCENARIOS_FLAG=""
if [ -d "${REPO_ROOT}/e2e-scenarios" ]; then
  SCENARIOS_FLAG="${REPO_ROOT}/e2e-scenarios"
  echo "Branch scenarios: ${SCENARIOS_FLAG}"
fi

# Invoke shroud-e2e
export SHROUD_TGZ
export SHROUD_SCENARIOS="${SCENARIOS_FLAG}"
exec bash "${E2E_DIR}/compat/run-compat.sh" "$@"
