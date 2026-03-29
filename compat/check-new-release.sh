#!/bin/bash
# Check if a new OpenClaw version has been released since our last check.
# Designed to run on a cron schedule (e.g., daily).
#
# Outputs: "new:<version>" if new, "current" if up to date
# Exit 0 in both cases; exit 1 on error
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSIONS_FILE="${SCRIPT_DIR}/versions.json"

# Get latest from npm
LATEST=$(npm view openclaw version 2>/dev/null)
if [ -z "${LATEST}" ]; then
  echo "ERROR: Failed to query npm for openclaw version"
  exit 1
fi

# Get our latest known version
OUR_LATEST=$(node -e "
  const v = require('${VERSIONS_FILE}');
  const latest = v.versions[v.versions.length - 1];
  console.log(latest.version);
")

if [ "${LATEST}" = "${OUR_LATEST}" ]; then
  echo "current"
  exit 0
fi

# Check if it's actually newer (npm might return same version)
IS_NEWER=$(node -e "
  const a = '${LATEST}'.split('.').map(Number);
  const b = '${OUR_LATEST}'.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i]||0) > (b[i]||0)) { console.log('yes'); process.exit(); }
    if ((a[i]||0) < (b[i]||0)) { console.log('no'); process.exit(); }
  }
  console.log('no');
")

if [ "${IS_NEWER}" = "yes" ]; then
  echo "new:${LATEST}"
else
  echo "current"
fi
