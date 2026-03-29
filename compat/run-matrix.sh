#!/bin/bash
# Run Shroud compatibility tests against all supported OpenClaw versions.
#
# Usage:
#   bash compat/run-matrix.sh              # all supported versions
#   bash compat/run-matrix.sh --latest 3   # only latest 3 versions
#   bash compat/run-matrix.sh --parallel   # run all in parallel
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${SCRIPT_DIR}/versions.json"

LATEST_N=""
PARALLEL=false
SANDBOX=""

# Interactive mode if no args provided
if [[ $# -eq 0 && -t 0 ]]; then
  echo "=== Shroud Compat Matrix ==="
  echo "  1) Current OpenClaw version only"
  echo "  2) Current + last 3 OpenClaw versions (backward compat)"
  echo ""
  read -rp "Choose [1/2]: " choice
  case $choice in
    1) LATEST_N=1 ;;
    2) LATEST_N=4 ;;
    *) echo "Invalid choice"; exit 1 ;;
  esac
  echo ""
else
  while [[ $# -gt 0 ]]; do
    case $1 in
      --latest) LATEST_N="$2"; shift 2 ;;
      --parallel) PARALLEL=true; shift ;;
      --sandbox) SANDBOX="--sandbox"; shift ;;
      *) echo "Unknown arg: $1"; exit 1 ;;
    esac
  done
fi

# Read versions from registry
VERSIONS=$(node -e "
  const v = require('${VERSIONS_FILE}');
  const supported = v.versions
    .filter(x => x.status !== 'retired')
    .map(x => x.version);
  const n = ${LATEST_N:-0};
  const list = n > 0 ? supported.slice(-n) : supported;
  console.log(list.join(' '));
")

echo "=== Shroud Compatibility Matrix ==="
echo "Versions: ${VERSIONS}"
echo ""

cd "${REPO_ROOT}"

RESULTS=()
FAILED=()

run_one() {
  local ver=$1
  echo "--- OpenClaw ${ver} ---"
  if bash compat/run-compat.sh "${ver}" ${SANDBOX}; then
    RESULTS+=("${ver}: PASS")
  else
    RESULTS+=("${ver}: FAIL")
    FAILED+=("${ver}")
  fi
}

if [ "${PARALLEL}" = true ]; then
  mkdir -p compat/logs
  PIDS=()
  for ver in ${VERSIONS}; do
    bash compat/run-compat.sh "${ver}" ${SANDBOX} &>"compat/logs/${ver}.log" &
    PIDS+=("$!:${ver}")
  done
  for entry in "${PIDS[@]}"; do
    PID="${entry%%:*}"
    VER="${entry##*:}"
    if wait "${PID}"; then
      RESULTS+=("${VER}: PASS")
    else
      RESULTS+=("${VER}: FAIL")
      FAILED+=("${VER}")
    fi
  done
else
  for ver in ${VERSIONS}; do
    run_one "${ver}"
  done
fi

echo ""
echo "=== Matrix Results ==="
for r in "${RESULTS[@]}"; do
  echo "  ${r}"
done

if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "FAILED: ${FAILED[*]}"
  exit 1
fi

echo ""
echo "All versions passed."

# ── Cleanup: keep only the 3 most recent base + test images ──
KEEP=3
echo ""
echo "Pruning compat images (keeping latest ${KEEP})..."

for prefix in shroud-compat-base shroud-compat; do
  IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' \
    | grep "^${prefix}:oc-" \
    | sort -k2 -r \
    | tail -n +$((KEEP + 1)) \
    | awk '{print $1}')
  for img in ${IMAGES}; do
    echo "  Removing ${img}"
    docker rmi "${img}" 2>/dev/null || true
  done
done
