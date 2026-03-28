#!/bin/bash
# Run Shroud compatibility test against a single OpenClaw version.
# Both Shroud and OpenClaw are installed from npm — no local build.
#
# Usage:
#   bash compat/run-compat.sh 2026.3.24
#   bash compat/run-compat.sh latest
#   bash compat/run-compat.sh 2026.3.24 --rebuild-base
#   SHROUD_VERSION=2.2.8 bash compat/run-compat.sh latest  # specific Shroud version
#
set -euo pipefail

OC_VERSION="${1:?Usage: run-compat.sh <openclaw-version> [--rebuild-base]}"
REBUILD_BASE="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Resolve "latest" to actual version
if [ "${OC_VERSION}" = "latest" ]; then
  OC_VERSION=$(npm view openclaw version 2>/dev/null)
  echo "Resolved 'latest' to OpenClaw ${OC_VERSION}"
fi

BASE_TAG="shroud-compat-base:oc-${OC_VERSION}"
TEST_TAG="shroud-compat:oc-${OC_VERSION}"
NETWORK="shroud-compat-net"

cd "${REPO_ROOT}"

# ── Step 1: Resolve Shroud version ──
SHROUD_VERSION="${SHROUD_VERSION:-latest}"
if [ "${SHROUD_VERSION}" = "latest" ]; then
  SHROUD_VERSION=$(npm view shroud-privacy version 2>/dev/null)
  echo "Resolved Shroud 'latest' to ${SHROUD_VERSION}"
fi
echo "Shroud version: ${SHROUD_VERSION} (from npm)"

# ── Step 2: Build/reuse base image ──
if [ "${REBUILD_BASE}" = "--rebuild-base" ] || \
   ! docker image inspect "${BASE_TAG}" &>/dev/null; then
  echo "Building base image for OpenClaw ${OC_VERSION}..."
  docker build \
    --build-arg "OC_VERSION=${OC_VERSION}" \
    -t "${BASE_TAG}" \
    -f compat/Dockerfile.base .
else
  echo "Reusing cached base image: ${BASE_TAG}"
fi

# ── Step 3: Build test image ──
echo "Building test image..."
docker build \
  --build-arg "OC_VERSION=${OC_VERSION}" \
  --build-arg "SHROUD_VERSION=${SHROUD_VERSION}" \
  -t "${TEST_TAG}" \
  -f compat/Dockerfile.test .

# ── Step 4: Create isolated Docker network ──
# --internal: full networking inside the container, zero external routing.
# No packets can leave. Mock servers run on localhost inside the container.
if ! docker network inspect "${NETWORK}" &>/dev/null; then
  docker network create --internal "${NETWORK}"
  echo "Created isolated network: ${NETWORK}"
fi

# ── Step 5: Run tests ──
echo ""
echo "Running compat tests against OpenClaw ${OC_VERSION}..."
echo "============================================="

docker run --rm \
  --network "${NETWORK}" \
  --memory 1g \
  --cpus 2 \
  --name "shroud-compat-${OC_VERSION}" \
  "${TEST_TAG}"

echo ""
echo "OpenClaw ${OC_VERSION}: PASS"
