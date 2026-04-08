#!/bin/bash
# Run Shroud compatibility test against a single OpenClaw version.
# Both Shroud and OpenClaw are installed from npm — no local build.
#
# Usage:
#   bash compat/run-compat.sh 2026.3.24
#   bash compat/run-compat.sh latest
#   bash compat/run-compat.sh 2026.3.24 --rebuild-base
#   bash compat/run-compat.sh 2026.3.28 --sandbox        # sandbox exec tests
#   SHROUD_VERSION=2.2.8 bash compat/run-compat.sh latest
#
set -euo pipefail

OC_VERSION="${1:?Usage: run-compat.sh <openclaw-version> [--rebuild-base|--sandbox]}"
shift
REBUILD_BASE=""
SANDBOX=""
LIFECYCLE=""
for arg in "$@"; do
  case $arg in
    --rebuild-base) REBUILD_BASE=1 ;;
    --sandbox) SANDBOX=1 ;;
    --lifecycle) LIFECYCLE=1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Resolve "latest" to actual version
if [ "${OC_VERSION}" = "latest" ]; then
  OC_VERSION=$(npm view openclaw version 2>/dev/null)
  echo "Resolved 'latest' to OpenClaw ${OC_VERSION}"
fi

BASE_TAG="shroud-compat-base:oc-${OC_VERSION}"
TEST_TAG="shroud-compat:oc-${OC_VERSION}"
SANDBOX_TAG="shroud-compat-sandbox:oc-${OC_VERSION}"
NETWORK="shroud-compat-net"
CURRENT_CONTAINER=""

cleanup() {
  local cleanup_exit="${1:-$?}"

  echo ""
  echo "Cleaning up..."

  if [ -n "${CURRENT_CONTAINER}" ]; then
    docker rm -f "${CURRENT_CONTAINER}" 2>/dev/null && echo "  Removed container: ${CURRENT_CONTAINER}" || true
  fi

  docker network rm "${NETWORK}" 2>/dev/null && echo "  Removed network: ${NETWORK}" || true

  docker images --format '{{.Repository}}:{{.Tag}}' \
    | grep -E '^shroud-compat(:|$)|^shroud-compat-base(:|$)|^shroud-compat-sandbox(:|$)' \
    | xargs -r docker rmi -f >/dev/null 2>&1 || true
  echo "  Removed compat images"

  docker ps -a --filter "name=openclaw-sbx-" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null \
    && echo "  Removed stale OC sandbox containers" || true

  return "${cleanup_exit}"
}

trap 'cleanup $?' EXIT

cd "${REPO_ROOT}"

# ── Step 1: Pack local Shroud build ──
echo "Packing local Shroud build..."
npm run build --silent
rm -f shroud-privacy-*.tgz
npm pack --silent
SHROUD_TGZ=$(ls shroud-privacy-*.tgz 2>/dev/null | head -1)
if [ -z "${SHROUD_TGZ}" ]; then
  echo "ERROR: npm pack failed — no tarball found"
  exit 1
fi
SHROUD_VERSION=$(node -e "console.log(require('./package.json').version)")
echo "Shroud version: ${SHROUD_VERSION} (local build)"
[ -n "${SANDBOX}" ] && echo "Mode: SANDBOX (rootless Docker)"
[ -n "${LIFECYCLE}" ] && echo "Mode: LIFECYCLE (long-running agent tests)"
[ -n "${SHROUD_SCENARIO:-}" ] && echo "Mode: SCENARIO filter (${SHROUD_SCENARIO})"

# ── Step 2: Build/reuse base image ──
if [ -n "${REBUILD_BASE}" ] || \
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
  -t "${TEST_TAG}" \
  -f compat/Dockerfile.test .

# ── Step 3b: Build sandbox image (if --sandbox) ──
if [ -n "${SANDBOX}" ]; then
  echo "Building sandbox image (rootless Docker)..."
  docker build \
    --build-arg "OC_VERSION=${OC_VERSION}" \
    -t "${SANDBOX_TAG}" \
    -f compat/Dockerfile.sandbox .
fi

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
[ -n "${SANDBOX}" ] && echo "(sandbox mode enabled)"
echo "============================================="

if [ -n "${SANDBOX}" ]; then
  CURRENT_CONTAINER="shroud-compat-sandbox-${OC_VERSION}"
  # Sandbox: Docker-in-Docker needs privileged mode for dockerd.
  # This is safe because:
  #   1. Network is --internal (zero egress, no packets leave)
  #   2. Container is ephemeral (--rm)
  #   3. No volume mounts to host filesystem
  #   4. Memory and CPU are capped
  docker run --rm \
    --network "${NETWORK}" \
    --memory 2g \
    --cpus 2 \
    --privileged \
    --name "${CURRENT_CONTAINER}" \
    "${SANDBOX_TAG}"
  EXIT_CODE=$?
else
  MEMORY_LIMIT="1g"
  [ -n "${LIFECYCLE}" ] && MEMORY_LIMIT="4g"
  DOCKER_ENV_ARGS=()
  if [ -n "${LIFECYCLE}" ]; then
    DOCKER_ENV_ARGS+=(-e SHROUD_LIFECYCLE=1)
  fi
  if [ -n "${SHROUD_SCENARIO:-}" ]; then
    DOCKER_ENV_ARGS+=(-e "SHROUD_SCENARIO=${SHROUD_SCENARIO}")
  fi
  CURRENT_CONTAINER="shroud-compat-${OC_VERSION}"
  docker run --rm \
    --network "${NETWORK}" \
    --memory "${MEMORY_LIMIT}" \
    --cpus 2 \
    --name "${CURRENT_CONTAINER}" \
    "${DOCKER_ENV_ARGS[@]}" \
    "${TEST_TAG}"
  EXIT_CODE=$?
fi

if [ ${EXIT_CODE} -eq 0 ]; then
  echo "OpenClaw ${OC_VERSION}: PASS"
else
  echo "OpenClaw ${OC_VERSION}: FAIL (exit code ${EXIT_CODE})"
  exit ${EXIT_CODE}
fi
