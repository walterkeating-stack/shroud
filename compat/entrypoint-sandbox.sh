#!/bin/bash
# Sandbox entrypoint: starts rootless Docker daemon, then delegates
# to the standard entrypoint for OpenClaw + Shroud setup and tests.
set -euo pipefail

echo "=== Sandbox Mode ==="

# ── Start rootless Docker daemon ──
# Create XDG_RUNTIME_DIR for rootless Docker
mkdir -p /run/user/1000
chown node:node /run/user/1000
chmod 700 /run/user/1000

echo "Starting rootless Docker daemon..."
# Start dockerd-rootless as node in background
su - node -c "
  export XDG_RUNTIME_DIR=/run/user/1000
  export DOCKER_HOST=unix:///run/user/1000/docker.sock
  dockerd-rootless-setuptool.sh install 2>/dev/null || true
  nohup dockerd-rootless.sh >/tmp/dockerd.log 2>&1 &
"

# Wait for Docker daemon to be ready (max 30s)
echo "Waiting for Docker daemon..."
export DOCKER_HOST=unix:///run/user/1000/docker.sock
for i in $(seq 1 30); do
  if su - node -c "DOCKER_HOST=unix:///run/user/1000/docker.sock docker info" >/dev/null 2>&1; then
    echo "Docker daemon ready (${i}s)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Docker daemon failed to start after 30s"
    cat /tmp/dockerd.log 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Export Docker socket path for OpenClaw
export DOCKER_HOST=unix:///run/user/1000/docker.sock

# ── Delegate to standard entrypoint ──
# The standard entrypoint handles:
#   - /etc/hosts redirects for mock servers
#   - OpenClaw state dirs
#   - Plugin install
#   - WhatsApp channel + mock auth
#   - Test harness execution
echo "Delegating to standard entrypoint..."
exec /shroud/entrypoint.sh
