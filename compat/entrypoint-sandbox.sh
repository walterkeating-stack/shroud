#!/bin/bash
# Sandbox entrypoint: starts Docker daemon (root), then delegates
# to the standard entrypoint for OpenClaw + Shroud setup and tests.
#
# We use regular dockerd (not rootless) because rootless Docker needs
# TUN devices and slirp4netns networking which conflicts with --internal
# Docker networks. The container already has SYS_ADMIN cap and the
# --internal network prevents any egress, so running dockerd as root
# inside the container is safe for testing purposes.
set -euo pipefail

echo "=== Sandbox Mode ==="

# ── Start Docker daemon ──
echo "Starting Docker daemon..."
# Use vfs storage driver (no overlayfs kernel module needed in nested containers)
dockerd --storage-driver=vfs --iptables=false --bridge=none \
  --data-root=/tmp/docker-data \
  >/tmp/dockerd.log 2>&1 &

# Wait for Docker daemon to be ready (max 30s)
echo "Waiting for Docker daemon..."
export DOCKER_HOST=unix:///var/run/docker.sock
for i in $(seq 1 30); do
  if docker info >/dev/null 2>&1; then
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

docker info --format '  Storage: {{.Driver}}, Containers: {{.Containers}}'

# ── Delegate to standard entrypoint ──
# The standard entrypoint handles:
#   - /etc/hosts redirects for mock servers
#   - OpenClaw state dirs
#   - Plugin install
#   - WhatsApp channel + mock auth
#   - Test harness execution
echo "Delegating to standard entrypoint..."
exec /shroud/entrypoint.sh
