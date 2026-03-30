#!/bin/bash
# Deploy Shroud with security extension enabled on local OpenClaw.
#
# Usage:
#   bash deploy-security.sh              # Flag mode (detect + log, don't block)
#   bash deploy-security.sh block        # Block mode (reject high-severity injections)
#   bash deploy-security.sh off          # Disable security, just privacy obfuscation
#
# Prerequisites:
#   - OpenClaw installed (openclaw command available)
#   - Shroud installed as plugin (openclaw plugins install shroud-privacy)
#   - npm run build (if running from source)
#
# What it does:
#   1. Builds Shroud from source
#   2. Installs the local build as OpenClaw plugin
#   3. Sets security extension environment variables
#   4. Starts OpenClaw with dashboard enabled
#   5. Opens dashboard URL
#
set -euo pipefail

MODE="${1:-flag}"
DASHBOARD_PORT="${SHROUD_DASHBOARD_PORT:-9380}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================="
echo "  Shroud Security Extension — Local Deploy"
echo "============================================="
echo ""
echo "  Mode:        ${MODE}"
echo "  Dashboard:   http://127.0.0.1:${DASHBOARD_PORT}"
echo ""

# ── Step 1: Build ──
echo "[1/4] Building Shroud..."
cd "${SCRIPT_DIR}"
npm run build --silent

# ── Step 2: Install plugin ──
echo "[2/4] Installing Shroud plugin..."
SHROUD_PKG="${SCRIPT_DIR}"
openclaw plugins install "${SHROUD_PKG}" 2>&1 || {
  echo "  (plugin may already be installed, continuing...)"
}

# ── Step 3: Set environment ──
echo "[3/4] Configuring security extension..."

# Core security
export SHROUD_INJECTION_DETECTION="${MODE}"
export SHROUD_INJECTION_SCAN_RESPONSES="true"
export SHROUD_INJECTION_MIN_SEVERITY="low"

# Behavioural profiling
export SHROUD_PROFILING_ENABLED="true"
export SHROUD_PROFILING_MODE="learning"

# Dashboard
export SHROUD_DASHBOARD="true"
export SHROUD_DASHBOARD_PORT="${DASHBOARD_PORT}"

# SIEM logging (local JSONL file)
export SHROUD_SIEM_JSONL_PATH="/tmp/shroud-security-events.jsonl"

# Optional: Tailscale accessible
export SHROUD_DASHBOARD_BIND="0.0.0.0"

echo "  SHROUD_INJECTION_DETECTION=${MODE}"
echo "  SHROUD_PROFILING_ENABLED=true"
echo "  SHROUD_DASHBOARD=true (port ${DASHBOARD_PORT})"
echo "  SHROUD_SIEM_JSONL_PATH=/tmp/shroud-security-events.jsonl"
echo ""

# ── Step 4: Start OpenClaw ──
echo "[4/4] Starting OpenClaw with security extension..."
echo ""
echo "============================================="
echo "  Dashboard: http://127.0.0.1:${DASHBOARD_PORT}"
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -n "${TAILSCALE_IP}" ]; then
  echo "  Tailscale: http://${TAILSCALE_IP}:${DASHBOARD_PORT}"
fi
echo "  SIEM log:  /tmp/shroud-security-events.jsonl"
echo "  Mode:      ${MODE}"
echo "============================================="
echo ""
echo "  Security features active:"
echo "    ✓ 109 injection signatures (14 languages)"
echo "    ✓ 22 tool call guard patterns"
echo "    ✓ Token smuggling detection"
echo "    ✓ Canary leak monitoring"
echo "    ✓ Behavioural profiling (learning mode)"
echo "    ✓ Per-agent WAF rules"
echo "    ✓ Real-time dashboard"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

# Start OpenClaw — it will load Shroud with the security env vars
exec openclaw start
