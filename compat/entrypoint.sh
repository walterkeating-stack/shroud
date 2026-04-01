#!/bin/bash
set -euo pipefail

OC_VERSION=$(cat /shroud/.oc-version)
SHROUD_VERSION="${SHROUD_VERSION:-unknown}"

echo "=== Shroud Compat Test: OpenClaw ${OC_VERSION} ==="
echo "Shroud version: ${SHROUD_VERSION} (from npm)"
echo "Node version: $(node --version)"
echo ""

# ── /etc/hosts redirects for channel E2E ──
# Redirect external API hostnames to localhost where mock servers listen.
# This makes the real Slack/WhatsApp SDKs resolve to our mock servers.
echo "127.0.0.1 slack.com api.slack.com" >> /etc/hosts
echo "127.0.0.1 web.whatsapp.com" >> /etc/hosts
echo "Configured /etc/hosts for channel E2E mocking"

# ── Setup OpenClaw state ──
STATE_DIR="/shroud/state"
mkdir -p "${STATE_DIR}/extensions" "${STATE_DIR}/logs" "${STATE_DIR}/workspace" \
         "${STATE_DIR}/credentials" "${STATE_DIR}/agents" \
         "${STATE_DIR}/channels/whatsapp/auth"

export HOME=/shroud
export OPENCLAW_STATE_DIR="${STATE_DIR}"

# Install plugin — same path real users hit
echo "Installing Shroud plugin..."
SHROUD_PKG=$(npm root -g)/shroud-privacy
# Disable dashboard during install — OC loads plugin to verify, and the HTTP
# server would keep the install process alive forever.
SHROUD_DASHBOARD=false openclaw plugins install "${SHROUD_PKG}" --dangerously-force-unsafe-install 2>&1

# Add WhatsApp channel (uses Baileys intercept in Docker)
echo "Adding WhatsApp channel..."
openclaw channels add --channel whatsapp --auth-dir "${STATE_DIR}/channels/whatsapp/auth" 2>&1 || true

# Pre-populate mock WhatsApp auth state so the extension thinks we're paired
WA_AUTH="${STATE_DIR}/channels/whatsapp/auth"
cat > "${WA_AUTH}/creds.json" <<'WAEOF'
{
  "noiseKey": {"private": {"type": "Buffer", "data": [0]}, "public": {"type": "Buffer", "data": [0]}},
  "pairingEphemeralKeyPair": {"private": {"type": "Buffer", "data": [0]}, "public": {"type": "Buffer", "data": [0]}},
  "signedIdentityKey": {"private": {"type": "Buffer", "data": [0]}, "public": {"type": "Buffer", "data": [0]}},
  "signedPreKey": {"keyPair": {"private": {"type": "Buffer", "data": [0]}, "public": {"type": "Buffer", "data": [0]}}, "signature": {"type": "Buffer", "data": [0]}, "keyId": 1},
  "registrationId": 1,
  "advSecretKey": "AAAAAAAAAAAAAAAAAAAAAA==",
  "me": {"id": "353850000000@s.whatsapp.net", "name": "MockBot"},
  "account": {"details": "mock", "accountSignature": "mock", "deviceSignature": "mock"},
  "signalIdentities": [],
  "registered": true,
  "platform": "smba",
  "lastAccountSyncTimestamp": 0
}
WAEOF
echo "WhatsApp mock auth state created"

# ── Run the test harness ──
export OPENCLAW_BIN=$(which openclaw)
export OPENCLAW_CONFIG="${STATE_DIR}/openclaw.json"
export SHROUD_TEST_DOCKER=1

echo ""
LIFECYCLE_FLAG=""
if [ "${SHROUD_LIFECYCLE:-}" = "1" ]; then
  LIFECYCLE_FLAG="--lifecycle"
  echo "Running OpenClaw sandbox tests (with lifecycle tests)..."
else
  echo "Running OpenClaw sandbox tests..."
fi
node /shroud/tests/harness/run.mjs --openclaw --verbose ${LIFECYCLE_FLAG}

EXIT_CODE=$?

echo ""
echo "=== Results ==="
exit ${EXIT_CODE}
