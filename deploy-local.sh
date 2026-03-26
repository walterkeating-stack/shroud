#!/usr/bin/env bash
# Build, test, and deploy Shroud to local OpenClaw extension dir.
#
# Steps:
#   1. Build (tsc)
#   2. Run fetch response deobfuscation + Slack chain tests
#   3. Copy to ~/.openclaw/extensions/shroud-privacy/
#   4. Clear V8 compile cache
#   5. Verify round-trip obfuscation/deobfuscation
#
# Usage:
#   ./deploy-local.sh              # build + test + deploy
#   ./deploy-local.sh --skip-test  # build + deploy only
set -e
cd "$(dirname "$0")"

# ── Build ──
echo "Building..."
npm run build

# ── Test ──
if [ "$1" != "--skip-test" ]; then
  echo ""
  echo "Running tests..."
  npx vitest run tests/fetch-response-deob.test.ts tests/slack-chain.test.ts --reporter=verbose
  echo ""
  echo "All tests passed."
fi

# ── Deploy ──
DEST="$HOME/.openclaw/extensions/shroud-privacy"
mkdir -p "$DEST"
# Remove stale files from previous versions
rm -f "$DEST/fetch-preload.cjs" 2>/dev/null || true
cp -r dist package.json openclaw.plugin.json "$DEST/"
echo "Deployed to $DEST"

# ── Clear V8 compile cache ──
NODE_CACHE_DIR="${NODE_COMPILE_CACHE:-/tmp/node-compile-cache}"
if [ -d "$NODE_CACHE_DIR" ]; then
  for d in "$NODE_CACHE_DIR"/v*-"$(id -u)" "$NODE_CACHE_DIR"/v*; do
    rm -rf "$d" 2>/dev/null || true
  done
  sudo rm -rf "$NODE_CACHE_DIR"/v*-0 2>/dev/null || true
  echo "Cleared Node.js compile cache."
fi

# ── Post-install verification ──
echo ""
echo "Verifying fetch intercept + deobfuscation..."
node -e "
  const { resolve } = require('path');
  const dist = resolve('$DEST', 'dist');
  import('file://' + dist + '/hooks.js').then(({ registerHooks }) => {
    const handlers = {};
    const api = {
      on(e, h) { handlers[e] = h; },
      registerTool() {},
      logger: { info() {}, warn() {}, error() {} },
    };
    import('file://' + dist + '/obfuscator.js').then(({ Obfuscator }) => {
      import('file://' + dist + '/config.js').then(({ resolveConfig }) => {
        const config = resolveConfig({ secretKey: 'deploy-verify-key-1234567890' });
        const obf = new Obfuscator(config);
        registerHooks(api, obf);

        // Check globalThis.__shroudDeobfuscate
        if (typeof globalThis.__shroudDeobfuscate !== 'function') {
          console.error('  FAIL: __shroudDeobfuscate not registered');
          process.exit(1);
        }
        console.log('  OK: globalThis.__shroudDeobfuscate registered');

        // Check fetch intercept is patched
        if (!globalThis.__shroudFetchPatched) {
          console.error('  FAIL: fetch intercept not installed');
          process.exit(1);
        }
        console.log('  OK: fetch intercept installed');

        // Round-trip test
        const r = obf.obfuscate('deploy-verify@acme.com');
        const fake = r.mappingsUsed['deploy-verify@acme.com'];
        if (!fake) { console.error('  FAIL: obfuscator did not detect email'); process.exit(1); }
        const deob = globalThis.__shroudDeobfuscate('Contact ' + fake);
        if (deob.includes('deploy-verify@acme.com')) {
          console.log('  OK: round-trip deobfuscation works');
        } else {
          console.error('  FAIL: deobfuscation returned: ' + deob + ' (fake was: ' + fake + ')');
          process.exit(1);
        }
      });
    });
  }).catch(e => { console.error('  FAIL:', e.message); process.exit(1); });
"

echo ""
echo "Deploy complete. Restart OpenClaw to pick up changes:"
echo "  systemctl --user restart openclaw-gateway"
echo ""
echo "No OpenClaw patches required — Shroud handles obfuscation and"
echo "deobfuscation entirely through the fetch intercept."
