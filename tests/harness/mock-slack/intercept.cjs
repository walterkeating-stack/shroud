/**
 * Preload script that patches @slack/web-api WebClient to use a mock Slack server.
 * Usage: NODE_OPTIONS="--require /path/to/intercept.cjs" openclaw gateway
 *
 * Reads MOCK_SLACK_PORT and MOCK_SLACK_URL from environment.
 * Patches WebClient.js constructor default to use MOCK_SLACK_URL env var.
 */

const MOCK_PORT = process.env.MOCK_SLACK_PORT;
const MOCK_URL = process.env.MOCK_SLACK_URL;
if (!MOCK_PORT || !MOCK_URL) return;

const fs = require('fs');
const path = require('path');

// Find and patch the WebClient.js file — check both local and global npm paths
const candidates = [
  // Local sandbox install
  path.join(process.env.NODE_PATH || '', 'openclaw', 'dist', 'extensions', 'slack', 'node_modules', '@slack', 'web-api', 'dist', 'WebClient.js'),
  // Docker global install
  '/usr/local/lib/node_modules/openclaw/dist/extensions/slack/node_modules/@slack/web-api/dist/WebClient.js',
];

for (const candidate of candidates) {
  if (!fs.existsSync(candidate)) continue;

  let code = fs.readFileSync(candidate, 'utf-8');
  if (code.includes('MOCK_SLACK_URL')) continue; // already patched

  // Replace the default slackApiUrl parameter in the WebClient constructor.
  // This single replace covers all WebClient instances (including those created by Bolt).
  code = code.replace(
    "slackApiUrl = 'https://slack.com/api/'",
    "slackApiUrl = (process.env.MOCK_SLACK_URL || 'https://slack.com/api/')"
  );

  fs.writeFileSync(candidate, code);
  break;
}
