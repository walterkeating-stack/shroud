/**
 * Preload script that patches @slack/web-api WebClient to use a mock Slack server.
 * Usage: NODE_OPTIONS="--require /path/to/intercept.cjs" openclaw gateway
 *
 * Reads MOCK_SLACK_PORT from environment.
 * Patches WebClient.js in the OpenClaw Slack extension to read slackApiUrl
 * from MOCK_SLACK_URL environment variable.
 */

const MOCK_PORT = process.env.MOCK_SLACK_PORT;
if (!MOCK_PORT) return;

const fs = require('fs');
const path = require('path');

// Find and patch the WebClient.js file
const candidates = [
  // OpenClaw 2026.3.24 path
  path.join(process.env.NODE_PATH || '', 'openclaw', 'dist', 'extensions', 'slack', 'node_modules', '@slack', 'web-api', 'dist', 'WebClient.js'),
];

for (const candidate of candidates) {
  if (!fs.existsSync(candidate)) continue;

  let code = fs.readFileSync(candidate, 'utf-8');
  if (code.includes('MOCK_SLACK_URL')) continue; // already patched

  // Replace the default slackApiUrl with an env var check
  code = code.replace(
    "slackApiUrl = 'https://slack.com/api/'",
    "slackApiUrl = process.env.MOCK_SLACK_URL || 'https://slack.com/api/'"
  );
  fs.writeFileSync(candidate, code);
  break;
}
