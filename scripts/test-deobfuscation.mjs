#!/usr/bin/env node
/**
 * test-deobfuscation.mjs
 *
 * Test 1: Local obfuscate/deobfuscate round-trip through a simulated pi-ai
 *         AssistantMessageEventStream (character-by-character streaming),
 *         using the same buffered deobfuscation logic as hooks.ts.
 *
 * Test 2: End-to-end via the running OpenClaw gateway -- send a Slack message
 *         containing a known PII value and verify the response has the real
 *         value (i.e. Shroud deobfuscated it before delivery).
 *
 * Usage:  node scripts/test-deobfuscation.mjs
 * Exit:   0 = all pass, 1 = any failure
 */

import { Obfuscator } from "../dist/obfuscator.js";
import {
  AssistantMessageEventStream,
} from "/home/user/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const REAL_EMAIL = "jj@kk.net";
const SLACK_REAL_EMAIL = "testuser@example.net";
const SLACK_BOT_TOKEN =
  "SHROUD_TEST_SLACK_TOKEN";
const SLACK_CHANNEL = "C0AMN8NUXPZ";

function makeTestConfig() {
  return {
    secretKey: "test-secret-key-for-deobfuscation-script-0123456789ab",
    persistentSalt: "test-salt-42",
    minConfidence: 0.0,
    allowlist: [],
    denylist: [],
    canaryEnabled: false,
    canaryPrefix: "SHROUD-CANARY",
    auditEnabled: false,
    logMappings: false,
    customPatterns: [],
    verboseLogging: false,
    auditLogFormat: "human",
    auditIncludeProofHashes: false,
    auditHashSalt: "",
    auditHashTruncate: 12,
    auditMaxFakesSample: 0,
    detectorOverrides: {},
    tenantId: "",
    maxToolDepth: 10,
    lockedCategories: [],
    exposureWindow: 0,
    exposureThresholds: {},
    exposureGlobalThreshold: 0,
    policyFile: "",
    redactionLevel: "full",
    sharedStorePath: "",
    sharedStoreTtlMs: 0,
    provenanceTagging: false,
    sessionHandoff: false,
    dryRun: false,
    maxStoreMappings: 0,
  };
}

let failures = 0;

function pass(name) {
  console.log(`  PASS  ${name}`);
}
function fail(name, reason) {
  console.error(`  FAIL  ${name} -- ${reason}`);
  failures++;
}

// ---------------------------------------------------------------------------
// Test 1 -- Local round-trip with simulated streaming + hooks.ts deob logic
// ---------------------------------------------------------------------------
async function testLocalStreamDeobfuscation() {
  console.log("\n=== Test 1: Local EventStream round-trip ===\n");

  // 1. Create obfuscator and obfuscate the real email
  const config = makeTestConfig();
  const obfuscator = new Obfuscator(config);

  const inputText = `Please contact jj@kk.net for details.`;
  const result = obfuscator.obfuscate(inputText);

  const fakeEmail = result.mappingsUsed[REAL_EMAIL];
  if (!fakeEmail) {
    fail("obfuscation", `email "${REAL_EMAIL}" was not detected/mapped`);
    return;
  }
  console.log(`  Real email : ${REAL_EMAIL}`);
  console.log(`  Fake email : ${fakeEmail}`);
  console.log(`  Obfuscated : ${result.obfuscated}`);

  // 2. Install the same buffered deobfuscation hook that hooks.ts uses.
  //    This uses Symbol("shroudStreamBuf") matching hooks.ts, and the
  //    globalThis.__shroudStreamDeobfuscate function that pi-ai's
  //    EventStream.push() calls automatically.
  const SHROUD_BUF = Symbol("shroudStreamBuf");
  globalThis.__shroudStreamDeobfuscate = (stream, event) => {
    // Handle text_delta events (direct from pi-ai providers)
    if (event.type === "text_delta") {
      const chunk = typeof event.delta === "string" ? event.delta
        : typeof event.text === "string" ? event.text : null;
      if (chunk !== null) {
        let buf = stream[SHROUD_BUF];
        if (!buf) { buf = { raw: "", emitted: 0 }; stream[SHROUD_BUF] = buf; }
        buf.raw += chunk;
        const deob = obfuscator.deobfuscate(buf.raw);
        const newText = deob.slice(buf.emitted);
        buf.emitted = deob.length;
        if (newText !== chunk) {
          event = { ...event };
          if (typeof event.delta === "string") event.delta = newText;
          if (typeof event.text === "string") event.text = newText;
        }
      }
    }
    // Handle message_update with nested text_delta (from agent loop)
    else if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
      const nested = event.assistantMessageEvent;
      const chunk = typeof nested.delta === "string" ? nested.delta
        : typeof nested.text === "string" ? nested.text : null;
      if (chunk !== null) {
        let buf = stream[SHROUD_BUF];
        if (!buf) { buf = { raw: "", emitted: 0 }; stream[SHROUD_BUF] = buf; }
        buf.raw += chunk;
        const deob = obfuscator.deobfuscate(buf.raw);
        const newText = deob.slice(buf.emitted);
        buf.emitted = deob.length;
        if (newText !== chunk) {
          const patched = { ...nested };
          if (typeof nested.delta === "string") patched.delta = newText;
          if (typeof nested.text === "string") patched.text = newText;
          event = { ...event, assistantMessageEvent: patched };
        }
      }
    }
    // Reset buffer on stream end
    else if (event.type === "done" || event.type === "error" || event.type === "agent_end") {
      delete stream[SHROUD_BUF];
    }
    return event;
  };

  // 3. Build an AssistantMessageEventStream and push text_delta events
  //    character-by-character with the FAKE email (simulating LLM streaming).
  //    The push() method in pi-ai calls globalThis.__shroudStreamDeobfuscate
  //    automatically, so events are deobfuscated inline.
  const llmReply = `Sure, you can reach out to ${fakeEmail} anytime.`;
  const stream = new AssistantMessageEventStream();

  // Push characters asynchronously so the for-await consumer can interleave.
  const pushTask = (async () => {
    for (const ch of llmReply) {
      stream.push({ type: "text_delta", delta: ch, text: ch });
      // Yield to the event loop so the consumer can pick up events
      await new Promise((r) => setTimeout(r, 0));
    }
    // Signal completion
    stream.push({
      type: "done",
      message: { role: "assistant", content: llmReply },
    });
  })();

  // 4. Consume the stream and collect all text_delta deltas
  let collected = "";
  for await (const event of stream) {
    if (event.type === "text_delta") {
      // Prefer delta field, fall back to text
      const t = typeof event.delta === "string" ? event.delta
        : typeof event.text === "string" ? event.text : "";
      collected += t;
    }
    if (event.type === "done") {
      break;
    }
  }
  await pushTask;

  console.log(`  Collected  : ${collected}`);

  // 5. Verify the collected text contains the REAL email
  if (collected.includes(REAL_EMAIL)) {
    pass("deobfuscation restores real email in streamed output");
  } else {
    fail(
      "deobfuscation restores real email in streamed output",
      `expected "${REAL_EMAIL}" in: ${collected}`
    );
  }

  if (!collected.includes(fakeEmail)) {
    pass("fake email is no longer present after deobfuscation");
  } else {
    fail(
      "fake email is no longer present after deobfuscation",
      `fake "${fakeEmail}" still found in: ${collected}`
    );
  }

  // Clean up the global hook
  delete globalThis.__shroudStreamDeobfuscate;
}

// ---------------------------------------------------------------------------
// Test 2 -- End-to-end via running OpenClaw gateway + Slack
// ---------------------------------------------------------------------------
async function testSlackEndToEnd() {
  console.log("\n=== Test 2: Slack end-to-end via OpenClaw ===\n");

  // 1. Read the latest message ts from the channel (baseline)
  console.log(`  Reading latest message ts from channel ${SLACK_CHANNEL} ...`);
  let baselineTs = "0";
  try {
    const histUrl = new URL("https://slack.com/api/conversations.history");
    histUrl.searchParams.set("channel", SLACK_CHANNEL);
    histUrl.searchParams.set("limit", "1");
    const histRes = await fetch(histUrl.toString(), {
      headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` },
    });
    const histData = await histRes.json();
    if (histData.ok && histData.messages && histData.messages.length > 0) {
      baselineTs = histData.messages[0].ts;
      console.log(`  Baseline ts: ${baselineTs}`);
    } else {
      console.log(`  No existing messages found, using ts=0`);
    }
  } catch (err) {
    console.log(`  Warning: could not read baseline ts: ${err.message}`);
  }

  // 2. Post "format at json: testuser@example.net" to the channel
  const messageText = `format at json: ${SLACK_REAL_EMAIL}`;
  console.log(`  Sending: "${messageText}" to channel ${SLACK_CHANNEL} ...`);

  let postRes;
  try {
    postRes = await fetch("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channel: SLACK_CHANNEL,
        text: messageText,
      }),
    });
  } catch (err) {
    fail("slack post", `fetch failed: ${err.message}`);
    return;
  }

  const postData = await postRes.json();
  if (!postData.ok) {
    fail("slack post", `Slack API error: ${postData.error}`);
    return;
  }
  const postedTs = postData.ts;
  console.log(`  Message sent (ts=${postedTs}). Waiting for bot reply ...`);

  // 3. Poll for new bot messages (up to 90 seconds, every 5 seconds)
  const deadline = Date.now() + 90_000;
  let botReplyText = null;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5000));

    let histRes;
    try {
      const url = new URL("https://slack.com/api/conversations.history");
      url.searchParams.set("channel", SLACK_CHANNEL);
      url.searchParams.set("oldest", baselineTs);
      url.searchParams.set("limit", "20");
      histRes = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` },
      });
    } catch (err) {
      console.log(`  (poll error: ${err.message}, retrying ...)`);
      continue;
    }

    const histData = await histRes.json();
    if (!histData.ok) {
      console.log(`  (poll API error: ${histData.error}, retrying ...)`);
      continue;
    }

    // Look for bot messages newer than our posted message
    const botMessages = (histData.messages || []).filter(
      (m) => m.ts !== postedTs && m.ts > postedTs && m.bot_id
    );
    if (botMessages.length > 0) {
      // Take the most recent bot message
      botReplyText = botMessages[0].text; // messages are newest-first
      break;
    }
  }

  if (botReplyText === null) {
    fail("slack reply", "no bot reply received within 90 seconds");
    return;
  }

  console.log(
    `  Bot reply (${botReplyText.length} chars): ${botReplyText.slice(0, 300)}${botReplyText.length > 300 ? "..." : ""}`
  );

  // 4. Check if the bot's response contains the real email (deobfuscated)
  if (botReplyText.includes(SLACK_REAL_EMAIL)) {
    pass("Slack bot reply contains the real email (deobfuscation worked)");
  } else {
    fail(
      "Slack bot reply contains the real email",
      `expected "${SLACK_REAL_EMAIL}" in reply but not found -- reply may contain fakes`
    );
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("Shroud deobfuscation test suite");
  console.log("===============================");

  await testLocalStreamDeobfuscation();
  await testSlackEndToEnd();

  console.log("\n-------------------------------");
  if (failures === 0) {
    console.log("All tests PASSED.");
    process.exit(0);
  } else {
    console.log(`${failures} test(s) FAILED.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
