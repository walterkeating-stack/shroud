#!/usr/bin/env node
/**
 * Mock Slack Server — fakes both the Slack Event webhook receiver
 * and the Slack Web API (chat.postMessage, etc).
 *
 * Endpoints:
 *   POST /slack/events        — OpenClaw sends inbound events here (HTTP mode)
 *   POST /api/chat.postMessage — captures outbound messages from OpenClaw
 *   POST /api/auth.test       — returns bot identity
 *   POST /api/conversations.info — returns channel info
 *   POST /api/users.info      — returns user info
 *   GET  /messages             — returns captured outbound messages
 *   DELETE /messages           — clears captured messages
 *   POST /inject               — inject a Slack event into OpenClaw's webhook
 *
 * Usage:
 *   PORT=0 node server.mjs
 *   Prints { "port": <port>, "apiPort": <apiPort> } on stdout once ready.
 */

import http from "node:http";

const messages = [];       // captured outbound messages (chat.postMessage calls)
let gatewayWebhookUrl = null; // set via /configure or inject

// ── Slack Web API mock ────────────────────────────────────────────

function handleSlackApi(req, res) {
  const url = new URL(req.url, `http://127.0.0.1`);
  const path = url.pathname;

  // Collect body
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString();
      let body = {};
      try {
        // Slack API accepts both JSON and form-encoded
        if (req.headers["content-type"]?.includes("application/json")) {
          body = JSON.parse(raw);
        } else {
          body = Object.fromEntries(new URLSearchParams(raw));
        }
      } catch {}

      if (path === "/api/chat.postMessage") {
        messages.push({
          channel: body.channel,
          text: body.text || "",
          blocks: body.blocks || null,
          ts: Date.now(),
        });
        json(res, { ok: true, ts: `${Date.now()}.000000`, channel: body.channel });
      } else if (path === "/api/chat.update") {
        // Streaming updates — record as update, not new message
        const existing = messages.find(m => m.channel === body.channel);
        if (existing) {
          existing.text = body.text || existing.text;
          existing.blocks = body.blocks || existing.blocks;
          existing.updated = true;
        }
        json(res, { ok: true, ts: body.ts || `${Date.now()}.000000`, channel: body.channel });
      } else if (path === "/api/auth.test") {
        json(res, {
          ok: true,
          url: "https://mock-workspace.slack.com/",
          team: "Mock Workspace",
          user: "shroud-bot",
          team_id: "T00000001",
          user_id: "UBOT00001",
          bot_id: "B00000001",
        });
      } else if (path === "/api/conversations.info") {
        const channels = {
          "C00000001": { id: "C00000001", name: "network-ops", is_channel: true, is_member: true, topic: { value: "Network operations alerts" } },
          "C00000002": { id: "C00000002", name: "security-alerts", is_channel: true, is_member: true, topic: { value: "Security incident channel" } },
        };
        const chanId = body.channel || "C00000001";
        json(res, {
          ok: true,
          channel: channels[chanId] || { id: chanId, name: "unknown-channel", is_channel: true, is_member: true },
        });
      } else if (path === "/api/conversations.list") {
        json(res, {
          ok: true,
          channels: [
            { id: "C00000001", name: "network-ops", is_channel: true, is_member: true, num_members: 12 },
            { id: "C00000002", name: "security-alerts", is_channel: true, is_member: true, num_members: 8 },
          ],
        });
      } else if (path === "/api/users.info") {
        // Simulate real users with different profiles
        const users = {
          "U00000001": { id: "U00000001", name: "walter.example", real_name: "User Example", is_bot: false, tz: "Europe/Dublin" },
          "U00000002": { id: "U00000002", name: "jane.ops", real_name: "Jane Ops", is_bot: false, tz: "America/New_York" },
          "UBOT00001": { id: "UBOT00001", name: "shroud-bot", real_name: "Shroud Bot", is_bot: true },
        };
        const userId = body.user || "U00000001";
        json(res, {
          ok: true,
          user: users[userId] || { id: userId, name: "unknown-user", real_name: "Unknown User", is_bot: false },
        });
      } else if (path === "/api/users.list") {
        json(res, {
          ok: true,
          members: [
            { id: "U00000001", name: "walter.example", real_name: "User Example", is_bot: false },
            { id: "U00000002", name: "jane.ops", real_name: "Jane Ops", is_bot: false },
            { id: "UBOT00001", name: "shroud-bot", real_name: "Shroud Bot", is_bot: true },
          ],
        });
      } else if (path === "/api/apps.connections.open") {
        // Socket mode connect — shouldn't be hit in HTTP mode but just in case
        json(res, { ok: true, url: "wss://mock.slack.com/link/ws" });
      } else {
        // Default: return ok for any unknown Slack API method
        json(res, { ok: true });
      }
      resolve();
    });
  });
}

// ── Control endpoints ─────────────────────────────────────────────

function handleControl(req, res) {
  const url = new URL(req.url, `http://127.0.0.1`);

  if (url.pathname === "/messages" && req.method === "GET") {
    json(res, messages);
    return;
  }

  if (url.pathname === "/messages" && req.method === "DELETE") {
    messages.length = 0;
    json(res, { cleared: true });
    return;
  }

  if (url.pathname === "/inject" && req.method === "POST") {
    // Inject an event into OpenClaw's Slack webhook
    return new Promise((resolve) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        if (!gatewayWebhookUrl) {
          json(res, { error: "Gateway webhook URL not configured" }, 500);
          resolve();
          return;
        }
        try {
          const resp = await fetch(gatewayWebhookUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Slack-Request-Timestamp": String(Math.floor(Date.now() / 1000)),
              "X-Slack-Signature": "v0=mock-signature",
            },
            body: JSON.stringify(body),
          });
          json(res, { injected: true, status: resp.status });
        } catch (err) {
          json(res, { error: err.message }, 500);
        }
        resolve();
      });
    });
  }

  if (url.pathname === "/configure" && req.method === "POST") {
    return new Promise((resolve) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        if (body.gatewayWebhookUrl) gatewayWebhookUrl = body.gatewayWebhookUrl;
        json(res, { configured: true });
        resolve();
      });
    });
  }

  res.writeHead(404);
  res.end("Not found");
}

// ── Unified server ────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1`);

  if (url.pathname.startsWith("/api/")) {
    await handleSlackApi(req, res);
  } else {
    await handleControl(req, res);
  }
});

function json(res, data, code = 200) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

const port = parseInt(process.env.PORT || "0", 10);
server.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  // Output port info as JSON on stdout — runner reads this
  console.log(JSON.stringify({ port: addr.port }));
});
