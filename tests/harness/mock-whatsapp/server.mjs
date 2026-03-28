#!/usr/bin/env node
/**
 * Mock WhatsApp Server — captures outbound messages from OpenClaw's
 * WhatsApp extension and allows injecting inbound messages.
 *
 * Works with the Baileys intercept (intercept.cjs) which redirects
 * sendMessage() calls here and exposes an injection endpoint.
 *
 * Endpoints:
 *   POST /send          — receives outbound messages from intercepted sendMessage()
 *   POST /inject        — inject an inbound message (triggers messages.upsert in Baileys mock)
 *   GET  /messages      — returns captured outbound messages
 *   DELETE /messages    — clears captured messages
 *   GET  /health        — health check
 *
 * Usage:
 *   PORT=9300 node server.mjs
 */

import http from "node:http";

const messages = [];
let injectCallback = null; // set by the intercept when the mock socket is created

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");

  if (req.method === "GET" && url.pathname === "/health") {
    json(res, { ok: true, messages: messages.length });
    return;
  }

  if (req.method === "GET" && url.pathname === "/messages") {
    json(res, messages);
    return;
  }

  if (req.method === "DELETE" && url.pathname === "/messages") {
    messages.length = 0;
    json(res, { cleared: true });
    return;
  }

  if (req.method === "POST" && url.pathname === "/send") {
    const body = await readBody(req);
    messages.push(body);
    json(res, { ok: true, messageId: `mock-${Date.now()}` });
    return;
  }

  if (req.method === "POST" && url.pathname === "/inject") {
    const body = await readBody(req);
    // The intercept registers a callback to inject messages into the mock socket
    if (globalThis.__mockWhatsAppInject) {
      globalThis.__mockWhatsAppInject(body);
      json(res, { injected: true });
    } else {
      json(res, { error: "No mock socket registered — intercept not loaded" }, 500);
    }
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

function json(res, data, code = 200) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { resolve({}); }
    });
  });
}

const port = parseInt(process.env.PORT || "0", 10);
server.listen(port, "127.0.0.1", () => {
  console.log(JSON.stringify({ port: server.address().port, ready: true }));
});
