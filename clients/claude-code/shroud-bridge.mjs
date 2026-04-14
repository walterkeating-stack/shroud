#!/usr/bin/env node
/**
 * Shroud Bridge — HTTP bridge between Claude Code hooks and Shroud APP server.
 *
 * Connects to a running APP server via Unix socket and exposes HTTP endpoints
 * that Claude Code hooks call on every tool use. Obfuscates tool outputs
 * (so Claude never sees real PII/infra) and deobfuscates tool inputs
 * (so real values reach disk/shell).
 *
 * Requires: APP server running with --listen flag
 *   node app-server.mjs dist --listen /tmp/shroud-app.sock
 *
 * Usage:
 *   node shroud-bridge.mjs
 *
 * Environment:
 *   SHROUD_BRIDGE_PORT  HTTP port (default: 17380)
 *   SHROUD_SOCKET       Unix socket path (default: /tmp/shroud-app.sock)
 *   SHROUD_BRIDGE_LOG   Set to "verbose" for debug logging
 */

import { createServer } from "node:http";
import { SocketClient } from "./socket-client.mjs";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.SHROUD_BRIDGE_PORT || "17380", 10);

// Tools whose OUTPUT should be obfuscated before Claude sees it
const READ_TOOLS = new Set([
  "Read", "Bash", "Grep", "Glob", "WebFetch", "WebSearch",
]);

// Tools whose INPUT should be deobfuscated before execution
const WRITE_TOOLS = new Set(["Write", "Edit", "Bash", "NotebookEdit"]);

// ---------------------------------------------------------------------------
// Hook Handlers
// ---------------------------------------------------------------------------

/**
 * PreToolUse: runs BEFORE the tool executes.
 *
 * 1. Report tool call to Shroud security pipeline (injection scan, tool guard).
 *    If Shroud blocks → deny the tool call.
 * 2. For write tools (Write, Edit, Bash): deobfuscate inputs so real values
 *    reach disk/shell. Claude works with fakes; the real world gets real data.
 */
async function handlePreToolUse(body, app) {
  const { tool_name, tool_input } = body;
  if (!tool_name) return { continue: true };

  // --- Security scan ---
  let securityResult;
  try {
    securityResult = await app.toolCall(tool_name, tool_input || {});
  } catch {
    // fail open — don't block tools if security scan errors
  }

  if (securityResult?.blocked) {
    log(`BLOCKED ${tool_name}: ${securityResult.reason}`);
    return {
      continue: true,
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `Shroud security: ${securityResult.reason || "blocked by policy"}`,
      },
    };
  }

  // --- Deobfuscate write-tool inputs ---
  if (!WRITE_TOOLS.has(tool_name) || !tool_input) {
    return { continue: true };
  }

  let updatedInput = { ...tool_input };
  let modified = false;

  try {
    if (tool_name === "Write" && tool_input.content) {
      const r = await app.deobfuscate(tool_input.content);
      if (r.modified) { updatedInput.content = r.text; modified = true; }
    } else if (tool_name === "Edit") {
      if (tool_input.new_string) {
        const r = await app.deobfuscate(tool_input.new_string);
        if (r.modified) { updatedInput.new_string = r.text; modified = true; }
      }
      if (tool_input.old_string) {
        const r = await app.deobfuscate(tool_input.old_string);
        if (r.modified) { updatedInput.old_string = r.text; modified = true; }
      }
    } else if (tool_name === "Bash" && tool_input.command) {
      const r = await app.deobfuscate(tool_input.command);
      if (r.modified) { updatedInput.command = r.text; modified = true; }
    } else if (tool_name === "NotebookEdit" && tool_input.new_source) {
      const r = await app.deobfuscate(tool_input.new_source);
      if (r.modified) { updatedInput.new_source = r.text; modified = true; }
    }
  } catch (err) {
    log(`deobfuscate error for ${tool_name}: ${err.message}`);
    return { continue: true };
  }

  if (!modified) return { continue: true };

  log(`deobfuscated ${tool_name} input`);
  return {
    continue: true,
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      updatedInput,
    },
  };
}

/**
 * PostToolUse: runs AFTER the tool executes.
 *
 * For read tools (Read, Bash, Grep, Glob, WebFetch): obfuscate the output
 * so Claude sees format-preserving fakes instead of real PII/infra.
 * Also reports tool results to the security pipeline.
 */
async function handlePostToolUse(body, app) {
  const { tool_name } = body;
  if (!tool_name) return { continue: true };

  // Extract tool output — field name depends on Claude Code version
  const output = body.tool_output ?? body.tool_result ?? body.result ?? body.output;

  if (!READ_TOOLS.has(tool_name) || output == null) {
    return { continue: true };
  }

  const text = typeof output === "string" ? output : JSON.stringify(output);
  if (!text || text.length === 0) return { continue: true };

  // Report to security pipeline
  try {
    await app.toolResult(tool_name, text.slice(0, 10_000));
  } catch {}

  // Obfuscate the output
  try {
    const r = await app.obfuscate(text);
    if (!r.modified) return { continue: true };

    log(`obfuscated ${tool_name} output (${r.entityCount} entities)`);
    return {
      continue: true,
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedMCPToolOutput: r.text,
      },
    };
  } catch (err) {
    log(`obfuscate error for ${tool_name}: ${err.message}`);
    return { continue: true };
  }
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

function log(msg) {
  const ts = new Date().toISOString().slice(11, 23);
  process.stderr.write(`[shroud-bridge ${ts}] ${msg}\n`);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch (e) {
        reject(new Error(`Bad JSON: ${e.message}`));
      }
    });
    req.on("error", reject);
  });
}

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function createBridgeServer(app) {
  return createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const path = url.pathname;

    // Health endpoint (GET)
    if (req.method === "GET" && path === "/health") {
      try {
        const h = await app.health();
        sendJSON(res, 200, { ok: true, app: app.handshake, health: h });
      } catch (err) {
        sendJSON(res, 503, { ok: false, error: err.message });
      }
      return;
    }

    // Stats endpoint (GET)
    if (req.method === "GET" && path === "/stats") {
      try {
        const s = await app.stats();
        sendJSON(res, 200, s);
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
      return;
    }

    // Security endpoint (GET)
    if (req.method === "GET" && path === "/security") {
      try {
        const s = await app.security();
        sendJSON(res, 200, s);
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
      return;
    }

    // All hook endpoints are POST
    if (req.method !== "POST") {
      sendJSON(res, 405, { error: "Method not allowed" });
      return;
    }

    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      sendJSON(res, 400, { error: err.message });
      return;
    }

    const hookEvent = body.hook_event_name || path.replace(/^\//, "");

    try {
      let result;
      switch (hookEvent) {
        case "PreToolUse":
        case "pre-tool-use":
          result = await handlePreToolUse(body, app);
          break;
        case "PostToolUse":
        case "post-tool-use":
          result = await handlePostToolUse(body, app);
          break;
        default:
          // Unknown hook events pass through
          result = { continue: true };
      }
      sendJSON(res, 200, result);
    } catch (err) {
      log(`ERROR handling ${hookEvent}: ${err.message}`);
      // Fail open — always let the tool proceed on error
      sendJSON(res, 200, { continue: true });
    }
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const app = new SocketClient();
  log(`connecting to APP server at ${app.socketPath}`);

  const handshake = await app.connect();
  log(`connected: engine=${handshake.engine} v${handshake.version}`);

  // Identify as Claude Code
  try {
    const id = await app.identify("claude-code", "1.0.0", "claude-cli");
    log(`identified: agent=${id.agent} buildId=${id.buildId} security=${id.security}`);
  } catch (err) {
    log(`identify warning: ${err.message}`);
  }

  // Start HTTP server
  const server = createBridgeServer(app);
  server.listen(PORT, "127.0.0.1", () => {
    log(`listening on http://127.0.0.1:${PORT}`);
    log(`hook endpoints:`);
    log(`  POST /pre-tool-use   (PreToolUse)`);
    log(`  POST /post-tool-use  (PostToolUse)`);
    log(`  GET  /health`);
    log(`  GET  /stats`);
    log(`  GET  /security`);
  });

  // Graceful shutdown
  const shutdown = async (signal) => {
    log(`${signal} received, shutting down...`);
    server.close();
    app.close();
    process.exit(0);
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  process.stderr.write(`[shroud-bridge] FATAL: ${err.message}\n`);
  process.exit(1);
});
