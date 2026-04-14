#!/usr/bin/env node
/**
 * Shroud MCP Server — Model Context Protocol server for Claude Code.
 *
 * Connects to a running APP server via Unix socket and exposes Shroud's
 * privacy engine as MCP tools that Claude can call on demand.
 *
 * Requires: APP server running with --listen flag
 *   node app-server.mjs dist --listen /tmp/shroud-app.sock
 *
 * Transport: stdio (JSON-RPC 2.0, newline-delimited)
 * Protocol: MCP 2024-11-05
 *
 * Environment:
 *   SHROUD_SOCKET   Unix socket path (default: /tmp/shroud-app.sock)
 *   SHROUD_MCP_LOG  Set to "verbose" for debug logging
 */

import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { existsSync, statSync, unlinkSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SocketClient } from "./socket-client.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

function log(msg) {
  process.stderr.write(`[shroud-mcp] ${msg}\n`);
}

// ---------------------------------------------------------------------------
// Auto-spawn APP server if not already running
// ---------------------------------------------------------------------------

function isSocketAlive(socketPath) {
  try {
    return statSync(socketPath).isSocket();
  } catch {
    return false;
  }
}

function spawnAppServer(socketPath) {
  const appServer = resolve(__dirname, "../../app-server.mjs");
  const distPath = resolve(__dirname, "../../dist");

  if (!existsSync(appServer)) {
    throw new Error(`APP server not found at ${appServer}`);
  }

  log(`spawning APP server: ${appServer} ${distPath} --listen ${socketPath}`);

  const child = spawn(process.execPath, [appServer, distPath, "--listen", socketPath], {
    stdio: ["pipe", "pipe", "pipe"],
    detached: true,
    env: {
      ...process.env,
      // Write to a Claude-Code-specific session file so we don't overwrite
      // the main APP server's session file (which causes appear/disappear
      // on the dashboard as the two processes race on the same file).
      SHROUD_APP_SESSIONS_FILE: "/tmp/shroud-mcp-sessions.json",
    },
  });

  // Pipe stderr for diagnostics but don't block
  child.stderr.on("data", (chunk) => {
    for (const line of chunk.toString().split("\n").filter(Boolean)) {
      log(`[app] ${line}`);
    }
  });

  child.on("error", (err) => log(`APP server error: ${err.message}`));
  child.on("exit", (code) => log(`APP server exited with code ${code}`));

  // Detach so MCP server exit doesn't orphan cleanup
  child.unref();

  // Keep a reference so we can kill on exit
  return child;
}

async function ensureAppServer(socketPath, maxWaitMs = 8000) {
  // Try connecting first — server may already be running
  try {
    const probe = new SocketClient(socketPath);
    await probe.connect();
    log("APP server already running");
    return { client: probe, child: null };
  } catch {
    // Not running — spawn it
  }

  // Clean up stale socket
  if (isSocketAlive(socketPath)) {
    try { unlinkSync(socketPath); } catch {}
  }

  const child = spawnAppServer(socketPath);

  // Poll for socket availability
  const start = Date.now();
  const pollInterval = 200;
  while (Date.now() - start < maxWaitMs) {
    await new Promise((r) => setTimeout(r, pollInterval));
    try {
      const client = new SocketClient(socketPath);
      await client.connect();
      log("APP server ready");
      return { client, child };
    } catch {
      // Not ready yet
    }
  }

  throw new Error(`APP server failed to start within ${maxWaitMs}ms`);
}

// ---------------------------------------------------------------------------
// MCP Tool Definitions
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: "shroud_obfuscate",
    description:
      "Replace sensitive data (PII, IPs, emails, credentials, infrastructure details) " +
      "with deterministic format-preserving fakes. The same input always produces the " +
      "same fake, so you can use obfuscated values consistently across a conversation. " +
      "Use this before sharing text externally or when you need to sanitize content.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The text containing sensitive data to obfuscate",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "shroud_deobfuscate",
    description:
      "Restore original values from previously obfuscated text. Converts fake IPs, " +
      "emails, names etc. back to their real counterparts. Use this when you need " +
      "to work with real values (e.g., before writing to files or executing commands).",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text containing obfuscated (fake) values to restore",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "shroud_status",
    description:
      "Get Shroud engine status: mapping count, detection stats by category, " +
      "security events, and engine health. Use this to understand what data " +
      "has been protected and check for security incidents.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "shroud_scan_tool",
    description:
      "Scan a tool call for security threats before executing it. Returns whether " +
      "the call is allowed or blocked, with threat details. Use this to pre-check " +
      "potentially dangerous commands.",
    inputSchema: {
      type: "object",
      properties: {
        tool: {
          type: "string",
          description: "Tool name (e.g., 'Bash', 'Write', 'exec')",
        },
        args: {
          type: "object",
          description: "Tool arguments to scan",
          additionalProperties: true,
        },
      },
      required: ["tool", "args"],
    },
  },
  {
    name: "shroud_configure",
    description:
      "Hot-reload Shroud configuration. Adjust detection sensitivity, enable/disable " +
      "rules, change injection detection mode, etc. Changes take effect immediately.",
    inputSchema: {
      type: "object",
      properties: {
        config: {
          type: "object",
          description: "Configuration object with keys to update",
          additionalProperties: true,
        },
      },
      required: ["config"],
    },
  },
  {
    name: "shroud_reset",
    description:
      "Clear all obfuscation mappings and start fresh. Use this at the beginning " +
      "of a new task or when mappings have accumulated stale entries. Returns a " +
      "summary of what was cleared.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// ---------------------------------------------------------------------------
// MCP Tool Handlers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tracked tool call — wraps every MCP tool with tool_call/tool_result
// so the APP server tracks it in the agent session (dashboard visibility).
// ---------------------------------------------------------------------------

async function trackedToolCall(app, mcpToolName, fn) {
  // Report tool_call to the security pipeline (fire-and-forget on error)
  await app.toolCall(mcpToolName, {}).catch(() => {});

  const result = await fn();

  // Report tool_result so the dashboard sees completion
  await app.toolResult(mcpToolName, typeof result === "string" ? result.slice(0, 500) : "").catch(() => {});

  return result;
}

async function handleToolCall(name, args, app) {
  switch (name) {
    case "shroud_obfuscate": {
      if (!args.text) throw new Error("'text' parameter is required");
      return trackedToolCall(app, "obfuscate", async () => {
        const r = await app.obfuscate(args.text);
        const lines = [`**Obfuscated** (${r.entityCount} entities detected)`];
        if (r.entityCount > 0) {
          const cats = Object.entries(r.categories || {})
            .map(([k, v]) => `${k}: ${v}`)
            .join(", ");
          lines.push(`Categories: ${cats}`);
        }
        lines.push("", r.text);
        return lines.join("\n");
      });
    }

    case "shroud_deobfuscate": {
      if (!args.text) throw new Error("'text' parameter is required");
      return trackedToolCall(app, "deobfuscate", async () => {
        const r = await app.deobfuscate(args.text);
        const lines = [`**Deobfuscated** (${r.replacementCount} values restored)`];
        lines.push("", r.text);
        return lines.join("\n");
      });
    }

    case "shroud_status": {
      return trackedToolCall(app, "status", async () => {
        const [stats, health] = await Promise.all([
          app.stats().catch(() => null),
          app.health().catch(() => null),
        ]);
        let securityInfo;
        try { securityInfo = await app.security(); } catch {}

        const lines = ["## Shroud Status"];

        if (health) {
          lines.push(
            "",
            `**Engine**: v${stats?.engine?.version || "?"} | ` +
            `uptime ${health.uptime}s | ${health.requests} requests | ` +
            `${health.avgLatencyMs}ms avg | ${health.memoryMB}MB`
          );
        }

        if (stats) {
          lines.push("", `**Mappings**: ${stats.storeMappings} active`);
          const dets = Object.entries(stats.detectionsByCategory || {});
          if (dets.length > 0) {
            lines.push("", "**Detections by category**:");
            for (const [cat, count] of dets.sort((a, b) => b[1] - a[1])) {
              lines.push(`  ${cat}: ${count}`);
            }
          }
        }

        if (securityInfo?.enabled) {
          lines.push(
            "",
            `**Security**: ${securityInfo.mode} mode | ${securityInfo.events} events`
          );
          const byClass = Object.entries(securityInfo.byThreatClass || {});
          if (byClass.length > 0) {
            lines.push("", "**Threats by class**:");
            for (const [cls, count] of byClass.sort((a, b) => b[1] - a[1])) {
              lines.push(`  ${cls}: ${count}`);
            }
          }
        }

        return lines.join("\n");
      });
    }

    case "shroud_scan_tool": {
      if (!args.tool) throw new Error("'tool' parameter is required");
      return trackedToolCall(app, "scan_tool", async () => {
        const r = await app.toolCall(args.tool, args.args || {});
        const lines = [
          r.blocked
            ? `**BLOCKED**: ${r.reason || "security policy"}`
            : `**ALLOWED**: ${args.tool} (sequence length: ${r.sequenceLength})`,
        ];
        if (r.events?.length > 0) {
          lines.push("", "Events:");
          for (const evt of r.events) {
            lines.push(`  [${evt.severity}] ${evt.threatClass}: ${evt.action}`);
          }
        }
        return lines.join("\n");
      });
    }

    case "shroud_configure": {
      if (!args.config) throw new Error("'config' parameter is required");
      return trackedToolCall(app, "configure", async () => {
        const r = await app.configure(args.config);
        return `Configuration updated. Applied keys: ${(r.appliedKeys || []).join(", ") || "none"}`;
      });
    }

    case "shroud_reset": {
      return trackedToolCall(app, "reset", async () => {
        const r = await app.reset();
        const summary = r.summary || {};
        return (
          `Mappings cleared.\n` +
          `  Duration: ${summary.durationMs || 0}ms\n` +
          `  Mappings cleared: ${summary.storeMappings || 0}\n` +
          `  Total detections: ${JSON.stringify(summary.detectionsByCategory || {})}`
        );
      });
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// MCP Protocol Handler
// ---------------------------------------------------------------------------

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function sendResult(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function sendError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

// ---------------------------------------------------------------------------
// Lazy connection manager — connects on first tool call, auto-reconnects
// ---------------------------------------------------------------------------

class AppConnection {
  #socketPath;
  #client = null;
  #connecting = null;

  constructor(socketPath) {
    this.#socketPath = socketPath;
  }

  async get() {
    if (this.#client?.ready) return this.#client;

    // Avoid concurrent connection attempts
    if (this.#connecting) return this.#connecting;

    this.#connecting = this.#connect();
    try {
      return await this.#connecting;
    } finally {
      this.#connecting = null;
    }
  }

  async #connect() {
    // Close stale client
    if (this.#client) {
      try { this.#client.close(); } catch {}
      this.#client = null;
    }

    const { client } = await ensureAppServer(this.#socketPath);
    log(`connected: v${client.handshake.version}`);

    try {
      await client.identify("claude-code-mcp", "1.0.0", "mcp");
      log("identified as claude-code-mcp");
    } catch (err) {
      log(`identify warning: ${err.message}`);
    }

    this.#client = client;
    return client;
  }

  get version() {
    return this.#client?.handshake?.version || "unknown";
  }

  close() {
    if (this.#client) {
      try { this.#client.close(); } catch {}
      this.#client = null;
    }
  }
}

async function handleMessage(msg, conn) {
  const { id, method, params } = msg;

  // Notifications (no id) — acknowledge silently
  if (id === undefined || id === null) {
    return;
  }

  switch (method) {
    case "initialize":
      sendResult(id, {
        protocolVersion: "2024-11-05",
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: "shroud",
          version: conn.version,
        },
      });
      break;

    case "tools/list":
      sendResult(id, { tools: TOOLS });
      break;

    case "tools/call": {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};
      try {
        const app = await conn.get();
        const text = await handleToolCall(toolName, toolArgs, app);
        sendResult(id, {
          content: [{ type: "text", text }],
        });
      } catch (err) {
        sendResult(id, {
          content: [{ type: "text", text: `Shroud unavailable: ${err.message}` }],
          isError: true,
        });
      }
      break;
    }

    case "ping":
      sendResult(id, {});
      break;

    default:
      sendError(id, -32601, `Method not found: ${method}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // Claude Code gets its own APP server on a dedicated socket, separate from
  // OpenClaw/Hermes agents. This prevents identity collisions where different
  // agents re-identify on the same APP server, causing appear/disappear on
  // the dashboard. Multiple Claude Code sessions share this socket safely
  // since they all identify as the same agent.
  const socketPath = process.env.SHROUD_SOCKET || "/tmp/shroud-mcp.sock";
  const conn = new AppConnection(socketPath);

  log(`ready — lazy connect to ${socketPath}`);

  // Read MCP messages from stdin
  const rl = createInterface({ input: process.stdin, terminal: false });

  rl.on("line", async (line) => {
    line = line.trim();
    if (!line) return;
    try {
      const msg = JSON.parse(line);
      await handleMessage(msg, conn);
    } catch (err) {
      log(`parse error: ${err.message}`);
      sendError(null, -32700, "Parse error");
    }
  });

  function cleanup() {
    conn.close();
    process.exit(0);
  }

  rl.on("close", () => {
    log("stdin closed, shutting down");
    cleanup();
  });

  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
}

main();
