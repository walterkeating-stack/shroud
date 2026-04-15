#!/usr/bin/env node
/**
 * Codex MCP wrapper for Shroud.
 *
 * Reuses the shared MCP implementation but sets Codex-specific agent identity,
 * socket, and session-file defaults first.
 */
import { spawn } from "node:child_process";
import { readFileSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveCodexBridgeEnv } from "./bridge-env.mjs";
import { resolveExternalAgentConfig } from "../shared/agent-config.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

process.env.SHROUD_AGENT_LABEL ||= "codex";
process.env.SHROUD_AGENT_CHANNEL ||= "codex-cli";
process.env.SHROUD_AGENT_VERSION ||= "1.0.0";
process.env.SHROUD_AGENT_SLUG ||= "codex-mcp";
process.env.SHROUD_SOCKET ||= "/tmp/shroud-codex-mcp.sock";

const AGENT = resolveExternalAgentConfig({
  agentLabel: "codex",
  agentVersion: "1.0.0",
  agentChannel: "codex-cli",
  agentSlug: "codex-mcp",
  socketPath: "/tmp/shroud-codex-mcp.sock",
});

function pidIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function ensureCodexBridge() {
  if (String(process.env.SHROUD_CODEX_BRIDGE || "1") === "0") return;

  const pidFile = join(AGENT.stateDir, "shroud-codex-bridge.pid");
  try {
    const existingPid = Number.parseInt(readFileSync(pidFile, "utf-8").trim(), 10);
    if (pidIsAlive(existingPid)) return;
    unlinkSync(pidFile);
  } catch {}

  const bridgePath = join(__dirname, "shroud-bridge.mjs");
  const bridgeEnv = resolveCodexBridgeEnv(process.env);
  bridgeEnv.OPENCLAW_STATE_DIR = AGENT.stateDir;
  bridgeEnv.HOME = process.env.HOME;
  const child = spawn(process.execPath, [bridgePath], {
    detached: true,
    stdio: "ignore",
    env: bridgeEnv,
  });
  child.unref();
}

ensureCodexBridge();

await import("../claude-code/shroud-mcp.mjs");
