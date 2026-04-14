#!/usr/bin/env node
/**
 * Codex MCP wrapper for Shroud.
 *
 * Reuses the shared MCP implementation but sets Codex-specific agent identity,
 * socket, and session-file defaults first.
 */
process.env.SHROUD_AGENT_LABEL ||= "codex";
process.env.SHROUD_AGENT_CHANNEL ||= "codex-cli";
process.env.SHROUD_AGENT_VERSION ||= "1.0.0";
process.env.SHROUD_AGENT_SLUG ||= "codex-mcp";
process.env.SHROUD_SOCKET ||= "/tmp/shroud-codex-mcp.sock";

await import("../claude-code/shroud-mcp.mjs");
