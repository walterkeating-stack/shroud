import { join } from "node:path";

function sanitizeSlug(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    || "app";
}

export function resolveExternalStateDir() {
  const home = process.env.HOME || "/tmp";
  if (process.env.OPENCLAW_STATE_DIR) return process.env.OPENCLAW_STATE_DIR;
  return home.endsWith("/.openclaw") ? home : join(home, ".openclaw");
}

export function resolveExternalAgentConfig(defaults = {}) {
  const stateDir = resolveExternalStateDir();
  const agentLabel = process.env.SHROUD_AGENT_LABEL || defaults.agentLabel || "app-agent";
  const agentVersion = process.env.SHROUD_AGENT_VERSION || defaults.agentVersion || "1.0.0";
  const agentChannel = process.env.SHROUD_AGENT_CHANNEL || defaults.agentChannel || "app";
  const agentSlug = sanitizeSlug(process.env.SHROUD_AGENT_SLUG || defaults.agentSlug || agentLabel);

  return {
    stateDir,
    agentLabel,
    agentVersion,
    agentChannel,
    agentSlug,
    socketPath: process.env.SHROUD_SOCKET || defaults.socketPath || `/tmp/shroud-${agentSlug}.sock`,
    sessionFile: process.env.SHROUD_APP_SESSIONS_FILE || join(stateDir, `shroud-${agentSlug}-sessions.json`),
    eventsFile: process.env.SHROUD_APP_EVENTS_FILE || join(stateDir, `shroud-${agentSlug}-events.jsonl`),
  };
}
