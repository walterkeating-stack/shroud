export function resolveCodexBridgeEnv(baseEnv = process.env) {
  const env = { ...baseEnv };
  env.SHROUD_AGENT_LABEL = "codex";
  env.SHROUD_AGENT_CHANNEL = "codex-cli";
  env.SHROUD_AGENT_VERSION = env.SHROUD_AGENT_VERSION || "1.0.0";
  env.SHROUD_AGENT_SLUG = "codex-cli";
  delete env.SHROUD_APP_SESSIONS_FILE;
  delete env.SHROUD_APP_EVENTS_FILE;
  return env;
}

export function applyCodexBridgeEnv(targetEnv = process.env) {
  const normalized = resolveCodexBridgeEnv(targetEnv);
  delete targetEnv.SHROUD_APP_SESSIONS_FILE;
  delete targetEnv.SHROUD_APP_EVENTS_FILE;
  targetEnv.SHROUD_AGENT_LABEL = normalized.SHROUD_AGENT_LABEL;
  targetEnv.SHROUD_AGENT_CHANNEL = normalized.SHROUD_AGENT_CHANNEL;
  targetEnv.SHROUD_AGENT_VERSION = normalized.SHROUD_AGENT_VERSION;
  targetEnv.SHROUD_AGENT_SLUG = normalized.SHROUD_AGENT_SLUG;
  return targetEnv;
}
