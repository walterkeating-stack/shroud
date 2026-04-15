import { describe, expect, test } from "vitest";

import {
  applyCodexBridgeEnv,
  resolveCodexBridgeEnv,
} from "../clients/codex/bridge-env.mjs";

describe("Codex bridge env normalization", () => {
  test("forces codex-cli identity and strips inherited APP file overrides", () => {
    const env = resolveCodexBridgeEnv({
      SHROUD_AGENT_LABEL: "codex",
      SHROUD_AGENT_CHANNEL: "codex-cli",
      SHROUD_AGENT_VERSION: "1.0.0",
      SHROUD_AGENT_SLUG: "codex-mcp",
      SHROUD_APP_SESSIONS_FILE: "/tmp/shroud-codex-mcp-sessions.json",
      SHROUD_APP_EVENTS_FILE: "/tmp/shroud-codex-mcp-events.jsonl",
    });

    expect(env.SHROUD_AGENT_LABEL).toBe("codex");
    expect(env.SHROUD_AGENT_CHANNEL).toBe("codex-cli");
    expect(env.SHROUD_AGENT_VERSION).toBe("1.0.0");
    expect(env.SHROUD_AGENT_SLUG).toBe("codex-cli");
    expect("SHROUD_APP_SESSIONS_FILE" in env).toBe(false);
    expect("SHROUD_APP_EVENTS_FILE" in env).toBe(false);
  });

  test("mutates process-style env objects into bridge-safe defaults", () => {
    const env: Record<string, string> = {
      SHROUD_AGENT_LABEL: "codex",
      SHROUD_AGENT_CHANNEL: "codex-cli",
      SHROUD_AGENT_SLUG: "codex-mcp",
      SHROUD_APP_SESSIONS_FILE: "/tmp/shroud-codex-mcp-sessions.json",
    };

    const normalized = applyCodexBridgeEnv(env);

    expect(normalized).toBe(env);
    expect(env.SHROUD_AGENT_SLUG).toBe("codex-cli");
    expect(env.SHROUD_AGENT_VERSION).toBe("1.0.0");
    expect("SHROUD_APP_SESSIONS_FILE" in env).toBe(false);
  });
});
