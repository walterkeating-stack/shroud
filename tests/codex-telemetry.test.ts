import { describe, expect, test } from "vitest";

import {
  computeExternalAgentBuildId,
  isCodexControlPrompt,
  summarizeCodexHistoryJsonl,
} from "../src/codex-telemetry.js";

describe("Codex telemetry helpers", () => {
  test("summarizes prompts and sessions from Codex history", () => {
    const history = [
      { session_id: "s1", ts: 100, text: "hello" },
      { session_id: "s1", ts: 101, text: "quit" },
      { session_id: "s2", ts: 102, text: "status of repo?" },
      { session_id: "s3", ts: 103, text: "$" },
      { session_id: "s2", ts: 104, text: "run tests" },
      { bogus: true },
      "not-json",
    ]
      .map((entry) => typeof entry === "string" ? entry : JSON.stringify(entry))
      .join("\n");

    expect(summarizeCodexHistoryJsonl(history)).toEqual({
      promptCount: 3,
      sessionCount: 2,
      lastPromptAtMs: 104000,
    });
  });

  test("recognizes Codex control prompts", () => {
    expect(isCodexControlPrompt("quit")).toBe(true);
    expect(isCodexControlPrompt(" exit ")).toBe(true);
    expect(isCodexControlPrompt("$")).toBe(true);
    expect(isCodexControlPrompt("status")).toBe(false);
  });

  test("uses the APP-style external build-id scheme", () => {
    expect(computeExternalAgentBuildId("codex", "1.0.0")).toBe("099ee3156ab5ab01");
  });
});
