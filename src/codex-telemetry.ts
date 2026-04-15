import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface CodexHistoryEntry {
  session_id?: unknown;
  ts?: unknown;
  text?: unknown;
}

export interface CodexHistorySummary {
  promptCount: number;
  sessionCount: number;
  lastPromptAtMs: number;
}

const CONTROL_PROMPTS = new Set([
  "",
  "$",
  "quit",
  "exit",
  "logout",
]);

export function computeExternalAgentBuildId(label: string, version: string): string {
  return createHash("sha256")
    .update(`${String(label || "").trim()}:${String(version || "").trim()}`)
    .digest("hex")
    .slice(0, 16);
}

export function resolveCodexHome(): string {
  if (process.env.CODEX_HOME) return process.env.CODEX_HOME;
  const home = process.env.HOME || "/root";
  return join(home, ".codex");
}

export function resolveCodexHistoryFile(): string {
  return process.env.SHROUD_CODEX_HISTORY_FILE || join(resolveCodexHome(), "history.jsonl");
}

export function isCodexControlPrompt(value: unknown): boolean {
  return CONTROL_PROMPTS.has(String(value || "").trim().toLowerCase());
}

export function summarizeCodexHistoryJsonl(text: string): CodexHistorySummary {
  const sessionIds = new Set<string>();
  let promptCount = 0;
  let lastPromptAtMs = 0;

  for (const line of String(text || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let entry: CodexHistoryEntry;
    try {
      entry = JSON.parse(trimmed) as CodexHistoryEntry;
    } catch {
      continue;
    }

    const sessionId = typeof entry.session_id === "string" ? entry.session_id.trim() : "";
    const tsSeconds = Number(entry.ts);
    const textValue = typeof entry.text === "string" ? entry.text : "";
    if (!sessionId || !Number.isFinite(tsSeconds) || isCodexControlPrompt(textValue)) continue;

    sessionIds.add(sessionId);
    promptCount++;
    lastPromptAtMs = Math.max(lastPromptAtMs, Math.trunc(tsSeconds * 1000));
  }

  return {
    promptCount,
    sessionCount: sessionIds.size,
    lastPromptAtMs,
  };
}

export function loadCodexHistorySummary(historyFile = resolveCodexHistoryFile()): CodexHistorySummary | null {
  if (!existsSync(historyFile)) return null;
  try {
    const raw = readFileSync(historyFile, "utf-8");
    return summarizeCodexHistoryJsonl(raw);
  } catch {
    return null;
  }
}
