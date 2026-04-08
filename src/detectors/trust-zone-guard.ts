import type { SecuritySeverity } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

export interface TrustZoneViolation {
  severity: SecuritySeverity;
  signatureId: string;
  threatClass: ThreatClass;
  reason: string;
}

const OVERRIDE_PATTERNS = [
  /\bignore\s+(?:all\s+)?previous\b/i,
  /\boverride\b.{0,40}\b(?:policy|system|instruction|guardrail)\b/i,
  /\bsystem\s+prompt\b/i,
  /\bdo\s+not\s+obey\b/i,
  /\bnew\s+instructions?\b/i,
];

function extractCandidateText(params: unknown): string {
  if (typeof params === "string") return params;
  if (!params || typeof params !== "object") return "";
  const p = params as Record<string, unknown>;
  for (const key of ["message", "content", "text", "body", "prompt", "query"]) {
    if (typeof p[key] === "string") return p[key] as string;
  }
  return JSON.stringify(params);
}

export function checkTrustZoneOverride(toolName: string, params: unknown): TrustZoneViolation | null {
  const lowerTool = toolName.toLowerCase();
  if (!["sessions_send", "sessions_spawn", "exec", "bash", "code_execution"].includes(lowerTool)) {
    return null;
  }

  const text = extractCandidateText(params);
  if (!text) return null;
  const matched = OVERRIDE_PATTERNS.find(p => p.test(text));
  if (!matched) return null;

  return {
    severity: "high",
    signatureId: "trust_zone_override",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    reason: `Trust-zone override attempt: low-trust instruction content reached ${toolName}`,
  };
}
