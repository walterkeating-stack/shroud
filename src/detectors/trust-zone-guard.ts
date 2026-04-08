import type { SecuritySeverity } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

export interface TrustZoneViolation {
  severity: SecuritySeverity;
  signatureId: string;
  threatClass: ThreatClass;
  reason: string;
}

export interface TrustZoneSignal {
  privilegedTool: boolean;
  lowTrustText: boolean;
  matchedPatternCount: number;
  matchedPatterns: string[];
  riskScore: number;
  risky: boolean;
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

export function assessTrustZoneContext(toolName: string, params: unknown): TrustZoneSignal {
  const lowerTool = toolName.toLowerCase();
  const privilegedTool = ["sessions_send", "sessions_spawn", "exec", "bash", "code_execution"].includes(lowerTool);
  if (!privilegedTool) {
    return {
      privilegedTool: false,
      lowTrustText: false,
      matchedPatternCount: 0,
      matchedPatterns: [],
      riskScore: 0,
      risky: false,
    };
  }

  const text = extractCandidateText(params);
  if (!text) {
    return {
      privilegedTool,
      lowTrustText: false,
      matchedPatternCount: 0,
      matchedPatterns: [],
      riskScore: 0,
      risky: false,
    };
  }
  const matchedPatterns = OVERRIDE_PATTERNS
    .filter(p => p.test(text))
    .map(p => p.source);
  const matchedPatternCount = matchedPatterns.length;
  const lowTrustText = matchedPatternCount > 0;
  const riskScore = Math.min(1, (lowTrustText ? 0.65 : 0) + Math.max(0, matchedPatternCount - 1) * 0.15);

  return {
    privilegedTool,
    lowTrustText,
    matchedPatternCount,
    matchedPatterns,
    riskScore,
    risky: riskScore >= 0.65,
  };
}

export function checkTrustZoneOverride(toolName: string, params: unknown): TrustZoneViolation | null {
  const signal = assessTrustZoneContext(toolName, params);
  if (!signal.risky) return null;

  return {
    severity: "high",
    signatureId: "trust_zone_override",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    reason: `Trust-zone override attempt: low-trust instruction content reached ${toolName}`,
  };
}
