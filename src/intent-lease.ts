import { ToolCategory, TOOL_CATEGORIES } from "./detectors/tool-intent.js";

export interface IntentLease {
  leaseId: string;
  parentAgentBuildId: string;
  parentAgentLabel: string;
  childHint: string;
  intentSummary: string;
  allowedToolFamilies: ToolCategory[];
  allowedDataClasses: string[];
  maxSteps: number;
  expiresAt: number;
  signature: string;
}

export interface LeaseViolation {
  severity: "medium" | "high";
  reason: string;
  signatureId: string;
}

function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
  return Math.abs(hash).toString(16);
}

export class IntentLeaseManager {
  private _pending: IntentLease[] = [];
  private _active = new Map<string, IntentLease>();
  private _stepCounts = new Map<string, number>();

  issueLease(input: {
    parentAgentBuildId: string;
    parentAgentLabel: string;
    childHint: string;
    intentSummary: string;
    allowedToolFamilies: ToolCategory[];
    allowedDataClasses: string[];
    maxSteps?: number;
    ttlMs?: number;
  }): IntentLease {
    const now = Date.now();
    const lease: IntentLease = {
      leaseId: `${simpleHash(`${input.parentAgentBuildId}:${input.childHint}:${now}:${input.intentSummary}`)}`,
      parentAgentBuildId: input.parentAgentBuildId,
      parentAgentLabel: input.parentAgentLabel,
      childHint: input.childHint,
      intentSummary: input.intentSummary.slice(0, 300),
      allowedToolFamilies: [...new Set(input.allowedToolFamilies)],
      allowedDataClasses: [...new Set(input.allowedDataClasses)],
      maxSteps: input.maxSteps ?? 8,
      expiresAt: now + (input.ttlMs ?? 10 * 60_000),
      signature: simpleHash(`${input.parentAgentBuildId}:${input.childHint}:${input.intentSummary}`),
    };
    this._pending.push(lease);
    if (this._pending.length > 200) this._pending = this._pending.slice(-100);
    return lease;
  }

  consumeLease(agentBuildId: string, agentLabel: string, hint?: string): IntentLease | null {
    const now = Date.now();
    this._pending = this._pending.filter(l => l.expiresAt > now);
    let idx = -1;
    if (hint) {
      const lowerHint = hint.toLowerCase();
      idx = this._pending.findIndex(l => l.childHint.toLowerCase() === lowerHint || agentLabel.toLowerCase().includes(lowerHint));
    }
    if (idx < 0 && agentLabel) {
      const lowerLabel = agentLabel.toLowerCase();
      idx = this._pending.findIndex(l => l.childHint && (l.childHint.toLowerCase() === lowerLabel || lowerLabel.includes(l.childHint.toLowerCase())));
    }
    if (idx < 0 && this._pending.length > 0) idx = 0;
    if (idx < 0) return null;
    const lease = this._pending.splice(idx, 1)[0];
    this._active.set(agentBuildId, lease);
    this._stepCounts.set(agentBuildId, 0);
    return lease;
  }

  getLease(agentBuildId: string): IntentLease | null {
    const lease = this._active.get(agentBuildId);
    if (!lease) return null;
    if (lease.expiresAt <= Date.now()) {
      this._active.delete(agentBuildId);
      this._stepCounts.delete(agentBuildId);
      return null;
    }
    return lease;
  }

  checkLease(agentBuildId: string, toolName: string): LeaseViolation | null {
    const lease = this.getLease(agentBuildId);
    if (!lease) return null;
    const count = (this._stepCounts.get(agentBuildId) || 0) + 1;
    this._stepCounts.set(agentBuildId, count);
    if (count > lease.maxSteps) {
      return {
        severity: "high",
        reason: `Lease violation: exceeded max delegated steps (${lease.maxSteps}) for "${lease.intentSummary}"`,
        signatureId: "lease_step_limit",
      };
    }
    const category = TOOL_CATEGORIES[toolName];
    if (category && !lease.allowedToolFamilies.includes(category)) {
      return {
        severity: "high",
        reason: `Lease violation: delegated agent used ${toolName} (${category}) outside lease scope`,
        signatureId: "lease_tool_family",
      };
    }
    return null;
  }
}
