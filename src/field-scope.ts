/**
 * Per-tool field scoping and per-agent category exemptions for obfuscation.
 *
 * Reduces false positives by only scanning relevant fields per tool and
 * exempting entity categories that the agent's contract allows.
 */

import { resolveAgentContract } from "./contracts.js";
import type { FieldScopingConfig, ScopeDecision } from "./types.js";

/** Simple wildcard matching (supports * and ?). */
function wildcardMatch(value: string, pattern: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

export class FieldScopeResolver {
  private readonly toolPatterns: Array<{ pattern: string; scanFields: Set<string> }>;
  private readonly neverScanFields: Set<string>;
  private readonly defaultScanFields: Set<string>;
  private readonly useContractExemptions: boolean;
  private readonly enabled: boolean;

  constructor(config?: FieldScopingConfig) {
    if (!config) {
      this.enabled = false;
      this.toolPatterns = [];
      this.neverScanFields = new Set();
      this.defaultScanFields = new Set();
      this.useContractExemptions = false;
      return;
    }

    this.enabled = true;
    this.neverScanFields = new Set(config.neverScanFields ?? []);
    this.defaultScanFields = new Set(config.defaultScanFields ?? []);
    this.useContractExemptions = config.useContractExemptions ?? false;

    this.toolPatterns = [];
    for (const [pattern, rule] of Object.entries(config.toolFields ?? {})) {
      this.toolPatterns.push({ pattern, scanFields: new Set(rule.scanFields) });
    }
  }

  /** Resolve which fields to scan for a given tool name. */
  resolveToolScope(toolName: string): ScopeDecision {
    if (!this.enabled) {
      return { mode: "all", scanFields: new Set(), neverScanFields: new Set() };
    }

    // Find first matching tool pattern
    for (const { pattern, scanFields } of this.toolPatterns) {
      if (wildcardMatch(toolName, pattern)) {
        return {
          mode: "selected",
          scanFields,
          neverScanFields: this.neverScanFields,
        };
      }
    }

    // No match — use default
    if (this.defaultScanFields.size > 0) {
      return {
        mode: "selected",
        scanFields: this.defaultScanFields,
        neverScanFields: this.neverScanFields,
      };
    }

    // Empty defaultScanFields = scan everything (backward compatible)
    return { mode: "all", scanFields: new Set(), neverScanFields: this.neverScanFields };
  }

  /**
   * Resolve which entity categories are exempt from obfuscation for an agent.
   * Uses the agent contract's allowedDataClasses — those categories are data
   * the agent is trusted to handle, so obfuscating them is counterproductive.
   */
  resolveAgentExemptions(agentLabel: string, role: string): Set<string> {
    if (!this.enabled || !this.useContractExemptions) {
      return new Set();
    }

    const contract = resolveAgentContract(agentLabel, role);
    return new Set(contract.allowedDataClasses);
  }

  /** Check if a field should be scanned given the resolved scope. */
  shouldScanField(fieldName: string, scope: ScopeDecision): boolean {
    if (scope.neverScanFields.has(fieldName)) return false;
    if (scope.mode === "all") return true;
    return scope.scanFields.has(fieldName);
  }
}
