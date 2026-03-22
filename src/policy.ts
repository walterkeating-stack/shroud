/**
 * Policy-as-code: load allowlist/denylist from external files or
 * inline patterns with glob and regex support.
 */

import { readFileSync } from "node:fs";
import { Category } from "./types.js";

export interface PolicyMatcher {
  type: "literal" | "glob" | "regex";
  pattern: string;
  compiled: RegExp;
  category?: Category;
}

export interface PolicyRules {
  allowlist: PolicyMatcher[];
  denylist: PolicyMatcher[];
}

export type PolicyPatternInput =
  | string
  | { pattern: string; type?: "literal" | "glob" | "regex"; category?: string };

/**
 * Compile a policy pattern input to a RegExp matcher.
 *
 * - Bare strings are treated as literals
 * - Objects with type:"regex" compile as RegExp
 * - Objects with type:"glob" convert glob wildcards to RegExp
 * - Everything else is literal
 */
function compileMatcher(input: PolicyPatternInput): PolicyMatcher {
  if (typeof input === "string") {
    return {
      type: "literal",
      pattern: input,
      compiled: new RegExp(`^${escapeRegex(input)}$`),
    };
  }

  const type = input.type ?? "literal";
  const category = input.category as Category | undefined;

  if (type === "regex") {
    return {
      type: "regex",
      pattern: input.pattern,
      compiled: new RegExp(input.pattern),
      category,
    };
  }

  if (type === "glob") {
    return {
      type: "glob",
      pattern: input.pattern,
      compiled: globToRegex(input.pattern),
      category,
    };
  }

  return {
    type: "literal",
    pattern: input.pattern,
    compiled: new RegExp(`^${escapeRegex(input.pattern)}$`),
    category,
  };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegex(glob: string): RegExp {
  let regex = "^";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        regex += ".*";
        i++; // skip second *
      } else {
        regex += "[^/]*";
      }
    } else if (c === "?") {
      regex += ".";
    } else {
      regex += escapeRegex(c);
    }
  }
  regex += "$";
  return new RegExp(regex);
}

export class PolicyLoader {
  /**
   * Load policy rules from a JSON file.
   * Expected format: { allowlist: [...], denylist: [...] }
   * Each entry can be a string or { pattern, type, category }.
   */
  static loadFromFile(path: string): PolicyRules {
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    return PolicyLoader.parseInline(raw);
  }

  /**
   * Parse inline policy rules from config.
   */
  static parseInline(raw: {
    allowlist?: PolicyPatternInput[];
    denylist?: PolicyPatternInput[];
  }): PolicyRules {
    return {
      allowlist: (raw.allowlist ?? []).map(compileMatcher),
      denylist: (raw.denylist ?? []).map(compileMatcher),
    };
  }

  /**
   * Merge multiple policy rule sets.
   */
  static merge(...sets: PolicyRules[]): PolicyRules {
    return {
      allowlist: sets.flatMap((s) => s.allowlist),
      denylist: sets.flatMap((s) => s.denylist),
    };
  }

  /**
   * Test a value against an allowlist. Returns true if allowed (should NOT be obfuscated).
   */
  static isAllowed(value: string, rules: PolicyMatcher[]): boolean {
    for (const rule of rules) {
      if (rule.compiled.test(value)) return true;
    }
    return false;
  }

  /**
   * Test a value against a denylist. Returns the matching category if denied (MUST be obfuscated).
   */
  static isDenied(
    value: string,
    rules: PolicyMatcher[],
  ): { denied: boolean; category?: Category } {
    for (const rule of rules) {
      if (rule.compiled.test(value)) {
        return { denied: true, category: rule.category };
      }
    }
    return { denied: false };
  }

  /**
   * Scan text for denylist pattern matches (regex/glob patterns that search within text).
   */
  static scanDenylist(
    text: string,
    rules: PolicyMatcher[],
  ): Array<{ value: string; start: number; end: number; category?: Category }> {
    const matches: Array<{
      value: string;
      start: number;
      end: number;
      category?: Category;
    }> = [];

    for (const rule of rules) {
      if (rule.type === "literal") {
        // Literal: indexOf scan
        let idx = 0;
        while (true) {
          const pos = text.indexOf(rule.pattern, idx);
          if (pos === -1) break;
          matches.push({
            value: rule.pattern,
            start: pos,
            end: pos + rule.pattern.length,
            category: rule.category,
          });
          idx = pos + 1;
        }
      } else {
        // Regex/glob: matchAll
        const re = new RegExp(rule.compiled.source, "g");
        for (const m of text.matchAll(re)) {
          if (m.index !== undefined) {
            matches.push({
              value: m[0],
              start: m.index,
              end: m.index + m[0].length,
              category: rule.category,
            });
          }
        }
      }
    }

    return matches;
  }
}
