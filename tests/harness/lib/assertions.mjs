/**
 * Assertion functions for Shroud integration tests.
 *
 * Each function throws an AssertionError on failure with a descriptive message.
 */

class AssertionError extends Error {
  constructor(message) {
    super(message);
    this.name = "AssertionError";
  }
}

/**
 * Verify that the LLM never saw any of the real values in its request log.
 */
export function assertLlmDidNotSee(requestLog, realValues) {
  const allText = JSON.stringify(requestLog);
  for (const val of realValues) {
    if (allText.includes(val)) {
      throw new AssertionError(`LLM saw real value: "${val}"`);
    }
  }
}

/**
 * Verify that the LLM request log contains expected patterns (regex strings).
 */
export function assertLlmSawPattern(requestLog, patterns) {
  const allText = JSON.stringify(requestLog);
  for (const pat of patterns) {
    if (!new RegExp(pat).test(allText)) {
      throw new AssertionError(`LLM did not see expected pattern: ${pat}`);
    }
  }
}

/**
 * Verify that the final user-facing output contains all original real values.
 */
export function assertUserSees(output, realValues) {
  for (const val of realValues) {
    if (!output.includes(val)) {
      throw new AssertionError(`User output missing real value: "${val}"`);
    }
  }
}

/**
 * Verify the entity count is within expected bounds.
 */
export function assertEntityCount(result, min, max) {
  if (min !== undefined && result.entityCount < min)
    throw new AssertionError(`Entity count ${result.entityCount} < min ${min}`);
  if (max !== undefined && result.entityCount > max)
    throw new AssertionError(`Entity count ${result.entityCount} > max ${max}`);
}

/**
 * Verify that specific PII categories were detected.
 */
export function assertCategories(result, expected) {
  for (const cat of expected) {
    if (!(cat in (result.categories || {})))
      throw new AssertionError(`Category "${cat}" not detected`);
  }
}

/**
 * Verify no CGNAT IP addresses (100.64.0.0/10) leaked to user-facing output.
 * These are used as fake surrogates and should never reach the user.
 */
export function assertNoCgnatLeak(text) {
  const cgnat = /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/g;
  const matches = text.match(cgnat);
  if (matches) throw new AssertionError(`CGNAT IPs leaked to output: ${matches.join(", ")}`);
}

/**
 * Verify no ULA IPv6 addresses (fd00::/8) leaked to user-facing output.
 * These are used as fake surrogates and should never reach the user.
 */
export function assertNoUlaLeak(text) {
  const ula = /\bfd00:[0-9a-fA-F:]+\b/g;
  const matches = text.match(ula);
  if (matches) throw new AssertionError(`ULA IPv6 leaked to output: ${matches.join(", ")}`);
}

/**
 * Verify that obfuscate -> LLM -> deobfuscate produces the original text.
 */
export function assertRoundtrip(obfuscated, deobfuscated, original) {
  if (deobfuscated !== original) {
    throw new AssertionError(
      `Roundtrip failed:\n  Original:     ${original}\n  Deobfuscated: ${deobfuscated}`
    );
  }
}

/**
 * Verify no CGNAT range references leaked to user-facing output.
 * Catches not just exact IPs (100.64.x.y) but also range descriptions
 * that a real LLM generates when summarizing fake networks:
 *   - "100.64.x.x/xx"
 *   - "100.64.0.x/24"
 *   - "100.64.0.0/10"
 *   - "within 100.64.x.x space"
 *   - "100.64.0.0 - 100.127.255.255"
 */
export function assertNoCgnatRangeLeak(text) {
  // Exact CGNAT IPs
  const exactCgnat = /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/g;
  // Wildcard CGNAT descriptions (100.64.x.x, 100.64.0.x, etc.)
  const wildcardCgnat = /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.[x\d]+\.[x\d]+/gi;
  // CGNAT range with CIDR (100.64.0.0/10, 100.64.x.x/xx)
  const cidrCgnat = /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\S*\/\d+/gi;

  const allMatches = [
    ...(text.match(exactCgnat) || []),
    ...(text.match(wildcardCgnat) || []),
    ...(text.match(cidrCgnat) || []),
  ];

  // Deduplicate
  const unique = [...new Set(allMatches)];
  if (unique.length > 0) {
    throw new AssertionError(
      `CGNAT range references leaked to output: ${unique.join(", ")}\n` +
      `This indicates the LLM learned Shroud's fake IP range and is describing it generically.`
    );
  }
}

// ── Agent Identity & Profiling Assertions ──────────────────────

/**
 * Verify each agent has the expected label and classification role.
 * @param {object[]} agents - Agent sessions from /api/agents
 * @param {object[]} expected - Array of { expected_label, expected_role }
 */
export function assertAgentIdentity(agents, expected) {
  for (const exp of expected) {
    const match = agents.find(a =>
      a.agentLabel && a.agentLabel.toLowerCase() === exp.expected_label.toLowerCase()
    );
    if (!match) {
      const labels = agents.map(a => a.agentLabel).join(", ");
      throw new AssertionError(
        `Agent "${exp.expected_label}" not found. Present: ${labels}`
      );
    }
    if (exp.expected_role && match.classification?.role !== exp.expected_role) {
      throw new AssertionError(
        `Agent "${exp.expected_label}" classified as "${match.classification?.role}", expected "${exp.expected_role}"`
      );
    }
  }
}

/**
 * Verify all agents have unique build IDs (no collisions).
 */
export function assertUniqueBuildIds(agents) {
  const ids = agents.map(a => a.agentBuildId);
  const unique = new Set(ids);
  if (unique.size < ids.length) {
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
    const dupeAgents = agents.filter(a => dupes.includes(a.agentBuildId))
      .map(a => `${a.agentLabel}=${a.agentBuildId}`);
    throw new AssertionError(
      `Build ID collision: ${dupeAgents.join(", ")}`
    );
  }
}

/**
 * Verify no agent's soulExtract starts with framework preamble.
 */
export function assertNoFrameworkPreamble(agents) {
  const preambles = [
    "you are a personal assistant running inside openclaw",
    "you are a personal assistant",
  ];
  for (const a of agents) {
    if (!a.soulExtract) continue;
    const lower = a.soulExtract.toLowerCase().trim();
    for (const p of preambles) {
      if (lower.startsWith(p)) {
        throw new AssertionError(
          `Agent "${a.agentLabel}" soulExtract starts with framework preamble: "${a.soulExtract.slice(0, 80)}..."`
        );
      }
    }
  }
}

/**
 * Verify tool inventory is populated for agents that should have it.
 */
export function assertToolInventory(agents, expectedAgents) {
  for (const exp of expectedAgents) {
    const match = agents.find(a =>
      a.agentLabel?.toLowerCase() === exp.expected_label.toLowerCase()
    );
    if (!match) continue;
    if (!match.toolInventory || match.toolInventory.length === 0) {
      throw new AssertionError(
        `Agent "${exp.expected_label}" has empty toolInventory`
      );
    }
  }
}

/**
 * Verify profiling baselines have categories populated.
 */
export function assertCategoryProfile(agents) {
  for (const a of agents) {
    if (!a.profiling) continue;
    if (a.profiling.maturity === "none") continue; // no baseline yet
    if (!a.profiling.knownCategories || a.profiling.knownCategories.length === 0) {
      throw new AssertionError(
        `Agent "${a.agentLabel}" has baseline but empty categoryProfile`
      );
    }
  }
}

/**
 * Verify no duplicate agents (same label appearing twice).
 */
export function assertNoDuplicateAgents(agents) {
  const labels = agents.map(a => a.agentLabel?.toLowerCase());
  const seen = new Set();
  for (const label of labels) {
    if (!label) continue;
    if (seen.has(label)) {
      throw new AssertionError(
        `Duplicate agent label: "${label}"`
      );
    }
    seen.add(label);
  }
}

/**
 * Verify build IDs are stable between two snapshots.
 * @param {object[]} before - Agents before restart
 * @param {object[]} after - Agents after restart
 */
export function assertBuildIdStability(before, after) {
  for (const b of before) {
    const match = after.find(a =>
      a.agentLabel?.toLowerCase() === b.agentLabel?.toLowerCase()
    );
    if (!match) {
      throw new AssertionError(
        `Agent "${b.agentLabel}" disappeared after restart`
      );
    }
    if (match.agentBuildId !== b.agentBuildId) {
      throw new AssertionError(
        `Agent "${b.agentLabel}" build ID changed: ${b.agentBuildId} → ${match.agentBuildId}`
      );
    }
  }
}

/**
 * Verify baselines survived a restart (session counts not reset).
 */
export function assertBaselinePersistence(before, after) {
  for (const b of before) {
    const match = after.find(a =>
      a.agentLabel?.toLowerCase() === b.agentLabel?.toLowerCase()
    );
    if (!match) continue;
    if (match.llmCallCount < b.llmCallCount) {
      throw new AssertionError(
        `Agent "${b.agentLabel}" call count decreased after restart: ${b.llmCallCount} → ${match.llmCallCount}`
      );
    }
  }
}

/**
 * Verify channels are detected for agents that should have them.
 */
export function assertChannelsDetected(agents, expectedAgents) {
  for (const exp of expectedAgents) {
    if (!exp.channel) continue;
    const match = agents.find(a =>
      a.agentLabel?.toLowerCase() === exp.expected_label.toLowerCase()
    );
    if (!match) continue;
    if (!match.channels || match.channels.length === 0) {
      throw new AssertionError(
        `Agent "${exp.expected_label}" has no channels detected (expected: ${exp.channel})`
      );
    }
    if (!match.channels.includes(exp.channel)) {
      throw new AssertionError(
        `Agent "${exp.expected_label}" missing channel "${exp.channel}". Has: ${match.channels.join(", ")}`
      );
    }
  }
}

export { AssertionError };
