/**
 * Agent session tracking — maps LLM API calls to local agent identities.
 *
 * Each agent has a unique identity derived from its system prompt, plugin set,
 * and model. This module tracks which agent is making each LLM call, enabling:
 * - Per-agent WAF rules (different injection policies per agent)
 * - Per-agent behavioural baselines (Track 3)
 * - Per-agent canary attribution (Track 2)
 * - Multi-agent session correlation
 */

import { createHash } from "node:crypto";

/** Agent role classification derived from name, channel, and behaviour. */
export interface AgentClassification {
  /** Primary role category. */
  role: string;
  /** Confidence percentage (0-100). */
  confidencePct: number;
  /** Confidence tier for display. */
  confidence: "high" | "medium" | "low";
  /** Colour code for dashboard rendering. */
  colour: string;
  /** Keywords that triggered the classification. */
  signals: string[];
}

/** Agent health and behavioural compliance status. */
export interface AgentHealth {
  /** Overall health: "healthy", "warning", "critical". */
  status: "healthy" | "warning" | "critical";
  /** Health colour for dashboard. */
  colour: string;
  /** Is the agent behaving according to its classification? */
  compliant: boolean;
  /** Compliance detail messages. */
  issues: string[];
  /** Last active relative indicator. */
  lastActiveAgo: string;
  /** Security event rate per 100 calls. */
  eventRate: number;
}

/** Represents a tracked agent session. */
export interface AgentSession {
  /** Stable identity hash: SHA256(systemPrompt + pluginList + modelId). */
  agentBuildId: string;
  /** Human-readable label extracted from system prompt (first 60 chars). */
  agentLabel: string;
  /** Session-scoped unique ID. */
  sessionId: string;
  /** When this session was first seen. */
  startedAt: number;
  /** Total LLM API calls made by this agent session. */
  llmCallCount: number;
  /** Total security events attributed to this agent. */
  securityEventCount: number;
  /** Last LLM call timestamp. */
  lastCallAt: number;
  /** LLM model ID detected from API calls (e.g. "claude-3-opus", "gpt-4"). */
  detectedModel: string;
  /** Channel source if detected (e.g. "slack:C00000001", "whatsapp:+353..."). */
  channelSource: string;
  /** Inferred role classification. */
  classification: AgentClassification;
  /** Tool names available to the agent (from body.tools). */
  toolInventory: string[];
  /** SOUL.md extract — agent's core identity/instructions from early messages. */
  soulExtract: string;
  /** Per-agent LLM cache stats. */
  cache: AgentCacheStats;
  /** Active channels this agent has been seen on. */
  channels: string[];
}

/** Per-agent LLM cache tracking for anomaly detection. */
export interface AgentCacheStats {
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCacheRead: number;
  totalCacheWrite: number;
  /** Running average cache hit ratio (0-1). */
  avgHitRatio: number;
  /** Baseline hit ratio (from first N calls). -1 if not established. */
  baselineHitRatio: number;
  /** Number of calls contributing to the baseline. */
  baselineSamples: number;
  /** Number of calls with cache data. */
  callsWithCache: number;
}

/**
 * Tracks agent sessions and maps LLM calls to agent identities.
 * One instance shared via globalThis across all plugin loads.
 */
export class AgentSessionTracker {
  /** Active sessions keyed by agent label (the stable identity). */
  private _sessions: Map<string, AgentSession> = new Map();
  /** Current active agent label. */
  private _currentLabel = "";

  /**
   * Register or update an agent session from system prompt content.
   *
   * Identity strategy: the extracted LABEL is the primary key, not the
   * prompt skeleton hash. System prompts contain too much dynamic content
   * (conversation context, RAG, tool results) to produce stable hashes.
   * The label — extracted from "- Name: X", "You are X", etc. — is the
   * stable identity that humans recognise.
   *
   * The buildId is still computed for fingerprinting but is NOT used as
   * the session key.
   */
  registerAgent(
    systemPrompt: string,
    pluginList: string[] = [],
    modelId = "unknown",
  ): AgentSession {
    const label = extractLabel(systemPrompt);
    const buildId = computeBuildId(systemPrompt, pluginList, modelId);
    this._currentLabel = label;

    let session = this._sessions.get(label);
    if (!session) {
      session = {
        agentBuildId: buildId,
        agentLabel: label,
        sessionId: createHash("sha256")
          .update(`${label}:${Date.now()}:${Math.random()}`)
          .digest("hex")
          .slice(0, 12),
        startedAt: Date.now(),
        llmCallCount: 0,
        securityEventCount: 0,
        lastCallAt: Date.now(),
        detectedModel: modelId,
        channelSource: "",
        classification: classifyAgent(label, systemPrompt),
        toolInventory: [],
        soulExtract: "",
        cache: {
          totalInputTokens: 0, totalOutputTokens: 0,
          totalCacheRead: 0, totalCacheWrite: 0,
          avgHitRatio: 0, baselineHitRatio: -1,
          baselineSamples: 0, callsWithCache: 0,
        },
        channels: [],
      };
      this._sessions.set(label, session);
    } else {
      // Update build ID to latest (prompt may evolve, label stays stable)
      session.agentBuildId = buildId;
    }

    return session;
  }

  /** Update detected model from LLM API request body. */
  updateModel(model: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && model) {
      session.detectedModel = model;
    }
  }

  /** Update channel source (e.g. "slack:C00000001"). */
  updateChannel(source: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && source) {
      session.channelSource = source;
    }
  }

  /**
   * Update per-agent cache stats from an LLM response.
   * Returns anomaly alerts if cache behaviour deviates from baseline.
   */
  updateCache(usage: {
    inputTokens: number; outputTokens: number;
    cacheReadTokens: number; cacheWriteTokens: number;
  }): { alert: string; severity: "medium" | "high" } | null {
    const session = this._sessions.get(this._currentLabel);
    if (!session || usage.inputTokens === 0) return null;

    const c = session.cache;
    c.totalInputTokens += usage.inputTokens;
    c.totalOutputTokens += usage.outputTokens;
    c.totalCacheRead += usage.cacheReadTokens;
    c.totalCacheWrite += usage.cacheWriteTokens;
    c.callsWithCache++;

    const hitRatio = usage.inputTokens > 0
      ? usage.cacheReadTokens / usage.inputTokens : 0;

    // Running average (exponential moving average, alpha=0.3)
    c.avgHitRatio = c.callsWithCache === 1
      ? hitRatio
      : c.avgHitRatio * 0.7 + hitRatio * 0.3;

    // Establish baseline from first 5 calls
    const BASELINE_WINDOW = 5;
    if (c.baselineSamples < BASELINE_WINDOW) {
      c.baselineSamples++;
      c.baselineHitRatio = c.baselineSamples === 1
        ? hitRatio
        : ((c.baselineHitRatio * (c.baselineSamples - 1)) + hitRatio) / c.baselineSamples;
      return null; // Still learning baseline
    }

    // Anomaly detection: compare current ratio to baseline
    // 1. Cache ratio drop >30% — possible prompt injection/tampering
    if (c.baselineHitRatio > 0.3 && hitRatio < c.baselineHitRatio * 0.5) {
      return {
        alert: `Cache hit ratio dropped to ${Math.round(hitRatio * 100)}% (baseline: ${Math.round(c.baselineHitRatio * 100)}%) — possible system prompt change`,
        severity: "high",
      };
    }

    // 2. Zero cache hits when baseline expects them
    if (c.baselineHitRatio > 0.5 && hitRatio === 0) {
      return {
        alert: `Zero cache hits (baseline: ${Math.round(c.baselineHitRatio * 100)}%) — system prompt may have been replaced`,
        severity: "high",
      };
    }

    // 3. Unusual cache write spike (>3x baseline write ratio)
    const baselineWriteRatio = c.totalCacheWrite / Math.max(1, c.totalInputTokens - usage.inputTokens);
    const currentWriteRatio = usage.cacheWriteTokens / Math.max(1, usage.inputTokens);
    if (c.callsWithCache > BASELINE_WINDOW && baselineWriteRatio > 0 && currentWriteRatio > baselineWriteRatio * 3) {
      return {
        alert: `Cache write spike: ${Math.round(currentWriteRatio * 100)}% of input (baseline: ${Math.round(baselineWriteRatio * 100)}%) — possible prompt stuffing`,
        severity: "medium",
      };
    }

    return null;
  }

  /** Detect and record the channel from prompt metadata. */
  updateChannelFromPrompt(prompt: string): string | null {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return null;
    const ch = detectChannel(prompt);
    if (ch && !session.channels.includes(ch)) {
      session.channels.push(ch);
    }
    return ch;
  }

  /** Update tool inventory from body.tools array. Only sets once (first call). */
  updateTools(tools: string[]): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && tools.length > 0 && session.toolInventory.length === 0) {
      session.toolInventory = tools;
      // Re-classify with tool data for better accuracy
      session.classification = classifyAgentWithTools(
        session.agentLabel, "", session.toolInventory,
      );
    }
  }

  /** Update SOUL extract from early messages. Only sets once. */
  updateSoul(soul: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && soul && !session.soulExtract) {
      session.soulExtract = soul.slice(0, 500);
      // Re-classify with SOUL data
      session.classification = classifyAgentWithTools(
        session.agentLabel, session.soulExtract, session.toolInventory,
      );
    }
  }

  /** Record an LLM API call for the current agent. */
  recordLlmCall(): AgentSession | null {
    const session = this._sessions.get(this._currentLabel);
    if (session) {
      session.llmCallCount++;
      session.lastCallAt = Date.now();
    }
    return session ?? null;
  }

  /** Record a security event for the current agent. */
  recordSecurityEvent(count = 1): void {
    const session = this._sessions.get(this._currentLabel);
    if (session) {
      session.securityEventCount += count;
    }
  }

  /** Get the current active agent session. */
  getCurrentSession(): AgentSession | null {
    return this._sessions.get(this._currentLabel) ?? null;
  }

  /** Get the current agent build ID. */
  getCurrentBuildId(): string {
    const session = this._sessions.get(this._currentLabel);
    return session?.agentBuildId ?? "";
  }

  /** Get all tracked agent sessions. */
  getAllSessions(): AgentSession[] {
    return [...this._sessions.values()];
  }

  /** Get session by build ID. */
  getSession(buildId: string): AgentSession | null {
    // Search by build ID (secondary key)
    for (const session of this._sessions.values()) {
      if (session.agentBuildId === buildId) return session;
    }
    return null;
  }

  /** Get session by label (primary key). */
  getSessionByLabel(label: string): AgentSession | null {
    return this._sessions.get(label) ?? null;
  }

  /** Reset all session tracking. */
  reset(): void {
    this._sessions.clear();
    this._currentLabel = "";
  }
}

/**
 * Compute a stable agent build ID.
 *
 * Uses a "skeleton" of the system prompt rather than the full text.
 * This makes the ID resilient to:
 * - Dynamic timestamps, dates, session IDs injected into prompts
 * - User names or account-specific context
 * - Retrieved RAG snippets appended to the base prompt
 * - Minor wording tweaks during prompt iteration
 *
 * The skeleton is: first 500 chars of the prompt with numbers, dates,
 * emails, UUIDs, and hex strings normalized to placeholders.
 */
export function computeBuildId(
  systemPrompt: string,
  pluginList: string[],
  modelId: string,
): string {
  const skeleton = extractPromptSkeleton(systemPrompt);
  const components = [
    skeleton,
    pluginList.sort().join(","),
    modelId,
  ];
  return createHash("sha256")
    .update(components.join("\n"))
    .digest("hex")
    .slice(0, 16);
}

/**
 * Extract a stable "skeleton" from a system prompt by normalizing
 * dynamic content to placeholders.
 *
 * Normalizes: timestamps, dates, numbers >4 digits, emails, UUIDs,
 * hex strings >8 chars, IP addresses, URLs with path components.
 * Keeps: the structural words, role definitions, tool descriptions,
 * behavioral instructions — the parts that define the agent's identity.
 */
export function extractPromptSkeleton(prompt: string): string {
  let s = prompt;

  // --- Phase 1: Strip ALL volatile/dynamic blocks ---
  // XML-tagged blocks (system-reminder, context, memory, tool results, etc.)
  s = s.replace(/<[a-z][-a-z_]*[^>]*>[\s\S]*?<\/[a-z][-a-z_]*>/gi, "");
  // OpenClaw system context prefix — per-session metadata
  s = s.replace(/^System:\s*\[.*?\].*?\n/gm, "");
  s = s.replace(/^Sender\s*\(.*?\):.*?\n/gm, "");
  s = s.replace(/^Session\s+\w+:.*?\n/gm, "");
  s = s.replace(/^Channel:.*?\n/gm, "");
  s = s.replace(/^\[.*?\]\s*$/gm, "");
  // Conversation/chat history sections and everything after
  s = s.replace(/(?:^|\n)(?:Current conversation|Recent messages|Conversation history|Chat history|# Environment|gitStatus):?\s*\n[\s\S]*/im, "");

  // --- Phase 2: Take a SHORT identity window ---
  // Agent identity is in the first few sentences. A small window avoids
  // capturing dynamic content (tools, RAG, conversation context).
  s = s.slice(0, 500);

  // --- Phase 3: Normalize dynamic tokens ---
  s = s.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>");
  s = s.replace(/\b\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g, "<DATE>");
  s = s.replace(/\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?\b/g, "<TIME>");
  s = s.replace(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, "<EMAIL>");
  s = s.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "<IP>");
  s = s.replace(/\b[0-9a-f]{7,}\b/gi, "<HEX>");
  s = s.replace(/\b\d{4,}\b/g, "<NUM>");
  s = s.replace(/https?:\/\/[^\s<>"']+/g, "<URL>");
  s = s.replace(/(?:GMT|UTC)[+-]\d{1,2}(?::\d{2})?/g, "<TZ>");
  s = s.replace(/(?:\/[\w.-]+){2,}/g, "<PATH>");

  // Collapse whitespace
  s = s.replace(/\s+/g, " ").trim();

  return s;
}

/**
 * Extract a short, snappy agent name from system prompt.
 *
 * Handles multiple formats:
 * 1. OpenClaw IDENTITY.md: "- Name: PJ" or "- Name: Coach Alessandra"
 * 2. "You are [Name/Role]" — with or without article (a/an/the)
 * 3. "- Creature: X" (OpenClaw IDENTITY.md secondary)
 * 4. "My name is [X]" / "I am [X]" / "called [X]" patterns
 * 5. Markdown heading: "# [AgentName]"
 * 6. Fallback: first meaningful line, cleaned up
 *
 * Skips OpenClaw system context prefixes (timestamps, session metadata).
 */
function extractLabel(systemPrompt: string): string {
  // Strategy: try multiple extraction approaches in order of confidence.

  // 1. OpenClaw channel/conversation label: "#agent-name" or "conversation_label"
  //    When OpenClaw sends session context, the channel name IS the agent identity.
  const channelMatch = systemPrompt.match(/"conversation_label"\s*:\s*"#?([^"]+)"/);
  if (channelMatch) {
    let name = channelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.split(/[-_]/).map(w =>
      w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)
    ).join(" ");
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2a. Slack channel header: "Slack message in #channel-name"
  const slackChannelMatch = systemPrompt.match(/Slack\s+message\s+in\s+#([^\s]+)/i);
  if (slackChannelMatch) {
    let name = slackChannelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.split(/[-_]/).map(w =>
      w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)
    ).join(" ");
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2b. WhatsApp header: "WhatsApp message from [Name]" or "WhatsApp group [Name]"
  const waMatch = systemPrompt.match(/WhatsApp\s+(?:message|group)\s+(?:from\s+|in\s+)?["']?([^"'\n]+)/i);
  if (waMatch) {
    const name = waMatch[1].trim().replace(/\s*\(.*?\)\s*$/, ""); // strip phone in parens
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2c. TUI / terminal: "TUI session" or "terminal session" — use agent name from session key
  //     Session keys: "agent:main:tui:..." → extract "main"
  const tuiMatch = systemPrompt.match(/(?:TUI|terminal)\s+(?:session|message)/i);
  if (tuiMatch) {
    // Try to find agent name from session key pattern in metadata
    const agentKeyMatch = systemPrompt.match(/agent:([^:]+):/);
    if (agentKeyMatch) {
      let name = agentKeyMatch[1].trim();
      name = name.split(/[-_]/).map(w =>
        w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)
      ).join(" ");
      if (name.length > 1 && name.length < 50) return name;
    }
  }

  // 3. Try section-based extraction (framework preamble + agent SOUL.md)
  const sections = systemPrompt.split(/\n---+\n/);
  const candidates = sections.length > 1
    ? [sections[sections.length - 1], systemPrompt]
    : [systemPrompt];

  for (const text of candidates) {
    const label = _extractLabelFromText(text);
    if (label) return label;
  }
  return "Unknown Agent";
}

/** Extract agent label from a single text block. Returns null if no confident match. */
function _extractLabelFromText(text: string): string | null {
  // 1. OpenClaw IDENTITY.md format: "- Name: X" (highest confidence)
  const nameMatch = text.match(/-\s*Name:\s*(.+)/i);
  if (nameMatch) {
    const name = nameMatch[1].trim();
    if (name.length > 1 && name.length < 60) return name;
  }

  // 2. "You are [Name/Role]" — article is optional
  //    Use the LAST match in the text, not the first — the agent's identity
  //    is typically after any framework preamble.
  const roleMatches = [...text.matchAll(
    /[Yy]ou\s+are\s+(?:a\s+|an\s+|the\s+)?(.+?)(?:\.|,|\n|$)/g,
  )];
  if (roleMatches.length > 0) {
    // Prefer the last "You are" match (agent identity, not framework)
    const match = roleMatches[roleMatches.length - 1];
    let role = match[1].trim();
    role = role.replace(/\s+(?:at|for|who|that|which|specializing|working|based|created|developed|built|made|designed|powered)\s+.*/i, "");
    if (role === role.toLowerCase()) {
      role = role.replace(/\b\w/g, (c) => c.toUpperCase());
    }
    if (role.length > 1 && role.length < 50) return role;
  }

  // 3. "- Creature: X" (OpenClaw IDENTITY.md secondary)
  const creatureMatch = text.match(/-\s*Creature:\s*(.+)/i);
  if (creatureMatch) {
    const creature = creatureMatch[1].trim();
    if (creature.length > 3 && creature.length < 60) {
      return creature.replace(/\b\w/g, (c) => c.toUpperCase());
    }
  }

  // 4. "My name is X" / "I am X" / "called X"
  const selfIdMatch = text.match(
    /(?:[Mm]y\s+name\s+is|I\s+am|I'm|[Cc]alled)\s+([A-Z][A-Za-z0-9 _-]{1,40})(?:\.|,|\n|$)/,
  );
  if (selfIdMatch) {
    const name = selfIdMatch[1].trim();
    if (name.length > 1 && name.length < 50) return name;
  }

  // 5. Markdown heading: "# AgentName"
  const headingMatch = text.match(/^#\s+(.{2,40})$/m);
  if (headingMatch) {
    const heading = headingMatch[1].trim();
    if (heading.length > 1 && heading.length < 50 &&
        !/^(system|instructions|config|settings|readme)/i.test(heading)) {
      return heading;
    }
  }

  // 6. Fallback — only accept short, name-like strings (not instructions)
  //    Reject lines that look like instructions, sentences, or descriptions.
  //    A valid name is typically 1-4 words, no verbs, no punctuation mid-line.
  const firstLine = text
    .split("\n")
    .map((l) => l.trim())
    .find((l) =>
      l.length > 2 &&
      l.length < 40 &&
      !l.startsWith("#") &&
      !l.startsWith("<!--") &&
      !l.startsWith("System:") &&
      !l.startsWith("- ") &&
      !/^\d{4}-\d{2}-\d{2}/.test(l) &&
      !/^\[.*\]$/.test(l) &&
      // Reject instruction-like text: starts with verb, contains commas, "you", "when", etc.
      !/^(when|if|do|don't|always|never|you |respond|make|use|keep|try|be |note|remember|ensure|for |the |this |please)/i.test(l) &&
      // Reject sentences (more than 5 words)
      l.split(/\s+/).length <= 5,
    );
  if (!firstLine) return null;
  return firstLine;
}

// ===================================================================
// Agent role classifier — keyword-based, zero dependencies
// ===================================================================

/** Role taxonomy with keyword signals. Ordered by specificity (most specific first). */
const ROLE_TAXONOMY: { role: string; keywords: RegExp }[] = [
  { role: "Security Research",    keywords: /security|threat|vulnerab|pentest|exploit|malware|incident|forensic|soc\b|siem|ids|ips|firewall/i },
  { role: "DevOps / SRE",        keywords: /devops|sre\b|deploy|infra|kubernetes|k8s|docker|terraform|ansible|ci\s*\/?\s*cd|pipeline|monitoring|grafana|prometheus/i },
  { role: "System Admin",        keywords: /sysadmin|system\s*admin|server|linux|network\s*admin|dns|dhcp|ldap|active\s*directory/i },
  { role: "Network Engineering",  keywords: /network|router|switch|vlan|bgp|ospf|firewall\s*rule|palo\s*alto|juniper|cisco/i },
  { role: "Software Engineering", keywords: /software|develop|program|code|engineer|fullstack|backend|frontend|api\b|microservice/i },
  { role: "Data / Analytics",     keywords: /data\s*scien|analytics|machine\s*learn|ml\b|ai\b|model|dataset|pipeline|etl|warehouse/i },
  { role: "Customer Support",     keywords: /support|customer|helpdesk|ticket|billing|account\s*issue|service\s*desk|crm/i },
  { role: "Sales / Outreach",     keywords: /sales|outreach|prospect|lead\s*gen|crm|pipeline|deal|quota|revenue/i },
  { role: "Research",             keywords: /research|investigat|analy[sz]|report|study|academic|paper|journal|semicond|alpha/i },
  { role: "Coaching / Training",  keywords: /coach|train|mentor|fitness|endurance|athlete|workout|nutrition|performance/i },
  { role: "Writing / Content",    keywords: /writ|content|blog|article|copy|editor|journalist|marketing\s*content/i },
  { role: "Legal / Compliance",   keywords: /legal|compliance|regulat|audit|policy|gdpr|hipaa|sox\b|contract/i },
  { role: "Finance",              keywords: /financ|accounting|budget|invest|portfolio|trading|revenue|forecast/i },
  { role: "Personal Assistant",   keywords: /personal|assistant|scheduler|organiz|reminder|task\s*manag|daily|general\s*purpose/i },
];

/**
 * Classify an agent's role from its label and system prompt content.
 * Uses keyword matching against a role taxonomy — no LLM call needed.
 *
 * Strategy: check the LABEL first (high confidence), then fall back to
 * the system prompt (inferred). This prevents noisy metadata in the
 * prompt from overriding the agent's actual identity.
 */
/** Build a classification result with colour and confidence percentage. */
function makeClassification(
  role: string, pct: number, signals: string[],
): AgentClassification {
  const confidence = pct >= 80 ? "high" : pct >= 50 ? "medium" : "low";
  // Colour: green for high, blue for medium, grey for low
  const colour = pct >= 80 ? "#3fb950" : pct >= 50 ? "#58a6ff" : "#8b949e";
  return { role, confidencePct: pct, confidence, colour, signals };
}

/**
 * Classify an agent's role from its label and system prompt content.
 * Uses keyword matching against a role taxonomy — no LLM call needed.
 *
 * Confidence scoring:
 *   90% — role keyword in agent label (explicit naming)
 *   70% — role keyword in SOUL.md "You are a [role]" declaration
 *   40% — role keyword found in general prompt metadata
 *   10% — no match, "General Agent"
 *
 * Multiple signal matches boost confidence by 5% each (capped at 95%).
 */
export function classifyAgent(label: string, systemPrompt: string): AgentClassification {
  // 1. Match against label first — highest confidence signal
  const labelLower = label.toLowerCase();
  for (const { role, keywords } of ROLE_TAXONOMY) {
    const matches = [...labelLower.matchAll(new RegExp(keywords.source, "gi"))];
    if (matches.length > 0) {
      const pct = Math.min(95, 90 + (matches.length - 1) * 5);
      return makeClassification(role, pct, matches.map(m => m[0]));
    }
  }

  // 2. Extract SOUL.md content — look for "You are a [role]" patterns
  const soulMatch = systemPrompt.match(
    /[Yy]ou\s+are\s+(?:a\s+|an\s+|the\s+)?(.{10,200})(?:\.|$)/m,
  );
  const soulText = soulMatch ? soulMatch[1].toLowerCase() : "";

  if (soulText) {
    for (const { role, keywords } of ROLE_TAXONOMY) {
      const matches = [...soulText.matchAll(new RegExp(keywords.source, "gi"))];
      if (matches.length > 0) {
        const pct = Math.min(85, 70 + (matches.length - 1) * 5);
        return makeClassification(role, pct, matches.map(m => m[0]));
      }
    }
  }

  // 3. Last resort: scan the full prompt
  const fullLower = systemPrompt.toLowerCase();
  for (const { role, keywords } of ROLE_TAXONOMY) {
    const matches = [...fullLower.matchAll(new RegExp(keywords.source, "gi"))];
    if (matches.length > 0) {
      const pct = Math.min(60, 40 + (matches.length - 1) * 5);
      return makeClassification(role, pct, matches.map(m => m[0]));
    }
  }

  return makeClassification("General Agent", 10, []);
}

/** Tool name patterns that indicate specific roles. */
const TOOL_ROLE_SIGNALS: { role: string; tools: RegExp }[] = [
  { role: "DevOps / SRE",        tools: /deploy|kubernetes|docker|terraform|ansible|helm|kubectl|aws|gcloud|azure/i },
  { role: "Software Engineering", tools: /code|compile|build|test|lint|git|npm|pip|cargo|debug|exec|write_file|read_file/i },
  { role: "System Admin",        tools: /ssh|systemctl|service|cron|mount|useradd|passwd|iptables/i },
  { role: "Network Engineering",  tools: /ping|traceroute|nslookup|dig|netstat|snmp|bgp|route/i },
  { role: "Data / Analytics",     tools: /query|sql|bigquery|spark|pandas|jupyter|notebook|dataset/i },
  { role: "Customer Support",     tools: /ticket|zendesk|intercom|crm|freshdesk|jira.*service/i },
  { role: "Sales / Outreach",     tools: /salesforce|hubspot|outreach|email.*send|linkedin|prospect/i },
  { role: "Research",             tools: /search|web_fetch|browser|scrape|crawl|arxiv|scholar/i },
  { role: "Writing / Content",    tools: /publish|wordpress|medium|draft|edit.*doc|notion/i },
  { role: "Personal Assistant",   tools: /calendar|schedule|remind|todo|weather|timer/i },
];

/**
 * Enhanced classifier that uses tools + SOUL.md + label.
 * Called when new data (tools or SOUL) becomes available.
 */
export function classifyAgentWithTools(
  label: string, soulExtract: string, tools: string[],
): AgentClassification {
  // Start with base classification
  const base = classifyAgent(label, soulExtract);

  // If already high confidence, keep it
  if (base.confidencePct >= 80) return base;

  // Try to upgrade using tool inventory — but ONLY if base is General Agent
  // or if tools confirm the same role. All OpenClaw agents share base tools
  // (Read, Write, exec, etc.) so generic tools shouldn't override a label match.
  if (tools.length > 0 && (base.role === "General Agent" || base.confidencePct < 50)) {
    const toolStr = tools.join(" ").toLowerCase();
    for (const { role, tools: pattern } of TOOL_ROLE_SIGNALS) {
      const matches = [...toolStr.matchAll(new RegExp(pattern.source, "gi"))];
      if (matches.length >= 2) { // Require 2+ tool matches to classify from tools alone
        const toolPct = Math.min(75, 50 + matches.length * 5);
        const signals = [...base.signals, ...matches.map(m => "tool:" + m[0])];
        return makeClassification(role, toolPct, signals);
      }
    }
  } else if (tools.length > 0 && base.confidencePct >= 50) {
    // Tools confirm existing classification — boost confidence
    const toolStr = tools.join(" ").toLowerCase();
    for (const { role, tools: pattern } of TOOL_ROLE_SIGNALS) {
      if (role === base.role) {
        const matches = [...toolStr.matchAll(new RegExp(pattern.source, "gi"))];
        if (matches.length > 0) {
          const boosted = Math.min(95, base.confidencePct + 10);
          const signals = [...base.signals, ...matches.map(m => "tool:" + m[0])];
          return makeClassification(role, boosted, signals);
        }
      }
    }
  }

  // Try SOUL.md if we have it and base is still weak
  if (soulExtract && base.confidencePct < 50) {
    const soulResult = classifyAgent(label, soulExtract);
    if (soulResult.confidencePct > base.confidencePct) {
      return soulResult;
    }
  }

  return base;
}

// ===================================================================
// Channel detection — extract channel type from prompt metadata
// ===================================================================

/** Detect the channel type from OpenClaw prompt metadata. */
export function detectChannel(prompt: string): string | null {
  if (/Slack\s+message/i.test(prompt)) return "slack";
  if (/WhatsApp\s+message/i.test(prompt)) return "whatsapp";
  if (/TUI\s+(?:session|message)/i.test(prompt) || /openclaw-tui/i.test(prompt)) return "tui";
  if (/Email\s+(?:message|from)/i.test(prompt) || /Gmail\s+/i.test(prompt)) return "email";
  if (/Cron\s+(?:job|task|trigger)/i.test(prompt) || /scheduled\s+task/i.test(prompt)) return "cron";
  if (/Discord\s+message/i.test(prompt)) return "discord";
  if (/Telegram\s+message/i.test(prompt)) return "telegram";
  if (/Teams\s+message/i.test(prompt)) return "teams";
  return null;
}
