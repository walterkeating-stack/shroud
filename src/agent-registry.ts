/**
 * Agent registry — loads the OpenClaw agent inventory from openclaw.json.
 *
 * Instead of guessing agent identity by regex-parsing system prompts,
 * this module reads the authoritative agent registry and channel bindings
 * from ~/.openclaw/openclaw.json. It builds a signal map that resolves
 * structured identifiers (Slack channel IDs, WhatsApp numbers, cron agent
 * IDs, session keys) to canonical agent names in O(1).
 *
 * The registry is loaded once at plugin init (synchronous). Since OpenClaw
 * restarts the gateway when agents change, this is sufficient.
 *
 * If openclaw.json is missing or unreadable, all resolution returns null
 * and the existing regex fallback handles everything — zero regression.
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";

/** A registered OpenClaw agent. */
export interface AgentRegistryEntry {
  /** Agent ID (e.g. "endurance-coach"). */
  id: string;
  /** Canonical display name (e.g. "Coach Alessandra"). */
  canonicalName: string;
  /** Workspace directory path. */
  workspace: string;
  /** Agent config directory path. */
  agentDir: string;
  /** Tools explicitly allowed for this agent (from openclaw.json tools.allow). */
  toolsAllow: string[];
  /** Tools explicitly denied for this agent (from openclaw.json tools.deny). */
  toolsDeny: string[];
  /** Whether the agent runs in a sandbox. */
  sandboxed: boolean;
}

/**
 * Agent registry — resolves agent identity from structured signals.
 *
 * 3-tier identification:
 *   Tier 1: Signal map lookup (Slack channel ID, WhatsApp number, cron ID, session key)
 *   Tier 2: Falls back to caller (regex extraction in agent-session.ts)
 *   Tier 3: Falls back to "main" for TUI/CLI
 */
export class AgentRegistry {
  /** Agent ID → registry entry. */
  private _agents = new Map<string, AgentRegistryEntry>();
  /** Signal key → agent ID. e.g. "slack:C0AMN8NUXPZ" → "main" */
  private _signalMap = new Map<string, string>();
  /** Whether the registry loaded successfully. */
  private _loaded = false;

  /** Load the registry from openclaw.json. Returns true on success. */
  load(openclawDir?: string): boolean {
    const dir = openclawDir || _defaultOpenClawDir();
    const configPath = join(dir, "openclaw.json");

    try {
      const raw = readFileSync(configPath, "utf-8");
      const cfg = JSON.parse(raw);

      // 1. Load agent list
      const agentList = cfg?.agents?.list;
      if (!Array.isArray(agentList)) return false;

      for (const agent of agentList) {
        const id = agent?.id;
        if (!id || typeof id !== "string") continue;

        let name = agent?.identity?.name || agent?.name || id;

        // The "main" agent has name: "main" in config — read IDENTITY.md for real name
        if (id === "main" && name === "main") {
          const ws = agent?.workspace || join(dir, "workspace");
          name = _readIdentityName(ws) || "PJ";
        }

        const tools = agent?.tools || {};
        const entry: AgentRegistryEntry = {
          id,
          canonicalName: name,
          workspace: agent?.workspace || "",
          agentDir: agent?.agentDir || "",
          toolsAllow: Array.isArray(tools.allow) ? tools.allow : [],
          toolsDeny: Array.isArray(tools.deny) ? tools.deny : [],
          sandboxed: agent?.sandbox?.mode !== "off" && !!agent?.sandbox?.docker,
        };
        this._agents.set(id, entry);
      }

      // 2. Build signal map from bindings
      const bindings = cfg?.bindings;
      if (Array.isArray(bindings)) {
        for (const binding of bindings) {
          const agentId = binding?.agentId;
          if (!agentId || !this._agents.has(agentId)) continue;

          const match = binding?.match;
          if (!match) continue;

          const channel = match?.channel;
          const peer = match?.peer;

          if (peer?.id) {
            // Direct binding: slack channel ID or WhatsApp number
            const key = `${channel}:${peer.id}`.toLowerCase();
            this._signalMap.set(key, agentId);
          }

          if (match?.accountId) {
            // Route binding: slack accountId
            const key = `slack-account:${match.accountId}`.toLowerCase();
            this._signalMap.set(key, agentId);
          }
        }
      }

      // 3. Enrich signal map from session keys (captures bindings not in explicit bindings array)
      this._enrichFromSessionKeys(dir);

      this._loaded = true;
      return true;
    } catch {
      return false;
    }
  }

  /** Whether the registry loaded successfully. */
  get loaded(): boolean {
    return this._loaded;
  }

  /** Number of registered agents. */
  get size(): number {
    return this._agents.size;
  }

  /**
   * Resolve agent identity from structured signals in a prompt.
   *
   * Extracts Slack channel IDs, WhatsApp numbers, cron agent IDs, and
   * session keys from the prompt text, then looks them up in the signal map.
   * Returns the canonical agent name, or null if no signal matches.
   */
  resolve(prompt: string): string | null {
    if (!this._loaded || !prompt) return null;

    // 1. Session key: "agent:<id>:" — most reliable, from gateway metadata
    const sessionKeyMatch = prompt.match(/\bagent:([a-z0-9][-a-z0-9]*?):/);
    if (sessionKeyMatch) {
      const id = sessionKeyMatch[1];
      const entry = this._agents.get(id);
      if (entry) return entry.canonicalName;
    }

    // 2. Cron prefix: "[cron:<id> <agent-id>: <schedule>]"
    //    Cron IDs can be UUIDs or named (e.g. "a1b2c3d4-shroud-stale-task-sweep")
    const cronMatch = prompt.match(/\[cron:\S+\s+([a-z0-9][-a-z0-9]*):/);
    if (cronMatch) {
      const id = cronMatch[1];
      const entry = this._agents.get(id);
      if (entry) return entry.canonicalName;
    }

    // 3. Slack channel ID — from conversation_label JSON or raw channel ID
    //    Channel IDs are uppercase: C + 10-11 alphanumeric chars
    const slackLabelMatch = prompt.match(/"conversation_label"\s*:\s*"#?([^"]+)"/);
    if (slackLabelMatch) {
      // conversation_label might be a channel name like "#semiconalpha-research"
      // or a channel ID like "C0AN09SPT29". Try both.
      const label = slackLabelMatch[1].trim();
      // Try as channel ID first
      const key = `slack:${label}`.toLowerCase();
      const agentId = this._signalMap.get(key);
      if (agentId) return this._agents.get(agentId)!.canonicalName;
      // Try matching the label against agent IDs (channel names often match)
      for (const [id, entry] of this._agents) {
        if (label.toLowerCase().includes(id)) return entry.canonicalName;
      }
    }

    // Try raw Slack channel ID anywhere in the prompt
    const channelIdMatch = prompt.match(/\b(C[A-Z0-9]{8,12})\b/);
    if (channelIdMatch) {
      const key = `slack:${channelIdMatch[1]}`.toLowerCase();
      const agentId = this._signalMap.get(key);
      if (agentId) return this._agents.get(agentId)!.canonicalName;
    }

    // 4. WhatsApp sender_id or e164
    const waMatch = prompt.match(/"(?:sender_id|e164)"\s*:\s*"(\+\d+)"/);
    if (waMatch) {
      const key = `whatsapp:${waMatch[1]}`.toLowerCase();
      const agentId = this._signalMap.get(key);
      if (agentId) return this._agents.get(agentId)!.canonicalName;
      // Number not in signal map (ambiguous or unbound).
      // Try to identify from prompt content (IDENTITY.md "- Name:" or BOOT.md header).
      const nameFromPrompt = this._resolveFromPromptIdentity(prompt);
      if (nameFromPrompt) return nameFromPrompt;
      // Final fallback: OpenClaw routes unbound WhatsApp numbers to main agent.
      const main = this._agents.get("main");
      if (main) return main.canonicalName;
    }

    // 5. Slack "message in #channel-name" header
    const slackHeaderMatch = prompt.match(/Slack\s+message\s+in\s+#([^\s]+)/i);
    if (slackHeaderMatch) {
      const channelName = slackHeaderMatch[1].toLowerCase().replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
      // Try matching against agent IDs, canonical names, and slack account routes
      for (const [id, entry] of this._agents) {
        if (channelName.includes(id) || channelName.includes(id.replace(/-/g, ""))) {
          return entry.canonicalName;
        }
        // Match against canonical name parts (e.g. "coach-alessandra" matches "Coach Alessandra")
        const nameLower = entry.canonicalName.toLowerCase().replace(/\s+/g, "-");
        if (channelName.includes(nameLower) || nameLower.includes(channelName)) {
          return entry.canonicalName;
        }
      }
      // Try slack-account signal map (from route bindings)
      const accountKey = `slack-account:${channelName}`;
      const accountAgent = this._signalMap.get(accountKey);
      if (accountAgent) return this._agents.get(accountAgent)!.canonicalName;
    }

    // 6. BOOT.md header: "# BOOT (Agent Name)"
    const bootMatch = prompt.match(/# BOOT \(([^)]+)\)/);
    if (bootMatch) {
      let name = bootMatch[1].trim();
      if (name.includes(" — ")) name = name.split(" — ")[0].trim();
      if (name.includes(" - ")) name = name.split(" - ")[0].trim();
      // Match against known canonical names
      for (const entry of this._agents.values()) {
        if (entry.canonicalName.toLowerCase() === name.toLowerCase()) {
          return entry.canonicalName;
        }
      }
      // Could be a valid name we don't have in registry — return as-is
      if (name.length > 1 && name.length < 50) return name;
    }

    // 7. TUI/CLI detection → main agent
    if (/(?:"label"\s*:\s*"(?:cli|openclaw-tui)"|\bterminal\s+session\b|\bTUI\s+session\b)/i.test(prompt)) {
      const main = this._agents.get("main");
      if (main) return main.canonicalName;
    }

    return null;
  }

  /** Get canonical name for an agent ID. Returns the ID title-cased if not found. */
  getCanonicalName(agentId: string): string {
    const entry = this._agents.get(agentId);
    if (entry) return entry.canonicalName;
    // Fallback: title-case the ID
    return agentId.replace(/[-_]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  }

  /** Get all registered agents. */
  getAllAgents(): AgentRegistryEntry[] {
    return [...this._agents.values()];
  }

  /** Get registry entry by ID. */
  getAgent(agentId: string): AgentRegistryEntry | undefined {
    return this._agents.get(agentId);
  }

  /**
   * Check if a tool call violates the agent's configured sandbox boundary.
   *
   * Returns a reason string if violated, null if allowed.
   * Checks both deny lists and allow lists from openclaw.json.
   */
  checkToolBoundary(agentId: string, toolName: string): string | null {
    const entry = this._agents.get(agentId);
    if (!entry) return null; // Unknown agent — can't check

    const toolLower = toolName.toLowerCase();

    // Check deny list first — explicitly forbidden tools
    if (entry.toolsDeny.length > 0) {
      for (const denied of entry.toolsDeny) {
        if (denied.toLowerCase() === toolLower) {
          return `Tool "${toolName}" is in agent "${entry.canonicalName}"'s deny list`;
        }
      }
    }

    // Check allow list — if an allow list exists, only listed tools are permitted
    if (entry.toolsAllow.length > 0) {
      // Known OpenClaw tool group expansions
    const TOOL_GROUPS: Record<string, string[]> = {
      "group:fs": ["read", "write", "edit", "list", "glob", "find", "stat", "mkdir", "rm", "mv", "cp"],
      "group:web": ["web_search", "web_fetch"],
      "group:memory": ["memory_search", "memory_get", "memory_set", "memory_delete"],
      "group:exec": ["exec", "bash", "run"],
    };
    const allowed = entry.toolsAllow.some(a => {
        const al = a.toLowerCase();
        if (al.startsWith("group:")) {
          const groupTools = TOOL_GROUPS[al];
          // If we know the group, check membership; otherwise don't flag (can't evaluate)
          return groupTools ? groupTools.includes(toolLower) : true;
        }
        return al === toolLower;
      });
      if (!allowed) {
        return `Tool "${toolName}" is not in agent "${entry.canonicalName}"'s allow list`;
      }
    }

    return null;
  }

  /**
   * Try to identify the agent from "- Name:" or "# BOOT (...)" in the prompt.
   * Matches the extracted name against known agents in the registry.
   */
  private _resolveFromPromptIdentity(prompt: string): string | null {
    // "- Name: X" from IDENTITY.md
    const nameMatch = prompt.match(/-\s*Name:\s*(.+)/i);
    if (nameMatch) {
      const name = nameMatch[1].trim();
      for (const entry of this._agents.values()) {
        if (entry.canonicalName.toLowerCase() === name.toLowerCase()) return entry.canonicalName;
      }
    }
    // "# BOOT (Agent Name)" or "# BOOT (Agent Name — Alias)"
    const bootMatch = prompt.match(/# BOOT \(([^)]+)\)/);
    if (bootMatch) {
      let name = bootMatch[1].trim();
      if (name.includes(" — ")) name = name.split(" — ")[0].trim();
      if (name.includes(" - ")) name = name.split(" - ")[0].trim();
      for (const entry of this._agents.values()) {
        if (entry.canonicalName.toLowerCase() === name.toLowerCase()) return entry.canonicalName;
      }
    }
    return null;
  }

  /** Check if a label matches any known agent name. */
  isKnownAgent(label: string): boolean {
    const lower = label.toLowerCase().trim();
    for (const entry of this._agents.values()) {
      if (entry.canonicalName.toLowerCase() === lower) return true;
      if (entry.id === lower) return true;
    }
    return false;
  }

  /** Enrich the signal map from per-agent session keys. */
  private _enrichFromSessionKeys(openclawDir: string): void {
    const agentsDir = join(openclawDir, "agents");
    try {
      // First pass: collect all signal→agentId mappings (may have duplicates)
      const candidates = new Map<string, Set<string>>(); // signalKey → set of agentIds
      const agentDirs = readdirSync(agentsDir);
      for (const agentId of agentDirs) {
        if (!this._agents.has(agentId)) continue;
        const sessionsFile = join(agentsDir, agentId, "sessions", "sessions.json");
        try {
          const raw = readFileSync(sessionsFile, "utf-8");
          const sessions = JSON.parse(raw);
          for (const key of Object.keys(sessions)) {
            const waMatch = key.match(/whatsapp:direct:(\+\d+)/);
            if (waMatch) {
              const signalKey = `whatsapp:${waMatch[1]}`.toLowerCase();
              if (!candidates.has(signalKey)) candidates.set(signalKey, new Set());
              candidates.get(signalKey)!.add(agentId);
            }
            const slackMatch = key.match(/slack:channel:([a-z0-9]+)/);
            if (slackMatch) {
              const signalKey = `slack:${slackMatch[1]}`.toLowerCase();
              if (!candidates.has(signalKey)) candidates.set(signalKey, new Set());
              candidates.get(signalKey)!.add(agentId);
            }
          }
        } catch { /* sessions.json may not exist */ }
      }

      // Second pass: only add unambiguous signals (one agent) to the signal map.
      // Ambiguous signals (same number/channel used by multiple agents) are skipped —
      // the resolve() fallback handles them (e.g. default to "main" for WhatsApp).
      for (const [signalKey, agentIds] of candidates) {
        if (this._signalMap.has(signalKey)) continue; // explicit binding takes priority
        if (agentIds.size === 1) {
          this._signalMap.set(signalKey, [...agentIds][0]);
        }
      }
    } catch { /* agents dir may not exist */ }
  }
}

/** Read "- Name: X" from an IDENTITY.md file. */
function _readIdentityName(workspace: string): string | null {
  try {
    const identityPath = join(workspace, "IDENTITY.md");
    const content = readFileSync(identityPath, "utf-8");
    const match = content.match(/-\s*Name:\s*(.+)/i);
    if (match) return match[1].trim();
  } catch { /* file may not exist */ }
  return null;
}

/** Default OpenClaw directory — checks env vars, then standard paths. */
function _defaultOpenClawDir(): string {
  // OPENCLAW_CONFIG_PATH points to openclaw.json directly — use its parent dir
  const configPath = process.env.OPENCLAW_CONFIG_PATH;
  if (configPath) {
    return dirname(configPath);
  }
  // OPENCLAW_STATE_DIR is the state directory containing openclaw.json
  const stateDir = process.env.OPENCLAW_STATE_DIR;
  if (stateDir) return stateDir;
  // Default: ~/.openclaw
  return join(process.env.HOME || "/root", ".openclaw");
}
