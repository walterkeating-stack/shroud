# Per-agent ob/deob mode

Each agent (identified by its `agentLabel`) runs the obfuscation pipeline in one of three modes:

| Mode | Detect? | Replace? | Log? | Use case |
|------|---------|----------|------|----------|
| `enforce` | yes | yes | yes | Default. Production protection. |
| `shadow`  | yes | no  | yes (as shadow hits, masked samples) | Diagnose detector noise on a live agent without breaking it. |
| `off`     | no  | no  | no  | Disable protection when you have external justification (upstream sanitisation, offline-only agent, etc.). |

## Why shadow mode

The motivating problem: a research/finance agent (e.g. `agentdesk`) swims in 16-digit numbers that collide with the `credit_card` detector. Turning the detector off globally would regress protection for every other agent. Tuning it blindly risks missing real cards.

Shadow mode on that one agent lets you see *exactly* what is getting flagged, per category, with masked samples, over real traffic — then decide to exempt the category, tighten the rule, add Luhn validation, etc. Once noise is zero or all real, you flip it back to `enforce`.

This is the observation primitive that was missing; it is NOT a replacement for proper detection fixes.

## Configuration

`shroud.config.json`:

```json
{
  "agents": {
    "agentdesk": { "mode": "shadow" },
    "research-*": { "mode": "shadow" },
    "marketing-bot": { "mode": "off" },
    "*": { "mode": "enforce" }
  },
  "dashboardModeControl": "readonly"
}
```

**Precedence** (highest to lowest):
1. Exact label match
2. Wildcard pattern match (`*` and `?` supported; case-insensitive)
3. `"*"` fallback entry if present
4. Built-in default: `"enforce"`

Changes hot-reload within ~2 seconds via the existing `ConfigManager` watch. Agents picked up later inherit their mode immediately.

### Global `dryRun` precedence

If top-level `dryRun: true` is set, it suppresses replacement even for `enforce` agents (global master switch). Per-agent `shadow` mode achieves the same detect-but-don't-replace effect scoped to one agent.

| global `dryRun` | agent mode | Effective behaviour |
|----------------|-----------|--------------------|
| false          | enforce   | detect + replace |
| false          | shadow    | detect + log, no replace |
| false          | off       | no detection |
| true           | enforce   | detect + log, no replace (global dryRun wins) |
| true           | shadow    | detect + log, no replace |
| true           | off       | no detection |

## Dashboard controls

The Obfuscation tab of the security dashboard gains three sections:

1. **Mode summary strip** — count of agents in each mode, plus total shadow hits across all agents.
2. **Per-Agent Privacy Stats** — same table as before, extended with:
   - **Mode** column: coloured pill (green = enforce, amber = shadow, grey = off)
   - **Shadow hits (24h)** column
   - **Top shadow category** column
   - **Actions** buttons (only when `dashboardModeControl: "mutate"`): one-click transitions to each of the non-current modes. Each prompts for confirmation.
3. **Shadow Feed** — per-agent × per-category rollup with up to 20 recent masked samples per agent. Uses `RedactionFormatter.mask()`, so raw values never surface.

## API

All endpoints live on the dashboard HTTP port.

### `GET /api/agents/modes`

Returns every agent the tracker knows about, plus every configured label pattern, with its resolved mode:

```json
{
  "mutable": false,
  "agents": [
    { "label": "agentdesk", "mode": "shadow", "source": "exact", "configured": true },
    { "label": "research-*", "mode": "shadow", "source": "wildcard", "configured": true },
    { "label": "claude-code", "mode": "enforce", "source": "fallback", "configured": false },
    { "label": "*", "mode": "enforce", "source": "fallback", "configured": false }
  ]
}
```

### `GET /api/shadow`

Shadow detection feed:

```json
{
  "total": 847,
  "rows": [
    {
      "agent": "agentdesk",
      "category": "credit_card",
      "hits": 612,
      "samples": [
        { "masked": "40**-****-****-**12", "detector": "credit_card", "confidence": 0.85, "at": 1714019234567 }
      ]
    }
  ],
  "modeSummary": { "enforce": 7, "shadow": 1, "off": 0 }
}
```

### `POST /api/agents/:label/mode`

Body: `{ "mode": "enforce" | "shadow" | "off" }`

Gated by `dashboardModeControl === "mutate"` (returns 403 otherwise). Persists the change through `ConfigManager.setFields()` so it lands in `shroud.config.json` and hot-reloads. Emits a `mode_change` security event on success with `{ prevMode, newMode, source: "dashboard" }`.

Response:

```json
{
  "ok": true,
  "label": "agentdesk",
  "mode": "shadow",
  "prevMode": "enforce",
  "changedFields": ["agents"],
  "warnings": []
}
```

## Module reference

### `src/agent-mode.ts`

- **`class AgentModeResolver`**
  - `constructor(config: AgentsConfig)` — build from `config.agents`.
  - `resolve(agentLabel: string): AgentMode` — returns `"enforce"`, `"shadow"`, or `"off"` per precedence rules.
  - `listConfigured(): Array<{ label, mode, source }>` — enumerate everything the resolver knows about; used by the dashboard.
- **`setAgentModeResolver(r)` / `getAgentModeResolver()`** — module-level singleton, refreshed on hot-reload.
- **`setCurrentAgentMode(label, mode)` / `getCurrentAgentMode()` / `getCurrentAgentLabel()`** — module state used by the Obfuscator as a default when no explicit `mode` argument is passed. Hooks set this at each entry point.
- **`resetCurrentAgentMode()`** — test-only; returns state to the initial defaults.

### `src/obfuscator.ts`

`Obfuscator.obfuscate(text, context?, exemptCategories?, mode?)` — `mode` is optional; when omitted, the Obfuscator falls back to `getCurrentAgentMode()`. Three branches:

- `"off"`: return `{ obfuscated: text, entities: [] }` immediately. No detector run.
- `"shadow"`: run detectors + filters, but skip the replacement loop. Return result with `shadow: true`.
- `"enforce"`: existing behaviour.

`Obfuscator.deobfuscateWithStats()` short-circuits to a no-op when `getCurrentAgentMode() === "off"`.

### `src/agent-session.ts`

`AgentSessionTracker.recordShadow(entityCount, categoryCounts, samples)` — accumulates shadow-mode telemetry:

- `session.privacy.shadowDetections` — running total
- `session.privacy.shadowCategoryCounts` — per-category totals
- `session.privacy.shadowSamples` — ring buffer capped at 20 entries; every sample carries `{ category, masked, detector, confidence, at }`. Values are already masked by the caller.

### `src/hooks.ts` (private helpers)

- `getAgentModeResolverLocal()` — per-hook-instance resolver that reconstructs itself when `config.agents` changes. Keeps the module singleton in sync.
- `applyAgentMode(): { label, mode }` — called at the top of every hook that runs ob/deob. Resolves the current agent's mode and writes it to module state so `Obfuscator.obfuscate()` picks it up as the default.
- `recordObfOrShadow(entityCount, categoryCounts, sampleEntities)` — routes to `recordShadow` when the current mode is `"shadow"`, otherwise to `recordObfuscation`. Handles masking of samples via `RedactionFormatter.mask`.

### Fetch intercept (streaming)

The outbound fetch interceptor captures the resolved mode in a closure on entry and threads it through `deobfuscateResponse(fetchPromise, fetchModeCtx)`. Each `TransformStream.transform()` / `flush()` callback re-applies that mode to module state before calling deob, so concurrent fetches from agents in different modes cannot interleave and corrupt each other's state.

## Safety notes

- **Never surface raw values in shadow logs.** All samples pass through `RedactionFormatter.mask()` at the call site in `recordObfOrShadow`. Adding a "reveal raw" button to the dashboard is explicitly out of scope — screenshots and logs outlive their immediate context.
- **`off` is the dangerous mode.** `validateConfig` warns when any agent is configured `off`. The dashboard shows it with a grey pill to make it visually distinct from the protective modes.
- **`dashboardModeControl: "readonly"` is the default** for good reason. Only flip to `"mutate"` on trusted localhost deployments. For multi-user dashboards, leave it readonly and drive changes via `shroud.config.json` directly (still hot-reloads).
- **Mode changes are audit-logged** as `mode_change` security events with `prevMode`, `newMode`, and `source` metadata. They appear in the Events tab and flow through SIEM shipping if configured.

## Testing

See `tests/agent-mode.test.ts` — 24 unit tests covering:

- Resolver precedence (exact > wildcard > `"*"` > default)
- Case-insensitive wildcard match
- `listConfigured()` shape
- Module-level state functions
- Obfuscator branching for each of the three modes
- Module default fallback vs explicit `mode` arg precedence
- Interaction with global `dryRun`
- `deobfuscateWithStats` no-op for mode `"off"`
- Config parsing (valid / invalid values)
- `SHROUD_DASHBOARD_MODE_CONTROL` env var override
- `validateConfig` warnings for `off` agents and `mutate` dashboard control
- `AgentSessionTracker.recordShadow` accumulation and ring-buffer cap
