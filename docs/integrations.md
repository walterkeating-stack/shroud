# Shroud Integrations (`main` branch)

This document is the integration reference for the `main` worktree at `/home/ka/shroud-main`.
It focuses on the actual integration surfaces shipped in this branch:

- OpenClaw plugin integration
- APP server integration over stdio and Unix sockets
- Python APP client integration
- Existing APP clients such as NCG
- Claude Code MCP integration
- Claude Code hooks bridge integration
- Codex MCP integration

This branch is the privacy-core line. It ships the obfuscation/deobfuscation engine, runtime hooks, config-as-code, APP transport, and coding-agent clients. It now exposes `identify`, `security`, `tool_call`, and `tool_result` for client parity with `feature/transformer`, but keeps them telemetry-only: `security()` reports `enabled: false`, and tool RPCs never enforce policy.

## Integration Map

| Surface | Files | Transport | What it integrates |
|---|---|---|---|
| OpenClaw plugin | `openclaw.plugin.json`, `src/index.ts`, `src/hooks.ts` | OpenClaw plugin API + runtime patching | Inline obfuscation/deobfuscation inside OpenClaw |
| APP server | `app-server.mjs` | Newline-delimited JSON-RPC on stdio or Unix socket | Generic agent integration in any language |
| Python client | `clients/python/shroud_client.py` | Spawns APP server on stdio | Python agents that want a local wrapper |
| Existing APP clients | external clients such as `/home/ka/ncg/agent.py` | stdio or Unix socket APP JSON-RPC | Non-OpenClaw agents that want stable privacy RPCs plus agent/session telemetry |
| Claude MCP | `clients/claude-code/shroud-mcp.mjs`, `clients/claude-code/socket-client.mjs`, `clients/claude-code/mcp.json` | MCP on stdio, APP on Unix socket | Claude Code tool-based access to Shroud |
| Claude hooks bridge | `clients/claude-code/shroud-bridge.mjs`, `clients/claude-code/hooks.json` | HTTP hooks to bridge, Unix socket to APP | Automatic tool input deobfuscation and tool output obfuscation |
| Codex MCP | `clients/codex/shroud-mcp.mjs`, `clients/claude-code/shroud-mcp.mjs` | MCP on stdio, APP on Unix socket | Codex CLI tool-based access to the same Shroud MCP surface |

## OpenClaw Integration

### Manifest and compatibility

The OpenClaw integration is described in [`openclaw.plugin.json`](../openclaw.plugin.json).

- Plugin id: `shroud-privacy`
- Runtime server: `app-server.mjs`
- Declared APP protocol: `app-1.0`
- Declared compatibility floor: OpenClaw `2026.3.24`
- Declared adapter blocks: `enterpriseAgent`, `ncg`, and `app`

This branch exposes the privacy engine as a normal OpenClaw plugin and also declares the APP server as the out-of-process integration target.

### Runtime registration path

`src/index.ts` is the OpenClaw entrypoint. On registration it:

1. Patches the live `EventStream` prototype so streamed replies can be deobfuscated before OpenClaw surfaces them.
2. Resolves plugin configuration with `resolveConfig()`.
3. Constructs a single `Obfuscator` instance.
4. Starts config-as-code watching through `ConfigManager`.
5. Registers lifecycle hooks through `registerHooks()`.
6. Registers two OpenClaw tools:
   - `shroud_status`
   - `shroud_reset`

### Hook-level integration

`src/hooks.ts` is the core OpenClaw integration module. In this branch it wires these entry points:

| Hook / patch point | Direction | Effect |
|---|---|---|
| `before_prompt_build` | user/history -> LLM | Warms DNS classification, restores persisted mappings, pre-seeds obfuscation state |
| `before_message_write` | assistant/tool -> transcript | Deobfuscates visible assistant content for stored history |
| `before_tool_call` | model -> tool | Deobfuscates tool parameters before execution |
| `tool_result_persist` | tool -> history | Obfuscates tool results before they are stored |
| `message_sending` | agent -> user/channel | Backup outbound deobfuscation path |
| `globalThis.__shroudStreamDeobfuscate` | streaming LLM -> runtime | Per-event deobfuscation for SSE content blocks |
| `globalThis.__shroudDeobfuscate` | runtime -> channel adapter | Final global text deobfuscation hook |
| `globalThis.fetch` intercept | LLM request/response boundary | Obfuscates outbound provider payloads and deobfuscates inbound streaming responses |
| reply dispatcher wrapping | runtime reply senders | Deobfuscates block replies, final replies, and tool results before user delivery |

### OpenClaw-visible tools

The plugin registers these tools with `api.registerTool()`:

| Tool | Purpose |
|---|---|
| `shroud_status` | Returns current obfuscator statistics as JSON text |
| `shroud_reset` | Clears all mappings and starts a fresh session |

This branch does not register `shroud_security`; that exists only on `feature/transformer`.

### Config and state files used by the OpenClaw integration

| Purpose | Default path | Override |
|---|---|---|
| Plugin config | `~/.openclaw/openclaw.json` | OpenClaw-managed |
| Config-as-code file | `~/.shroud/shroud.config.json` | resolved from `OPENCLAW_STATE_DIR` or `HOME` |
| Stats dump | `/tmp/shroud-stats.json` | `SHROUD_STATS_FILE` |
| Persisted mapping store | `~/.openclaw/shroud-store.json` | `SHROUD_STORE_FILE` |

The mapping store matters for OpenClaw because assistant history may contain fake values from previous turns. On restart, `src/hooks.ts` restores serialized mappings so deobfuscation still works across process lifetimes.

## APP Integration

### What APP is in this branch

`app-server.mjs` is the reference APP server. It wraps the built `Obfuscator` and exposes the privacy engine over newline-delimited JSON-RPC.

Transport options:

- stdio mode: default, one APP server process per client
- socket mode: `--listen <socket-path>` for reusable shared daemon mode

### Startup and handshake

When the APP server starts it emits a single handshake object before any RPC responses:

```json
{
  "app": "1.0",
  "engine": "shroud",
  "version": "2.5.5",
  "capabilities": [
    "identify",
    "obfuscate",
    "deobfuscate",
    "batch",
    "stats",
    "health",
    "configure",
    "security",
    "tool_call",
    "tool_result",
    "audit",
    "partitions"
  ],
  "security": null
}
```

The handshake is identical on stdio and per-socket connections.

### Supported APP methods

This branch implements the following RPC methods:

| Method | Params | Returns | Notes |
|---|---|---|---|
| `identify` | `{ agent, version, channel? }` | `{ ok, agent, buildId, security }` | Optional for privacy-only callers, recommended for coding-agent integrations |
| `obfuscate` | `{ text, partition? }` | `{ text, entityCount, categories, modified, audit }` | Core privacy entrypoint |
| `deobfuscate` | `{ text, partition? }` | `{ text, replacementCount, replacementsByCategory, modified, storeSize, audit }` | Restores real values |
| `batch` | `{ operations, partition? }` | `{ results }` | Mixed obfuscate/deobfuscate batches |
| `reset` | `{ partition? }` | `{ ok, summary }` | Clears a single partition or all state |
| `stats` | `{}` | engine counters and rule/category stats | Includes uptime and memory |
| `health` | `{}` | liveness payload | Includes request count and latency |
| `security` | `{}` | `{ enabled: false, ... }` | Present for parity; no security engine in this branch |
| `tool_call` | `{ tool, args? }` | `{ blocked: false, sequenceLength, events: [] }` | Telemetry-only tool sequencing |
| `tool_result` | `{ tool, result }` | `{ ok, recorded }` | Telemetry-only completion record |
| `configure` | `{ config }` | `{ ok, appliedKeys }` | Rebuilds obfuscators with merged config |
| `shutdown` | `{}` | `{ ok, flushed }` | Flushes stats and exits |
| `setPartition` | `{ id }` | `{ ok, partition, storeSize }` | Sets default active partition |

### Core request flow

The APP contract in `main` stays simple for privacy-only callers, but coding-agent clients should still identify themselves:

1. Read the handshake.
2. Call `identify` if you want per-agent session files and request counters.
3. Call `obfuscate` before sending content to an LLM or external service.
4. Optionally call `tool_call` / `tool_result` around tool execution to populate telemetry.
5. Call `deobfuscate` on the way back to restore real values.
6. Call `reset` when starting a clean session if you do not want mappings reused.

Minimal example:

```json
{"id":1,"method":"identify","params":{"agent":"ncg","version":"1.0.0","channel":"enterprise-agent"}}
{"id":2,"method":"obfuscate","params":{"text":"Contact admin@acme.com about 10.1.0.1"}}
{"id":3,"method":"tool_call","params":{"tool":"Read","args":{"file_path":"/tmp/device.txt"}}}
{"id":4,"method":"deobfuscate","params":{"text":"Contact user@example.net about 100.64.0.12"}}
```

Partitioned example:

```json
{"id":3,"method":"setPartition","params":{"id":"customer-a"}}
{"id":4,"method":"obfuscate","params":{"partition":"customer-a","text":"router core-01 has 10.0.0.5"}}
{"id":5,"method":"stats","params":{}}
```

### Audit fields returned by APP

Both `obfuscate` and `deobfuscate` return an `audit` object. The server computes:

- `requestId`
- `proofIn`
- `proofOut`
- `chainHash`

`obfuscate` also includes character counts and may include a fake-value sample depending on `auditMaxFakesSample`.

### Partition support

The APP server supports multiple logical mapping namespaces:

- Per-request: include `partition` in `obfuscate` or `deobfuscate`
- Process default: call `setPartition`

Each partition gets its own `Obfuscator` instance and mapping store.

### Socket mode

Run:

```bash
node app-server.mjs dist --listen /tmp/shroud-app.sock
```

Socket mode keeps the same dispatch logic as stdio mode, but:

- emits the handshake to each connecting socket client
- still serves stdio for backward compatibility
- cleans up the socket file on shutdown

When `identify` has been called, the APP server also writes a session summary to:

- `SHROUD_APP_SESSIONS_FILE`, default `/tmp/shroud-app-sessions.json`

The summary includes:

- `agentLabel`
- `agentBuildId`
- `channel`
- `requestCount`
- `toolSequence`
- `privacy` counters

This is what lets direct APP clients such as NCG, Claude, and Codex surface stable per-agent counters even though this branch has no transformer security engine.

## Python Integration

### Client shape

`clients/python/shroud_client.py` is a standalone wrapper around the APP stdio server.

It provides:

- `ShroudClient.start()`
- `ShroudClient.stop()`
- `ShroudClient.obfuscate()`
- `ShroudClient.deobfuscate()`
- `ShroudClient.reset()`
- `ShroudClient.stats()`
- `ShroudClient.health()`
- `ShroudClient.configure()`

### Path resolution

If the caller does not pass explicit paths, the client auto-detects:

- `app-server.mjs`
- the built `dist/` directory

from the installed npm package layout.

### Process model

The Python client:

1. Spawns `node app-server.mjs <dist-path>`
2. Reads the APP handshake from stdout
3. Sends JSON-RPC requests over stdin/stdout
4. Reads stderr in a background thread for heartbeats and diagnostics

### Result objects

The wrapper normalizes APP responses into dataclasses:

| Dataclass | Fields |
|---|---|
| `ObfuscateResult` | `text`, `entity_count`, `categories`, `modified`, `audit` |
| `DeobfuscateResult` | `text`, `replacement_count`, `modified`, `audit`, `residual_fakes` |

`residual_fakes` is computed locally in Python by scanning the restored text for remaining CGNAT or ULA fake IPs.

### Configuration injection

If `config=` is supplied to `ShroudClient`, the client sets `SHROUD_PLUGIN_CONFIG` before spawning the APP server.

This is the primary direct-integration path for Python agents that do not speak JSON-RPC themselves.

## Claude Code MCP Integration

### Files

- `clients/claude-code/shroud-mcp.mjs`
- `clients/claude-code/socket-client.mjs`
- `clients/claude-code/mcp.json`

### Installation shape

The provided `mcp.json` snippet adds a `shroud` MCP server pointing at `shroud-mcp.mjs`.

```json
{
  "mcpServers": {
    "shroud": {
      "command": "node",
      "args": ["node_modules/shroud-privacy/clients/claude-code/shroud-mcp.mjs"]
    }
  }
}
```

### Runtime design

The MCP server:

1. Speaks MCP on stdio to Claude Code.
2. Lazily connects to APP on a Unix socket.
3. Auto-spawns an APP server on first use if one is not running.
4. Uses a dedicated default socket: `/tmp/shroud-claude-mcp.sock`.

That means Claude sessions can share one Shroud daemon while keeping the MCP boundary simple.

### MCP tools exposed

`shroud-mcp.mjs` exposes six tools:

| Tool | Effective on `main`? | Detail |
|---|---|---|
| `shroud_obfuscate` | Yes | Calls APP `obfuscate` |
| `shroud_deobfuscate` | Yes | Calls APP `deobfuscate` |
| `shroud_status` | Yes | Combines APP `stats` and `health` |
| `shroud_scan_tool` | Yes, telemetry-only | Calls APP `tool_call`, which always returns allow/no-events on this branch |
| `shroud_configure` | Yes | Calls APP `configure` |
| `shroud_reset` | Yes | Calls APP `reset` |

### Default artifact behavior

When the wrapper auto-spawns APP, it uses:

- socket: `/tmp/shroud-claude-mcp.sock`
- session file: `${STATE_DIR}/shroud-claude-mcp-sessions.json`
- events file env: `${STATE_DIR}/shroud-claude-mcp-events.jsonl` (reserved for parity; core `main` does not emit APP security events)
- APP identity: `claude-code-mcp` on channel `mcp`

`STATE_DIR` resolves from `OPENCLAW_STATE_DIR`, or `HOME` with the `~/.openclaw` fallback.

### Important caveat on `main`

The Claude client bundle is shared with richer builds, so it still calls `identify`, `tool_call`, `tool_result`, and `security`. On `main`, those methods exist, but they are privacy-core only:

- `identify` records the agent label/build/channel in the session file
- `tool_call` and `tool_result` record telemetry only and never block
- `security` always reports `enabled: false`

That means Claude MCP gets consistent counters and identity on both branches, but only `feature/transformer` performs real APP-side tool security enforcement.

## Codex MCP Integration

### Files

- `clients/codex/shroud-mcp.mjs`
- `clients/codex/shroud-bridge.mjs`
- `clients/claude-code/shroud-mcp.mjs`
- `clients/shared/agent-config.mjs`

### Runtime design

Codex uses the same MCP implementation as Claude, but the wrapper sets:

- label `codex`
- channel `codex-cli`
- slug `codex-mcp`
- socket `/tmp/shroud-codex-mcp.sock`

Its default session file is `${STATE_DIR}/shroud-codex-mcp-sessions.json`.

### Codex installation shape

```bash
codex mcp add shroud -- node node_modules/shroud-privacy/clients/codex/shroud-mcp.mjs
```

Codex sees the same six Shroud tools as Claude. On this branch they are privacy-first and telemetry-aware, but not APP-side security-enforcing.

### Codex dashboard bridge

`clients/codex/shroud-mcp.mjs` now auto-starts `clients/codex/shroud-bridge.mjs` in the background unless `SHROUD_CODEX_BRIDGE=0`.

The bridge:

1. reads `${CODEX_HOME:-~/.codex}/history.jsonl`
2. counts non-control prompts (`quit`, `exit`, `logout`, `$` are ignored)
3. counts unique Codex session ids
4. merges those counts with the MCP privacy/session snapshot if `shroud-codex-mcp-sessions.json` already exists
5. writes `${STATE_DIR}/shroud-codex-cli-sessions.json`

This keeps Codex session/call counters moving even when Codex is not actively invoking Shroud MCP tools. The bridge self-singletons via `${STATE_DIR}/shroud-codex-bridge.pid`.

## Claude Code Hooks Bridge Integration

### Files

- `clients/claude-code/shroud-bridge.mjs`
- `clients/claude-code/hooks.json`

### Purpose

The bridge lets Claude Code hook events call into Shroud automatically so Claude works with fake values while the real world still receives real values.

### HTTP endpoints exposed by the bridge

| Endpoint | Method | Purpose |
|---|---|---|
| `/pre-tool-use` | POST | Security scan attempt plus deobfuscation of write-tool input |
| `/post-tool-use` | POST | Obfuscation of read-tool output |
| `/health` | GET | Proxy APP health |
| `/stats` | GET | Proxy APP stats |
| `/security` | GET | Proxy APP security, if available |

### Hook matcher configuration

`clients/claude-code/hooks.json` configures:

- `PreToolUse` for `Read|Bash|Grep|Glob|Write|Edit|NotebookEdit|WebFetch|WebSearch`
- `PostToolUse` for `Read|Bash|Grep|Glob|WebFetch|WebSearch`

The shipped JSON looks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Bash|Grep|Glob|Write|Edit|NotebookEdit|WebFetch|WebSearch",
        "hooks": [
          {
            "type": "http",
            "url": "http://127.0.0.1:17380/pre-tool-use",
            "timeout": 5000
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Read|Bash|Grep|Glob|WebFetch|WebSearch",
        "hooks": [
          {
            "type": "http",
            "url": "http://127.0.0.1:17380/post-tool-use",
            "timeout": 5000
          }
        ]
      }
    }
  }
}
```

### Read/write tool policy

The bridge hard-codes two sets:

| Set | Tools | Behavior |
|---|---|---|
| read tools | `Read`, `Bash`, `Grep`, `Glob`, `WebFetch`, `WebSearch` | obfuscate output before Claude sees it |
| write tools | `Write`, `Edit`, `Bash`, `NotebookEdit` | deobfuscate input before execution |

### `main` branch behavior

The bridge now auto-spawns its own APP daemon and uses dedicated defaults:

- socket: `/tmp/shroud-claude-cli.sock`
- session file: `${STATE_DIR}/shroud-claude-cli-sessions.json`
- events file env: `${STATE_DIR}/shroud-claude-cli-events.jsonl` (reserved for parity; core `main` does not emit APP security events)
- APP identity: `claude-code` on channel `claude-cli`

Input deobfuscation and output obfuscation work normally. The APP-side security methods still remain telemetry-only here:

- `tool_call` never blocks
- `tool_result` records completion only
- `security` returns `enabled: false`

## Environment Variables and Integration Controls

### Common APP and client variables

| Variable | Used by | Purpose |
|---|---|---|
| `SHROUD_PLUGIN_CONFIG` | APP server, Python client | Inline JSON config blob |
| `SHROUD_STATS_FILE` | hooks, APP server | Stats dump file |
| `SHROUD_STORE_FILE` | hooks, APP server | Mapping persistence file |
| `SHROUD_SOCKET` | socket client, MCP, bridge | APP Unix socket path |

### Claude-specific variables

| Variable | Used by | Purpose |
|---|---|---|
| `SHROUD_BRIDGE_PORT` | bridge | HTTP bind port, default `17380` |
| `SHROUD_MCP_LOG` | MCP server | verbose logging toggle |
| `SHROUD_BRIDGE_LOG` | bridge | verbose bridge logging toggle |
| `OPENCLAW_STATE_DIR` | Claude/Codex wrappers | base directory for per-agent session files |
| `SHROUD_AGENT_LABEL` | Claude/Codex wrappers | override APP agent label |
| `SHROUD_AGENT_CHANNEL` | Claude/Codex wrappers | override APP channel |
| `SHROUD_AGENT_VERSION` | Claude/Codex wrappers | override APP version |
| `SHROUD_AGENT_SLUG` | Claude/Codex wrappers | override socket/session basename |

## Integration Differences From `feature/transformer`

If you need the richer APP security protocol, use `feature/transformer`. The differences matter:

- `main` implements `identify`, `security`, `tool_call`, and `tool_result` for coding-agent parity, but they remain telemetry-only.
- `main` has no APP-side injection scanning, threat events, or blocking behavior.
- `main` OpenClaw registers privacy tools only.
- `main` persists APP session counters for Claude/Codex/NCG, but does not ship the dashboard/event bridge stack from `feature/transformer`.

If your goal is privacy-only integration, `main` is the simpler branch to embed.
