# APP Protocol Security Extension

## Overview

The Agent Privacy Protocol (APP) now includes security firewall integration. Non-OpenClaw agents (e.g., NCG) that use the APP server for privacy obfuscation are now monitored by the same security pipeline as OpenClaw agents: injection detection, tool call guard, agent tracking, and dashboard visibility.

## Protocol Flow

```
Agent startup:
  1. Spawn app-server.mjs
  2. Receive handshake (capabilities, security status)
  3. Call `identify` with agent name + version       ← REQUIRED

Agent loop:
  4. Call `obfuscate` with user/prompt text           ← injection scanned
  5. Send obfuscated text to LLM
  6. Receive LLM response
  7. Call `deobfuscate` with LLM response             ← exfiltration scanned
  8. Parse tool calls from deobfuscated response
  9. For each tool call:
     a. Call `tool_call` with tool name + args        ← tool guard scanned
     b. Execute tool locally
     c. Call `tool_result` with tool name + result    ← result scanned
  10. Repeat from step 4

Monitoring:
  11. Call `security` to query event counts            ← optional
```

## New APP Methods

### `identify` (required)

Must be called before `obfuscate`/`deobfuscate`/`tool_call`/`tool_result`. Registers the agent identity with the security firewall.

**Request:**
```json
{"id": 1, "method": "identify", "params": {
  "agent": "ncg",
  "version": "2.1.0",
  "channel": "enterprise-agent"
}}
```

**Response:**
```json
{"id": 1, "result": {
  "ok": true,
  "agent": "ncg",
  "buildId": "7bc7757cc159e618",
  "security": true
}}
```

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `agent` | string | yes | Agent name (appears in dashboard) |
| `version` | string | yes | Agent version (used to derive buildId) |
| `channel` | string | no | Channel type (default: `"app"`) |

If `identify` is not called, all subsequent `obfuscate`/`deobfuscate`/`tool_call`/`tool_result` calls return error code `-32001`:
```json
{"error": {"code": -32001, "message": "Agent not identified. Call \"identify\" with {agent, version} before obfuscate/deobfuscate."}}
```

### `tool_call` (before tool execution)

Reports a tool call to the security firewall before execution. The firewall runs the tool guard (dangerous command patterns) and injection scanner on the args.

**Request:**
```json
{"id": 10, "method": "tool_call", "params": {
  "tool": "exec",
  "args": {"command": "python generate.py ATVIE"}
}}
```

**Response (allowed):**
```json
{"id": 10, "result": {
  "allowed": true,
  "blocked": false,
  "tool": "exec",
  "sequenceLength": 3
}}
```

**Response (blocked, when `SHROUD_INJECTION_DETECTION=block`):**
```json
{"id": 10, "result": {
  "allowed": false,
  "blocked": true,
  "reason": "Dangerous command: rm with recursive force flags",
  "events": [{"threatClass": "dangerous_command", "severity": "high", "action": "blocked"}]
}}
```

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | yes | Tool name |
| `args` | object | no | Tool arguments (scanned for dangerous patterns) |

### `tool_result` (after tool execution)

Reports a tool result to the security firewall after execution. Scans the result for exfiltration markers.

**Request:**
```json
{"id": 11, "method": "tool_result", "params": {
  "tool": "exec",
  "result": "Generated 12 config files for ATVIE"
}}
```

**Response:**
```json
{"id": 11, "result": {
  "ok": true,
  "tool": "exec"
}}
```

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | yes | Tool name |
| `result` | string | no | Tool result text (first 2000 chars scanned) |

### `security` (query)

Returns the current security state — event counts, threat breakdown, agent info.

**Request:**
```json
{"id": 20, "method": "security", "params": {}}
```

**Response:**
```json
{"id": 20, "result": {
  "enabled": true,
  "mode": "flag",
  "events": 3,
  "byThreatClass": {"instruction_override": 1, "dangerous_command": 2},
  "agent": {
    "label": "ncg",
    "buildId": "7bc7757cc159e618",
    "version": "2.1.0",
    "channel": "enterprise-agent",
    "requestCount": 42
  },
  "recentEvents": [
    {"threatClass": "dangerous_command", "severity": "high", "action": "flagged", "timestamp": 1775150000000}
  ]
}}
```

## Updated Handshake

The handshake now advertises security capabilities:

```json
{
  "app": "1.0",
  "engine": "shroud",
  "version": "2.4.0",
  "capabilities": [
    "obfuscate", "deobfuscate", "batch", "stats", "health",
    "configure", "audit", "partitions",
    "identify", "security", "tool_call", "tool_result"
  ],
  "security": {
    "injectionDetection": "flag",
    "scanResponses": false,
    "requireIdentify": true
  }
}
```

The `security` field is `null` when security modules are not available (core-only Shroud build). Clients should check `"identify" in capabilities` before calling `identify`.

## Updated Existing Methods

### `obfuscate`

Now scans input text for injection patterns before obfuscation. In `block` mode, high-severity injections return an error instead of obfuscated text.

The `audit` block in the response includes a `securityEvents` count when injections are detected:
```json
{"audit": {"requestId": "...", "securityEvents": 2}}
```

### `deobfuscate`

Now scans deobfuscated output for exfiltration markers. Events are emitted to the security bus.

## Security Modes

Controlled by `SHROUD_INJECTION_DETECTION` environment variable:

| Mode | Behavior |
|------|----------|
| `off` | No security scanning. `identify` still works but is optional. |
| `flag` (default) | Scans and records events. Never blocks. |
| `block` | Scans, records events, and blocks high-severity threats. `tool_call` returns `blocked: true`, `obfuscate` returns an error. |

## Dashboard Bridge

The APP server writes security events to a JSONL file for the dashboard to read:

| Env var | Default | Description |
|---------|---------|-------------|
| `SHROUD_APP_EVENTS_FILE` | `/tmp/shroud-app-events.jsonl` | Security events (one JSON per line) |
| `SHROUD_APP_SESSIONS_FILE` | `/tmp/shroud-app-sessions.json` | Agent session state (updated every 30s) |

The dashboard polls these files to show APP agents alongside OpenClaw agents.

## Backward Compatibility

- **Core-only Shroud builds** (main branch): Security modules not present. APP server starts without security features. `identify`/`security`/`tool_call`/`tool_result` are advertised in capabilities but calling them returns method-not-found. Existing `obfuscate`/`deobfuscate` work unchanged.
- **Older APP clients**: Clients that don't call `identify` get error `-32001` on `obfuscate`/`deobfuscate`. They must be updated to call `identify` first.
- **Older APP servers**: Clients that check `"identify" in capabilities` before calling will gracefully skip on older servers that don't advertise it.

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| `-32001` | `ERR_NOT_IDENTIFIED` | Agent not identified. Call `identify` first. |
| `-32000` | `ERR_ENGINE` | Request blocked by injection detection. |
