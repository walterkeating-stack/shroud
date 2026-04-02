# NCG Integration with Shroud Security Firewall

## Overview

NCG (Network Config Generator) is a Python-based AI agent that uses Shroud's APP server for privacy obfuscation. With the security extension, NCG is now a fully monitored agent — identity tracked, tool calls guarded, injections detected, visible in the dashboard alongside OpenClaw agents.

## How It Works

### Agent Startup

NCG's `plugins/shroud.py` spawns the APP server and sends an `identify` call after the handshake:

```python
# In ShroudPlugin.start(), after handshake:
if self._protocol == "app" and "identify" in self._capabilities:
    self._call("identify", {
        "agent": "ncg",
        "version": self._version,
        "channel": "enterprise-agent",
    })
```

This registers NCG in the security dashboard with a unique `buildId` derived from `SHA256("ncg:" + version)`.

### Privacy (unchanged)

```python
safe_text = plugin.sanitize(real_text)    # obfuscate before LLM
real_text = plugin.desanitize(safe_text)  # deobfuscate after LLM
```

Both calls now include injection scanning. `sanitize()` scans for prompt injection patterns. `desanitize()` scans for exfiltration markers.

### Tool Call Monitoring (new)

NCG's `agent.py` wraps every tool execution with firewall calls:

```python
# In _run_tool(), before execution:
gate = self.sanitizer._call("tool_call", {"tool": name, "args": inputs})
if gate and gate.get("blocked"):
    return json.dumps({"error": f"Blocked by security firewall: {gate.get('reason')}"})

# Execute tool
result = fn(inputs)

# After execution:
self.sanitizer._call("tool_result", {"tool": name, "result": result[:2000]})
```

The tool guard scans for:
- Dangerous shell commands (`rm -rf`, `chmod 777`, reverse shells)
- Privilege escalation patterns
- Sandbox boundary violations
- Injection patterns in tool arguments

In `block` mode, dangerous tool calls are stopped before execution and an error is returned to the LLM.

### Dashboard Visibility

NCG appears in the Shroud security dashboard alongside OpenClaw agents:

- **Agent card** with name "ncg", role "APP Agent", channel "enterprise-agent"
- **Request count** tracking (obfuscate + deobfuscate calls)
- **Security events** from injection scanning and tool guard
- **Tool sequence** tracked for profiling

The dashboard reads NCG's state from two files written by the APP server:
- `/tmp/shroud-app-events.jsonl` — security events (JSONL, one per line)
- `/tmp/shroud-app-sessions.json` — agent session state (updated every 30s)

The dashboard polls these every 5 seconds.

## Data Flow

```
NCG Python Agent
  │
  ├─ sanitize(prompt) ──────→ APP Server ──→ injection scan ──→ obfuscate
  │                                                              │
  ├─ [prompt to LLM] ←──────────────────────────────────────────┘
  │
  ├─ [LLM response] ────────→ APP Server ──→ deobfuscate ──→ exfil scan
  │                                                              │
  ├─ desanitize(response) ←─────────────────────────────────────┘
  │
  ├─ tool_call(exec, args) ─→ APP Server ──→ tool guard scan
  │   │                                         │
  │   │  ← blocked (if dangerous)  ←────────────┘
  │   │  ← allowed ←────────────────────────────┘
  │   │
  │   ├─ [execute tool locally]
  │   │
  │   └─ tool_result(exec, result) → APP Server ──→ result scan
  │
  └─ repeat
```

## Files Changed

### Shroud (feature/transformer branch)

| File | Change |
|------|--------|
| `app-server.mjs` | `identify`, `tool_call`, `tool_result`, `security` methods; injection scanning; agent tracking; event JSONL bridge |
| `src/dashboard.ts` | APP event polling (5s), APP session merging into agents API |
| `src/index.ts` | Pass `appEventsFile` and `appSessionsFile` to dashboard |
| `docs/app-protocol-security.md` | Full APP security protocol reference |

### NCG (main branch)

| File | Change |
|------|--------|
| `plugins/shroud.py` | Call `identify` after handshake (6 lines) |
| `agent.py` | Wrap `_run_tool` with `tool_call`/`tool_result` (22 lines) |

## Configuration

NCG doesn't need any configuration changes. The security features are controlled by Shroud's environment variables, which NCG already passes through:

| Env var | Default | Effect on NCG |
|---------|---------|---------------|
| `SHROUD_INJECTION_DETECTION` | `flag` | `flag`: scan + log. `block`: scan + block dangerous. `off`: no scanning. |
| `SHROUD_APP_EVENTS_FILE` | `/tmp/shroud-app-events.jsonl` | Where APP server writes events for dashboard |
| `SHROUD_APP_SESSIONS_FILE` | `/tmp/shroud-app-sessions.json` | Where APP server writes session state |

These can be set in NCG's `config/shroud.yaml` under `plugin_config`, or as environment variables.

## Backward Compatibility

- **Older Shroud (no security extension):** NCG checks `"identify" in self._capabilities` before calling. If the APP server doesn't support it, NCG works as before — obfuscation only, no monitoring.
- **Older NCG (no tool_call/tool_result):** Shroud still monitors via injection scanning on `sanitize`/`desanitize`. Tool calls are just not tracked individually.
- **Core-only Shroud build (main branch):** Security modules not loaded. `identify` returns method-not-found. NCG works as before.
