# Plan: APP Server Firewall Integration

## Problem

NCG (and any non-OpenClaw agent) uses Shroud's APP server for obfuscation but is invisible to the security extension. No profiling, no injection detection, no dashboard visibility. Complete blind spot.

## Solution

Wire security modules into the APP server's existing request path. Require agents to identify themselves on connect.

## Required Handshake

After the initial APP handshake, clients MUST call `identify`:

```json
{"id": 1, "method": "identify", "params": {"agent": "ncg", "version": "2.1.0", "channel": "cli"}}
```

If a client sends `obfuscate`/`deobfuscate` without calling `identify` first, the APP server returns an error. No anonymous agents.

## Implementation Steps

### Step 1: Security module initialization (app-server.mjs)

Import SecurityEventBus, InjectionDetector, AgentSessionTracker from dist/. Guarded with try/catch so core-only builds degrade gracefully.

### Step 2: Required `identify` method

New JSON-RPC method. Stores agent label, version, channel. Derives buildId from SHA256(agent + version). Must be called before any obfuscate/deobfuscate — enforced.

### Step 3: Injection scanning on obfuscate/deobfuscate

In handleObfuscate: scan input text for injections. Emit events to SecurityEventBus. If mode is "block" and high-severity found, return error.

In handleDeobfuscate: scan output for exfiltration markers.

### Step 4: Agent tracking

Record each request in AgentSessionTracker. Track request count, text size distributions, category distributions.

### Step 5: Event bridge (JSONL file)

APP server appends security events to a JSONL file. Dashboard polls it every 5 seconds and merges into the shared event bus. Same pattern as SIEM shipping.

### Step 6: Dashboard visibility

APP agents appear alongside OpenClaw agents. Distinguished by `source: "app-server"`. Agent session state written to a file, dashboard reads and merges.

### Step 7: `security` query method

New JSON-RPC method returning event counts, recent events, agent info. Optional but useful for client-side monitoring.

### Step 8: Handshake update

Advertise security capabilities in handshake response: `["security", "identify", "injection_scan"]`. Clients discover what's available.

### Step 9: NCG adapter update

After handshake, call `identify` with agent name and version. If APP server returns method-not-found (older Shroud), graceful fallback.

## Files Changed

| File | Changes |
|------|---------|
| `app-server.mjs` | Steps 1-5, 7-8: security imports, identify, injection scanning, agent tracking, event file, security query, handshake |
| `src/dashboard.ts` | Step 6: poll APP event file, merge APP sessions into agent views |
| NCG `plugins/shroud.py` | Step 9: call identify after handshake |

## Key Decisions

- **Identify is required**, not optional. No anonymous agents.
- **JSONL file for IPC**, not sockets. Consistent with SIEM shipping, no new dependencies.
- **5-second poll latency** for dashboard. Acceptable for monitoring.
- **Ships via npm** — NCG gets it on next `npm update shroud-privacy`.
