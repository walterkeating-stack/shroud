# NCG Python Adapter

> Status: Fully implemented, production-tested

The NCG adapter (`ncg_adapter.py`) bridges Python-based enterprise agents to Shroud's TypeScript engine via JSON-RPC over stdin/stdout. It implements the `NCGPlugin` interface with `sanitize()`/`desanitize()` methods.

## Key Capabilities

- **Lifecycle management** — start/stop/restart of Node.js bridge subprocess
- **Auto-restart** — detects bridge crashes and restarts transparently (mappings lost)
- **Residual fake detection** — post-deobfuscation scan for leaked CGNAT/ULA IPs
- **Audit logging** — formats obfuscation/deobfuscation audit events as human-readable lines with proof hashes and chain hashing
- **Hot-reload** — `update_config()` and `reload_from_file()` without agent restart
- **Runtime control** — activate/deactivate/reset via tool calls
- **4 registered tools** — `shroud_status`, `shroud_reset`, `shroud_activate`, `shroud_deactivate`

## Full Source

```python
"""Shroud plugin adapter for enterprise agent.

Bridges the enterprise agent's Python runtime to the Shroud TypeScript
obfuscation engine (running as a Node.js subprocess) via JSON-RPC over
stdin/stdout.

This mirrors how OpenClaw integrates with Shroud:
- Obfuscate text before sending to the LLM
- Deobfuscate text received from the LLM
- Deobfuscate tool parameters before execution
- Obfuscate tool results before persisting to history

Usage (via PluginManager):
    plugin = ShroudPlugin.from_config(plugin_dir, config)
    plugin.start()
    safe   = plugin.sanitize(real_text)      # before LLM
    real   = plugin.desanitize(safe_text)     # after LLM
    plugin.stop()

Legacy usage (direct, for testing):
    plugin = ShroudPlugin.from_config()       # loads config/shroud.yaml
    plugin.start()

The plugin can be activated/deactivated at runtime, and its config
can be hot-reloaded without restarting the agent.
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from plugins.base import NCGPlugin

log = logging.getLogger("ncg.shroud")

# Legacy defaults — used only for backward-compat direct instantiation
_DEFAULT_SHROUD_PATH = str(Path(__file__).resolve().parent / "dist")
_LEGACY_BRIDGE_SCRIPT = Path(__file__).parent / "shroud_bridge.mjs"
_LEGACY_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "shroud.yaml"

# CGNAT range used by Shroud for fake IPv4 addresses
_CGNAT_RE = re.compile(r'\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b')
# ULA range used by Shroud for fake IPv6 addresses (fd00::/8)
_ULA_RE = re.compile(r'\bfd00:[0-9a-fA-F:]{2,39}\b')


def _fmt_audit_obfuscate(audit):
    """Format obfuscation audit data as a single human-readable line.

    Proves: text was modified, what categories were found, char delta,
    truncated proof hashes (no raw values), fake samples, chain hash.
    """
    cats = ",".join(f"{k}:{v}" for k, v in audit.get("byCategory", {}).items()) or "none"
    fakes = "|".join(audit.get("fakesSample", []))
    parts = [
        f"[shroud][audit] OBFUSCATE req={audit.get('req', '?')}",
        f"entities={audit.get('totalEntities', 0)}",
        f"chars={audit.get('inputChars', 0)}->{audit.get('outputChars', 0)} (delta={audit.get('charDelta', 0):+d})",
        f"modified={'YES' if audit.get('modified') else 'NO'}",
        f"byCat={cats}",
        f"proof_in={audit.get('proofIn', '?')} proof_out={audit.get('proofOut', '?')}",
        f"chain={audit.get('chainHash', '?')}",
    ]
    if fakes:
        parts.append(f"fakes=[{fakes}]")
    return " | ".join(parts)


def _fmt_audit_deobfuscate(audit, req_id=None):
    """Format deobfuscation audit data as a single human-readable line."""
    parts = [
        f"[shroud][audit] DEOBFUSCATE",
    ]
    if req_id:
        parts[0] += f" req={req_id}"
    parts += [
        f"replacements={audit.get('replacementCount', 0)}",
        f"chars={audit.get('inputChars', 0)}->{audit.get('outputChars', 0)}",
        f"modified={'YES' if audit.get('modified') else 'NO'}",
        f"proof_in={audit.get('proofIn', '?')} proof_out={audit.get('proofOut', '?')}",
        f"chain={audit.get('chainHash', '?')}",
    ]
    return " | ".join(parts)


class ShroudPlugin(NCGPlugin):
    """Python adapter for the Shroud obfuscation engine.

    Manages a long-lived Node.js child process that runs the shroud
    bridge script. Communication is newline-delimited JSON over
    stdin/stdout (same pattern OpenClaw uses for plugin IPC).
    """

    def __init__(self, *, enabled=True, shroud_path=None, bridge_script=None,
                 config=None, plugin_dir=None):
        self.enabled = enabled
        self.plugin_dir = plugin_dir
        self.shroud_path = shroud_path or _DEFAULT_SHROUD_PATH
        self.bridge_script = bridge_script or _LEGACY_BRIDGE_SCRIPT
        self.config = config or {}
        self._proc = None
        self._lock = threading.Lock()
        self._req_id = 0
        self._started = False
        self._version = None
        self._audit_logger = None  # set by agent for file-based audit log
        self._last_obf_req = None  # track request ID for deobfuscation correlation

    # ── Factory ─────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, plugin_dir: Path = None, config: dict = None,
                    enabled: bool = True):
        """Create a ShroudPlugin from a plugin directory and config dict.

        When called by PluginManager:
            ShroudPlugin.from_config(plugin_dir=..., config={...}, enabled=True)

        Legacy usage (direct, loads config/shroud.yaml):
            ShroudPlugin.from_config()
        """
        if plugin_dir is not None:
            shroud_path = str(plugin_dir / "dist")
            bridge_script = plugin_dir / "shroud_bridge.mjs"
            return cls(enabled=enabled, shroud_path=shroud_path,
                       bridge_script=bridge_script, config=config or {},
                       plugin_dir=plugin_dir)

        # Legacy path: read from config/shroud.yaml
        path = _LEGACY_CONFIG_FILE
        file_config = {}
        shroud_path = _DEFAULT_SHROUD_PATH

        if path.exists():
            try:
                import yaml
                raw = yaml.safe_load(path.read_text()) or {}
                shroud_path = raw.get("shroud_path", shroud_path)
                if shroud_path.startswith("$"):
                    shroud_path = os.path.expandvars(shroud_path)
                file_config = raw.get("plugin_config", {})
                if raw.get("enabled") is False:
                    enabled = False
                log.info("[shroud] Config loaded from %s", path)
            except Exception as e:
                log.warning("[shroud] Failed to load config %s: %s", path, e)
        else:
            log.info("[shroud] No config at %s — using defaults", path)

        return cls(enabled=enabled, shroud_path=shroud_path, config=file_config)

    def set_audit_logger(self, audit_logger):
        """Attach the agent's audit file logger so shroud events appear in session logs."""
        self._audit_logger = audit_logger

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self):
        """Spawn the Node.js bridge subprocess."""
        if not self.enabled:
            log.info("[shroud] Plugin disabled — skipping start")
            return False

        if self._started:
            log.warning("[shroud] Already started")
            return True

        dist = Path(self.shroud_path)
        if not dist.exists() or not (dist / "obfuscator.js").exists():
            log.error("[shroud] Shroud dist not found at %s", self.shroud_path)
            self.enabled = False
            return False

        if not self.bridge_script.exists():
            log.error("[shroud] Bridge script not found at %s", self.bridge_script)
            self.enabled = False
            return False

        env = os.environ.copy()
        if self.config:
            env["SHROUD_PLUGIN_CONFIG"] = json.dumps(self.config)

        try:
            self._proc = subprocess.Popen(
                ["node", str(self.bridge_script), self.shroud_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1,
            )

            self._stderr_thread = threading.Thread(
                target=self._read_stderr, daemon=True, name="shroud-stderr"
            )
            self._stderr_thread.start()

            ready_line = self._proc.stdout.readline()
            if not ready_line:
                raise RuntimeError("Bridge process died immediately")

            ready = json.loads(ready_line)
            if not ready.get("ready"):
                raise RuntimeError(f"Unexpected ready signal: {ready}")

            self._version = ready.get("version", "?")
            self._started = True
            log.info("[shroud] Plugin started (v%s, pid=%d)",
                     self._version, self._proc.pid)
            return True

        except Exception as e:
            log.error("[shroud] Failed to start: %s", e)
            self._cleanup()
            self.enabled = False
            return False

    def stop(self):
        """Shut down the bridge subprocess."""
        if self._proc:
            log.info("[shroud] Stopping plugin (pid=%d)", self._proc.pid)
            self._cleanup()
            self._started = False
            log.info("[shroud] Plugin stopped")

    def _cleanup(self):
        if self._proc:
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def _restart(self):
        """Attempt to restart the bridge subprocess after a crash.

        NOTE: mappings from the previous bridge process are lost.
        """
        self._cleanup()
        self._started = False
        try:
            return self.start()
        except Exception as e:
            log.error("[shroud] Restart failed: %s", e)
            return False

    def _read_stderr(self):
        """Read bridge stderr and forward to Python logging."""
        try:
            for line in self._proc.stderr:
                line = line.rstrip()
                if line:
                    log.debug("[shroud-bridge] %s", line)
        except Exception:
            pass

    # ── JSON-RPC communication ──────────────────────────────────────

    def _call(self, method, params=None):
        """Send a JSON-RPC request and return the result."""
        if not self._started or not self._proc or self._proc.poll() is not None:
            if self._started:
                log.error("[shroud] Bridge process died (exit=%s) — attempting restart",
                          self._proc.returncode if self._proc else "?")
                self._started = False
                if self._restart():
                    log.info("[shroud] Bridge restarted successfully")
                else:
                    log.error("[shroud] Bridge restart failed — disabling")
                    self.enabled = False
                    return None
            else:
                return None

        with self._lock:
            self._req_id += 1
            req_id = self._req_id
            req = {"id": req_id, "method": method}
            if params:
                req["params"] = params

            try:
                start_t = time.monotonic()
                self._proc.stdin.write(json.dumps(req) + "\n")
                self._proc.stdin.flush()

                resp_line = self._proc.stdout.readline()
                elapsed_ms = (time.monotonic() - start_t) * 1000

                if not resp_line:
                    log.error("[shroud] Bridge EOF on method=%s", method)
                    self._started = False
                    self.enabled = False
                    return None

                resp = json.loads(resp_line)

                if resp.get("error"):
                    log.warning("[shroud] %s error: %s", method, resp["error"])
                    return None

                if elapsed_ms > 100:
                    log.debug("[shroud] %s took %.1fms", method, elapsed_ms)

                return resp.get("result")

            except (BrokenPipeError, OSError) as e:
                log.error("[shroud] Bridge pipe error on %s: %s — attempting restart", method, e)
                self._started = False
                if self._restart():
                    log.warning("[shroud] Bridge restarted after pipe error (mappings lost)")
                else:
                    self.enabled = False
                return None
            except json.JSONDecodeError as e:
                log.error("[shroud] Bad JSON from bridge on %s: %s", method, e)
                return None

    # ── Audit logging ───────────────────────────────────────────────

    def _log_audit(self, message):
        """Write audit line to both console logger and agent audit file."""
        log.info("%s", message)
        if self._audit_logger:
            try:
                self._audit_logger.info("%s", message)
            except Exception:
                pass

    # ── Public API (matches enterprise agent Sanitizer interface) ───

    def sanitize(self, text):
        """Obfuscate real values → fake values (before sending to LLM)."""
        if not self.enabled or not text:
            return text

        result = self._call("obfuscate", {"text": text})
        if result is None:
            return text

        entity_count = result.get("entityCount", 0)
        if entity_count > 0:
            cats = result.get("categories", {})
            log.debug("[shroud] obfuscate: %d entities %s", entity_count, cats)

        audit = result.get("audit")
        if audit:
            self._last_obf_req = audit.get("req")
            self._log_audit(_fmt_audit_obfuscate(audit))

        return result.get("obfuscated", text)

    def desanitize(self, text):
        """Deobfuscate fake values → real values (after receiving from LLM)."""
        if not self.enabled or not text:
            return text

        result = self._call("deobfuscate", {"text": text})
        if result is None:
            log.warning("[shroud] desanitize: bridge returned None — fakes may leak through! "
                        "text_len=%d", len(text))
            return text

        deobfuscated = result.get("text", text)
        replacement_count = result.get("replacementCount", 0)
        store_size = result.get("storeSize", -1)

        audit = result.get("audit")
        if audit:
            self._log_audit(_fmt_audit_deobfuscate(audit, self._last_obf_req))

        # Residual fake detection
        residual_v4 = _CGNAT_RE.findall(deobfuscated)
        residual_v6 = _ULA_RE.findall(deobfuscated)
        residual = residual_v4 + residual_v6
        if residual:
            unique_residual = set(residual)
            label = "CGNAT/ULA" if residual_v6 else "CGNAT"
            log.warning(
                "[shroud] RESIDUAL FAKES DETECTED after deobfuscation: %d occurrences "
                "(%d unique) of %s IPs in output | store_size=%d | replacements=%d | "
                "residual_ips=%s",
                len(residual), len(unique_residual), label, store_size, replacement_count,
                ",".join(sorted(unique_residual)[:10]),
            )
            if self._audit_logger:
                self._audit_logger.warning(
                    "[shroud][LEAK] Residual %s IPs: %s (store=%d, replacements=%d)",
                    label, ",".join(sorted(unique_residual)[:10]), store_size, replacement_count,
                )

        if store_size == 0 and replacement_count == 0 and len(text) > 100:
            log.warning("[shroud] desanitize: store is EMPTY — no mappings available for "
                        "deobfuscation (bridge may have restarted)")

        return deobfuscated

    def reset(self):
        """Clear all mappings and start a fresh session."""
        result = self._call("reset")
        if result and result.get("ok"):
            log.info("[shroud] Session reset — all mappings cleared")
            self._last_obf_req = None
        return result

    def get_stats(self):
        """Return obfuscation statistics."""
        result = self._call("getStats")
        if result is None:
            return {"enabled": self.enabled, "error": "bridge not running"}
        result["enabled"] = self.enabled
        result["bridge_pid"] = self._proc.pid if self._proc else None
        result["version"] = self._version
        return result

    # ── Runtime control ─────────────────────────────────────────────

    def activate(self):
        """Enable the plugin at runtime."""
        if self.enabled and self._started:
            log.info("[shroud] Already active")
            return True
        self.enabled = True
        ok = self.start()
        if ok:
            log.info("[shroud] Activated")
        return ok

    def deactivate(self):
        """Disable the plugin at runtime (pass-through mode)."""
        self.enabled = False
        self.stop()
        log.info("[shroud] Deactivated — obfuscation disabled")

    def update_config(self, new_config):
        """Hot-reload shroud config without restarting the agent."""
        result = self._call("reconfigure", {"config": new_config})
        if result and result.get("ok"):
            self.config = new_config
            log.info("[shroud] Config updated and reloaded")
            return True
        log.warning("[shroud] Config update failed")
        return False

    def reload_from_file(self):
        """Re-read config file and hot-reload."""
        config_file = _LEGACY_CONFIG_FILE
        if config_file.exists():
            try:
                import yaml
                raw = yaml.safe_load(config_file.read_text()) or {}
                new_config = raw.get("plugin_config", {})
                return self.update_config(new_config)
            except Exception as e:
                log.error("[shroud] Failed to reload config: %s", e)
                return False
        log.warning("[shroud] Config file not found: %s", config_file)
        return False

    # ── Tool registration ────────────────────────────────────────────

    def get_tool_definitions(self) -> list[dict]:
        """Return shroud tool definitions for the agent."""
        return [
            {"name": "shroud_status",
             "description": "Show Shroud privacy plugin stats.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "shroud_reset",
             "description": "Clear all Shroud obfuscation mappings.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "shroud_activate",
             "description": "Enable the Shroud privacy plugin.",
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "shroud_deactivate",
             "description": "Disable the Shroud privacy plugin.",
             "input_schema": {"type": "object", "properties": {}}},
        ]

    def get_tool_handlers(self) -> dict:
        """Return {tool_name: handler_fn} for shroud tools."""
        return {
            "shroud_status": lambda _: self.get_stats(),
            "shroud_reset": lambda _: (
                {"ok": True, "message": "Shroud session reset. All mappings cleared."}
                if self.reset() else {"error": "Reset failed"}),
            "shroud_activate": lambda _: (
                {"ok": True, "message": "Shroud activated"} if self.activate()
                else {"ok": False, "message": "Activation failed"}),
            "shroud_deactivate": lambda _: (
                self.deactivate() or
                {"ok": True, "message": "Shroud deactivated — obfuscation disabled"}),
        }

    @property
    def is_running(self):
        return (self._started and self._proc is not None
                and self._proc.poll() is None)

    def __repr__(self):
        state = "active" if self.is_running else ("disabled" if not self.enabled else "stopped")
        return f"<ShroudPlugin state={state} version={self._version}>"
```
