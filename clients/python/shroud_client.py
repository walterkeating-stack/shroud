"""Shroud APP Client — standalone Python client for the Agent Privacy Protocol.

Spawns the Shroud APP server (app-server.mjs) as a subprocess and provides
obfuscate/deobfuscate over JSON-RPC on stdin/stdout.

Drop this file into any Python agent to add privacy obfuscation. No
framework dependencies — just Python 3.8+ and Node.js on the PATH.

Usage:
    from shroud_client import ShroudClient

    client = ShroudClient()
    client.start()

    safe = client.obfuscate("Contact admin@acme.com about 10.1.0.1")
    # safe.text = "Contact user@example.net about 100.64.0.12"
    # safe.entity_count = 2

    real = client.deobfuscate(llm_response)
    # real.text has original values restored

    client.stop()

Protocol: APP-RFC-0001 (Agent Privacy Protocol)
  - Transport: newline-delimited JSON-RPC over stdin/stdout
  - Handshake: {"app":"1.0","engine":"shroud","version":"...","capabilities":[...]}
  - Methods: obfuscate, deobfuscate, reset, stats, health, configure, shutdown
"""

import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("shroud")

# Shroud's fake IP ranges — used for residual leak detection
_CGNAT_RE_PATTERN = r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b"
_ULA_RE_PATTERN = r"\bfd00:[0-9a-fA-F:]{2,39}\b"

try:
    import re
    _CGNAT_RE = re.compile(_CGNAT_RE_PATTERN)
    _ULA_RE = re.compile(_ULA_RE_PATTERN)
except ImportError:
    _CGNAT_RE = None
    _ULA_RE = None


@dataclass
class ObfuscateResult:
    """Result of an obfuscate call."""
    text: str
    entity_count: int = 0
    categories: Dict[str, int] = field(default_factory=dict)
    modified: bool = False
    audit: Optional[Dict] = None


@dataclass
class DeobfuscateResult:
    """Result of a deobfuscate call."""
    text: str
    replacement_count: int = 0
    modified: bool = False
    audit: Optional[Dict] = None
    residual_fakes: List[str] = field(default_factory=list)


class ShroudClient:
    """Python client for the Shroud APP server.

    Args:
        server_script: Path to app-server.mjs. If None, auto-detected from
            the npm package (node_modules/shroud-privacy/app-server.mjs).
        dist_path: Path to Shroud dist/ directory. If None, auto-detected.
        config: Plugin configuration dict (passed via SHROUD_PLUGIN_CONFIG env).
        auto_restart: Restart the server if it crashes (default True).
        node_command: Node.js binary name (default "node").
    """

    def __init__(
        self,
        server_script: Optional[str] = None,
        dist_path: Optional[str] = None,
        config: Optional[Dict] = None,
        auto_restart: bool = True,
        node_command: str = "node",
    ):
        self._server_script = server_script
        self._dist_path = dist_path
        self._config = config or {}
        self._auto_restart = auto_restart
        self._node = node_command
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._req_id = 0
        self._started = False
        self._version: Optional[str] = None
        self._capabilities: List[str] = []

    # ── Lifecycle ────────────────────────────────────────────

    def start(self) -> bool:
        """Spawn the APP server and wait for the handshake."""
        if self._started:
            return True

        server, dist = self._resolve_paths()
        if not server.exists():
            raise FileNotFoundError(f"APP server not found: {server}")
        if not dist.exists():
            raise FileNotFoundError(f"Shroud dist not found: {dist}")

        env = os.environ.copy()
        if self._config:
            env["SHROUD_PLUGIN_CONFIG"] = json.dumps(self._config)

        try:
            self._proc = subprocess.Popen(
                [self._node, str(server), str(dist)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1,
            )

            # Stderr reader (heartbeats + debug logs)
            self._stderr_thread = threading.Thread(
                target=self._read_stderr, daemon=True, name="shroud-stderr",
            )
            self._stderr_thread.start()

            # Read handshake
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError("APP server died on startup")

            handshake = json.loads(line)
            if not handshake.get("app"):
                raise RuntimeError(f"Unexpected handshake: {handshake}")

            self._version = handshake.get("version", "?")
            self._capabilities = handshake.get("capabilities", [])
            self._started = True

            log.info("Shroud started (v%s, capabilities=%s, pid=%d)",
                     self._version, self._capabilities, self._proc.pid)
            return True

        except Exception as e:
            log.error("Failed to start Shroud: %s", e)
            self._cleanup()
            raise

    def stop(self):
        """Gracefully shut down the APP server."""
        if not self._started:
            return
        try:
            self._call("shutdown")
        except Exception:
            pass
        self._cleanup()
        self._started = False
        log.info("Shroud stopped")

    @property
    def version(self) -> Optional[str]:
        return self._version

    @property
    def is_running(self) -> bool:
        return self._started and self._proc is not None and self._proc.poll() is None

    # ── Public API ───────────────────────────────────────────

    def obfuscate(self, text: str) -> ObfuscateResult:
        """Obfuscate sensitive data before sending to LLM."""
        if not text:
            return ObfuscateResult(text=text)

        result = self._call_safe("obfuscate", {"text": text})
        if result is None:
            return ObfuscateResult(text=text)

        return ObfuscateResult(
            text=result.get("text", text),
            entity_count=result.get("entityCount", 0),
            categories=result.get("categories", {}),
            modified=result.get("modified", False),
            audit=result.get("audit"),
        )

    def deobfuscate(self, text: str) -> DeobfuscateResult:
        """Restore real values after receiving from LLM."""
        if not text:
            return DeobfuscateResult(text=text)

        result = self._call_safe("deobfuscate", {"text": text})
        if result is None:
            return DeobfuscateResult(text=text)

        deobfuscated = result.get("text", text)

        # Residual fake detection
        residual = []
        if _CGNAT_RE:
            residual.extend(_CGNAT_RE.findall(deobfuscated))
        if _ULA_RE:
            residual.extend(_ULA_RE.findall(deobfuscated))
        if residual:
            log.warning("Residual fake IPs in output: %s", residual[:10])

        return DeobfuscateResult(
            text=deobfuscated,
            replacement_count=result.get("replacementCount", 0),
            modified=result.get("modified", False),
            audit=result.get("audit"),
            residual_fakes=residual,
        )

    def reset(self) -> bool:
        """Clear all mappings."""
        result = self._call_safe("reset")
        return result is not None

    def stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return self._call_safe("stats") or {}

    def health(self) -> Dict[str, Any]:
        """Liveness check."""
        return self._call_safe("health") or {}

    def configure(self, config: Dict) -> bool:
        """Hot-reload configuration."""
        result = self._call_safe("configure", {"config": config})
        if result and result.get("ok"):
            self._config = config
            return True
        return False

    # ── JSON-RPC transport ───────────────────────────────────

    def _call(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Send a JSON-RPC request and return the result."""
        with self._lock:
            if not self._proc or self._proc.poll() is not None:
                raise ConnectionError("APP server not running")

            self._req_id += 1
            req = {"id": self._req_id, "method": method}
            if params:
                req["params"] = params

            self._proc.stdin.write(json.dumps(req) + "\n")
            self._proc.stdin.flush()

            line = self._proc.stdout.readline()
            if not line:
                raise ConnectionError("APP server EOF")

            resp = json.loads(line)
            if resp.get("error"):
                err = resp["error"]
                msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                log.warning("Shroud %s error: %s", method, msg)
                return None

            return resp.get("result")

    def _call_safe(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Call with auto-restart on failure."""
        try:
            return self._call(method, params)
        except (ConnectionError, BrokenPipeError, OSError) as e:
            log.error("Shroud connection lost on %s: %s", method, e)
            if self._auto_restart:
                self._cleanup()
                self._started = False
                try:
                    self.start()
                    log.warning("Shroud restarted (mappings lost)")
                    return self._call(method, params)
                except Exception:
                    log.error("Shroud restart failed")
            return None

    # ── Internal ─────────────────────────────────────────────

    def _resolve_paths(self):
        """Find app-server.mjs and dist/ path."""
        if self._server_script and self._dist_path:
            return Path(self._server_script), Path(self._dist_path)

        # Auto-detect from npm install
        candidates = [
            # Relative to this file (if copied into project)
            Path(__file__).parent.parent.parent,
            # npm node_modules
            Path("node_modules/shroud-privacy"),
            # Global npm
            Path.home() / ".npm-global/lib/node_modules/shroud-privacy",
        ]

        for base in candidates:
            server = base / "app-server.mjs"
            dist = base / "dist"
            if server.exists() and dist.exists():
                return server, dist

        # Fallback to explicit paths
        server = Path(self._server_script or "app-server.mjs")
        dist = Path(self._dist_path or "dist")
        return server, dist

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

    def _read_stderr(self):
        try:
            for line in self._proc.stderr:
                line = line.rstrip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("heartbeat"):
                        log.debug("heartbeat: up=%ds reqs=%d store=%d",
                                  msg.get("uptime", 0), msg.get("requests", 0),
                                  msg.get("storeSize", 0))
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass
                log.debug("[app-server] %s", line)
        except Exception:
            pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def __repr__(self):
        state = "running" if self.is_running else "stopped"
        return f"<ShroudClient state={state} version={self._version}>"
