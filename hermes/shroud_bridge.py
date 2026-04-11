"""
Shroud Bridge — manages the APP server lifecycle for the Hermes plugin.

Communicates via newline-delimited JSON-RPC on stdin/stdout (APP-RFC-0001).
Auto-detects the APP server from the plugin directory (cloned repo) or
env var overrides.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hermes.plugins.shroud")


# Default field scoping config — auto-enabled for all platforms.
# Reduces false positives on structural fields (IDs, hashes, timestamps).
_DEFAULT_FIELD_SCOPING = {
    "toolFields": {
        "read_file":      {"scanFields": ["content", "text"]},
        "Read":           {"scanFields": ["content", "text"]},
        "write_file":     {"scanFields": ["content", "text"]},
        "patch":          {"scanFields": ["content", "new_content", "old_content"]},
        "terminal":       {"scanFields": ["output", "stdout", "stderr", "command"]},
        "Bash":           {"scanFields": ["output", "stdout", "stderr", "command"]},
        "execute_code":   {"scanFields": ["code", "output", "stdout", "stderr"]},
        "web_search":     {"scanFields": ["query", "results", "content"]},
        "web_extract":    {"scanFields": ["content", "text", "markdown"]},
        "search_files":   {"scanFields": ["content", "matches"]},
        "send_message":   {"scanFields": ["content", "text", "message"]},
        "delegate_task":  {"scanFields": ["task", "result"]},
        "clarify":        {"scanFields": ["question", "answer"]},
        "memory":         {"scanFields": ["content", "text", "value"]},
        "search_sessions": {"scanFields": ["query", "results", "content"]},
    },
    "neverScanFields": [
        "id", "tool_call_id", "created_at", "updated_at",
        "sha", "hash", "ref", "type", "status", "state", "mode",
        "finish_reason", "index", "role",
    ],
    "defaultScanFields": [],
    "useContractExemptions": False,
}


class ShroudBridge:
    """Manages a Shroud APP server subprocess."""

    def __init__(self, plugin_dir: Optional[Path] = None) -> None:
        self._plugin_dir = plugin_dir
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._req_id = 0
        self._started = False
        self.version: Optional[str] = None
        self.capabilities: List[str] = []
        self.has_security = False
        self._config = self._load_config()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._started:
            return

        server, dist = self._resolve_paths()
        if not server.exists():
            raise FileNotFoundError(f"Shroud APP server not found: {server}")
        if not dist.exists():
            raise FileNotFoundError(f"Shroud dist/ not found: {dist}")

        env = os.environ.copy()
        if self._config:
            env["SHROUD_PLUGIN_CONFIG"] = json.dumps(self._config)

        # Isolate temp files per Hermes instance
        hermes_home = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
        env.setdefault("SHROUD_STATS_FILE", str(Path(hermes_home) / "shroud-stats.json"))
        env.setdefault("SHROUD_APP_SESSIONS_FILE", str(Path(hermes_home) / "shroud-sessions.json"))
        env.setdefault("SHROUD_APP_EVENTS_FILE", str(Path(hermes_home) / "shroud-events.jsonl"))

        self._proc = subprocess.Popen(
            ["node", str(server), str(dist)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )

        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True, name="shroud-stderr",
        )
        self._stderr_thread.start()

        line = self._proc.stdout.readline()
        if not line:
            self._cleanup()
            raise RuntimeError("Shroud APP server died on startup")

        handshake = json.loads(line)
        if not handshake.get("app"):
            self._cleanup()
            raise RuntimeError(f"Unexpected APP handshake: {handshake}")

        self.version = handshake.get("version", "?")
        self.capabilities = handshake.get("capabilities", [])
        self.has_security = "tool_call" in self.capabilities
        self._started = True

        if "identify" in self.capabilities:
            self._call("identify", {
                "agent": "hermes-agent",
                "version": os.environ.get("HERMES_VERSION", "0.8.0"),
                "channel": "hermes-plugin",
            })

        logger.info(
            "Shroud APP server v%s started (pid=%d, security=%s)",
            self.version, self._proc.pid, self.has_security,
        )

    def stop(self) -> None:
        if not self._started:
            return
        try:
            self._call("shutdown")
        except Exception:
            pass
        self._cleanup()
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started and self._proc is not None and self._proc.poll() is None

    # -- public API ---------------------------------------------------------

    def obfuscate(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"text": text, "entityCount": 0, "modified": False}
        return self._call_safe("obfuscate", {"text": text}) or {"text": text, "entityCount": 0, "modified": False}

    def deobfuscate(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"text": text, "replacementCount": 0, "modified": False}
        return self._call_safe("deobfuscate", {"text": text}) or {"text": text, "replacementCount": 0, "modified": False}

    def stats(self) -> Dict[str, Any]:
        return self._call_safe("stats") or {}

    def reset(self) -> bool:
        return self._call_safe("reset") is not None

    def health(self) -> Dict[str, Any]:
        return self._call_safe("health") or {}

    def tool_call(self, tool_name: str, args: dict) -> Dict[str, Any]:
        if not self.has_security:
            return {"allowed": True, "blocked": False}
        return self._call_safe("tool_call", {"tool": tool_name, "args": args}) or {}

    def tool_result(self, tool_name: str, result: str) -> Dict[str, Any]:
        if not self.has_security:
            return {"ok": True}
        return self._call_safe("tool_result", {"tool": tool_name, "result": result}) or {}

    # -- JSON-RPC transport -------------------------------------------------

    def _call(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        with self._lock:
            if not self._proc or self._proc.poll() is not None:
                raise ConnectionError("Shroud APP server not running")
            self._req_id += 1
            req = {"id": self._req_id, "method": method}
            if params:
                req["params"] = params
            self._proc.stdin.write(json.dumps(req) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
            if not line:
                raise ConnectionError("Shroud APP server EOF")
            resp = json.loads(line)
            if resp.get("error"):
                err = resp["error"]
                msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                logger.debug("Shroud %s error: %s", method, msg)
                return None
            return resp.get("result")

    def _call_safe(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        try:
            return self._call(method, params)
        except (ConnectionError, BrokenPipeError, OSError) as e:
            logger.warning("Shroud connection lost on %s: %s", method, e)
            self._cleanup()
            self._started = False
            try:
                self.start()
                logger.warning("Shroud restarted (mappings lost)")
                return self._call(method, params)
            except Exception:
                logger.error("Shroud restart failed")
            return None

    # -- path resolution ----------------------------------------------------

    def _resolve_paths(self) -> tuple:
        server_env = os.environ.get("SHROUD_SERVER_PATH")
        dist_env = os.environ.get("SHROUD_DIST_PATH")
        if server_env and dist_env:
            return Path(server_env), Path(dist_env)

        # Plugin directory (cloned repo via hermes plugins install)
        if self._plugin_dir:
            server = self._plugin_dir / "app-server.mjs"
            dist = self._plugin_dir / "dist"
            if server.exists() and dist.exists():
                return server, dist

        # Search candidates
        candidates = [
            Path.home() / "shroud",
            Path.cwd() / "node_modules" / "shroud-privacy",
            Path.home() / ".npm-global" / "lib" / "node_modules" / "shroud-privacy",
        ]
        for base in candidates:
            server = base / "app-server.mjs"
            dist = base / "dist"
            if server.exists() and dist.exists():
                return server, dist

        raise FileNotFoundError(
            "Cannot find Shroud APP server. Run 'npm install' in the plugin "
            "directory, or set SHROUD_SERVER_PATH and SHROUD_DIST_PATH."
        )

    # -- config -------------------------------------------------------------

    def _load_config(self) -> Dict:
        config = {}
        env_config = os.environ.get("SHROUD_PLUGIN_CONFIG")
        if env_config:
            try:
                config = json.loads(env_config)
            except json.JSONDecodeError:
                pass

        # Auto-enable field scoping for all platforms
        if "fieldScoping" not in config:
            config["fieldScoping"] = _DEFAULT_FIELD_SCOPING

        return config

    # -- internal -----------------------------------------------------------

    def _cleanup(self) -> None:
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

    def _drain_stderr(self) -> None:
        try:
            for line in self._proc.stderr:
                line = line.rstrip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("heartbeat"):
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass
                logger.debug("[shroud] %s", line)
        except Exception:
            pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
