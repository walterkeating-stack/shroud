"""
Shroud Privacy Plugin for Hermes Agent
=======================================

Intercepts all outbound LLM API calls, obfuscates sensitive data (PII,
credentials, network topology, ICS/SCADA identifiers) with deterministic
fakes, and deobfuscates responses so tools and users see real values.

Install:
    hermes plugins install wkeything/shroud

The plugin auto-builds the Shroud engine on first use if needed (requires
Node.js on PATH).  No manual npm install required.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("hermes.plugins.shroud")

_client: Optional[Any] = None
_interceptor: Optional[Any] = None
_lock = threading.Lock()
_started = False
_plugin_dir = Path(__file__).parent


def register(ctx) -> None:
    """Entry point called by Hermes plugin loader."""
    # Auto-build dist/ if not present
    _ensure_built()

    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)

    atexit.register(_shutdown)

    logger.info("Shroud plugin registered")


# ---------------------------------------------------------------------------
# Auto-build
# ---------------------------------------------------------------------------

def _ensure_built() -> None:
    """Build dist/ from TypeScript source if it doesn't exist."""
    dist = _plugin_dir / "dist"
    if dist.exists() and (dist / "obfuscator.js").exists():
        return

    logger.info("Shroud dist/ not found — building from source...")
    try:
        # Install deps
        subprocess.run(
            ["npm", "install", "--ignore-scripts"],
            cwd=str(_plugin_dir),
            capture_output=True,
            timeout=120,
        )
        # Compile TypeScript
        result = subprocess.run(
            ["npx", "tsc"],
            cwd=str(_plugin_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.error("Shroud build failed: %s", result.stderr[:500])
            return
        logger.info("Shroud built successfully")
    except FileNotFoundError:
        logger.error("Node.js/npm not found — cannot build Shroud. Install Node.js and restart.")
    except subprocess.TimeoutExpired:
        logger.error("Shroud build timed out")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def _on_session_start(**kwargs) -> None:
    """Start the Shroud APP server and install the SDK interceptor."""
    global _client, _interceptor, _started

    with _lock:
        if _started:
            return

        try:
            from hermes.shroud_bridge import ShroudBridge
            bridge = ShroudBridge(plugin_dir=_plugin_dir)
            bridge.start()
            _client = bridge

            from hermes.interceptor import install_openai_interceptor
            _interceptor = install_openai_interceptor(bridge)
            _started = True

            session_id = kwargs.get("session_id", "")
            model = kwargs.get("model", "")
            logger.info(
                "Shroud started for session %s (model=%s, engine=v%s)",
                session_id[:12], model, bridge.version or "?",
            )

        except FileNotFoundError as e:
            logger.warning("Shroud not available: %s", e)
        except Exception as e:
            logger.error("Shroud startup failed: %s", e, exc_info=True)


def _on_session_end(**kwargs) -> None:
    """Called at the end of every turn — keep Shroud running."""
    if _started and _client is not None:
        try:
            stats = _client.stats()
            logger.debug(
                "Shroud turn end: obfuscations=%d, deobfuscations=%d, store=%d",
                stats.get("audit", {}).get("totalObfuscations", 0),
                stats.get("audit", {}).get("totalDeobfuscations", 0),
                stats.get("storeMappings", 0),
            )
        except Exception:
            pass


def _shutdown() -> None:
    """Stop the Shroud APP server — called via atexit."""
    global _client, _interceptor, _started

    with _lock:
        if not _started:
            return

        try:
            if _interceptor is not None:
                from hermes.interceptor import uninstall_openai_interceptor
                uninstall_openai_interceptor(_interceptor)
                _interceptor = None

            if _client is not None:
                stats = _client.stats()
                logger.info(
                    "Shroud session summary: obfuscations=%d, deobfuscations=%d, store=%d",
                    stats.get("audit", {}).get("totalObfuscations", 0),
                    stats.get("audit", {}).get("totalDeobfuscations", 0),
                    stats.get("storeMappings", 0),
                )
                _client.stop()
                _client = None

        except Exception as e:
            logger.warning("Shroud shutdown error: %s", e)
        finally:
            _started = False


# ---------------------------------------------------------------------------
# Tool hooks
# ---------------------------------------------------------------------------

def _on_pre_tool_call(**kwargs) -> None:
    """Security scan + deobfuscate tool args before execution."""
    if not _started or _client is None:
        return

    tool_name = kwargs.get("tool_name", "")
    args = kwargs.get("args")

    # APP security scan (Firewall only — graceful no-op on core)
    if tool_name and isinstance(args, dict):
        try:
            scan = _client.tool_call(tool_name, args)
            if scan.get("blocked"):
                logger.warning("Shroud tool guard BLOCKED %s: %s", tool_name, scan.get("reason", "unknown"))
            elif scan.get("events"):
                for evt in scan["events"]:
                    logger.warning("Shroud tool guard: %s (%s) on %s",
                                   evt.get("threatClass", "?"), evt.get("severity", "?"), tool_name)
        except Exception as e:
            logger.debug("Shroud tool_call scan error: %s", e)

    # Deobfuscate args in-place
    if isinstance(args, dict):
        try:
            _deobfuscate_dict_inplace(args)
        except Exception as e:
            logger.debug("Shroud pre_tool_call deobfuscation error: %s", e)


def _deobfuscate_dict_inplace(d: dict) -> None:
    for key, value in list(d.items()):
        if isinstance(value, str) and value:
            result = _client.deobfuscate(value)
            if result.get("modified"):
                d[key] = result["text"]
        elif isinstance(value, dict):
            _deobfuscate_dict_inplace(value)
        elif isinstance(value, list):
            _deobfuscate_list_inplace(value)


def _deobfuscate_list_inplace(lst: list) -> None:
    for i, item in enumerate(lst):
        if isinstance(item, str) and item:
            result = _client.deobfuscate(item)
            if result.get("modified"):
                lst[i] = result["text"]
        elif isinstance(item, dict):
            _deobfuscate_dict_inplace(item)
        elif isinstance(item, list):
            _deobfuscate_list_inplace(item)


def _on_post_tool_call(**kwargs) -> None:
    """Scan tool output for exfiltration markers (Firewall only)."""
    if not _started or _client is None:
        return

    tool_name = kwargs.get("tool_name", "")
    result = kwargs.get("result", "")

    if not tool_name or not isinstance(result, str) or not result:
        return

    try:
        scan = _client.tool_result(tool_name, result)
        if scan.get("events"):
            for evt in scan["events"]:
                logger.warning("Shroud tool_result scan: %s (%s) in %s output",
                               evt.get("threatClass", "?"), evt.get("severity", "?"), tool_name)
    except Exception as e:
        logger.debug("Shroud tool_result scan error: %s", e)
