"""
OpenAI SDK Interceptor — wraps chat.completions.create to obfuscate
outbound messages and deobfuscate inbound responses.

This is the Python equivalent of Shroud's JS-side ``globalThis.fetch``
intercept.  It wraps the OpenAI SDK method (NOT Hermes code) at runtime.
Hermes sees a standard OpenAI SDK interface — messages flow in, responses
flow out.  The interceptor is invisible to Hermes.

Streaming deobfuscation
-----------------------
Hermes always uses ``stream=True``.  Outbound messages are obfuscated
before the request.  Inbound deltas are deobfuscated using a buffered
approach:

1. Accumulate all content deltas into a running buffer
2. On each new delta, deobfuscate the FULL buffer
3. Emit only the incremental diff as the new delta content

This ensures fake values that span chunk boundaries are correctly
deobfuscated.  Hermes's message assembly sees deobfuscated deltas and
naturally builds correct conversation history.  No Hermes modifications.
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Iterator, Optional

logger = logging.getLogger("hermes.plugins.shroud")


class _InterceptorState:
    """Holds references needed to install/uninstall the monkey-patch."""

    def __init__(self):
        self.original_create = None
        self.original_create_class = None
        self.bridge = None
        self.installed = False


def install_openai_interceptor(bridge) -> _InterceptorState:
    """Wrap openai.resources.chat.completions.Completions.create.

    This wraps the OpenAI SDK — NOT Hermes.  Hermes calls the SDK normally
    and receives obfuscated/deobfuscated results transparently.
    """
    state = _InterceptorState()
    state.bridge = bridge

    try:
        import openai.resources.chat.completions as _mod
        cls = _mod.Completions
    except (ImportError, AttributeError) as e:
        logger.warning("Cannot install Shroud interceptor: OpenAI SDK not found (%s)", e)
        return state

    state.original_create = cls.create
    state.original_create_class = cls

    def _wrapped_create(self_sdk, *args, **kwargs):
        if not bridge.is_running:
            return state.original_create(self_sdk, *args, **kwargs)

        # Obfuscate outbound messages
        messages = kwargs.get("messages")
        if messages:
            kwargs["messages"] = _obfuscate_messages(bridge, messages)

        is_stream = kwargs.get("stream", False)
        logger.info("Shroud interceptor: create() called, stream=%s, messages=%d",
                     is_stream, len(messages) if messages else 0)

        if is_stream:
            raw_stream = state.original_create(self_sdk, *args, **kwargs)
            logger.info("Shroud interceptor: wrapping stream (raw type=%s)", type(raw_stream).__name__)
            return _DeobfuscatingStream(raw_stream, bridge)
        else:
            response = state.original_create(self_sdk, *args, **kwargs)
            return _deobfuscate_response(bridge, response)

    cls.create = _wrapped_create
    state.installed = True
    logger.info("Shroud interceptor installed on OpenAI SDK")
    return state


def uninstall_openai_interceptor(state: _InterceptorState) -> None:
    """Restore the original SDK method."""
    if not state.installed:
        return
    try:
        state.original_create_class.create = state.original_create
        state.installed = False
        logger.info("Shroud interceptor removed from OpenAI SDK")
    except Exception as e:
        logger.warning("Failed to remove interceptor: %s", e)


# ---------------------------------------------------------------------------
# Outbound obfuscation
# ---------------------------------------------------------------------------

def _obfuscate_messages(bridge, messages: list) -> list:
    """Deep-copy messages and obfuscate content.

    Only obfuscates user, system, and tool messages.  Assistant messages
    are left as-is — they contain LLM-generated text that was already
    deobfuscated when received, so it has real values that need to be
    re-obfuscated.  Actually, we obfuscate ALL roles because any message
    may contain real values (tool results, user input, system prompts).
    """
    result = []
    for msg in messages:
        msg_copy = dict(msg)
        content = msg_copy.get("content")

        if isinstance(content, str) and content:
            obf = bridge.obfuscate(content)
            msg_copy["content"] = obf["text"]

        elif isinstance(content, list):
            parts_copy = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                    part_copy = dict(part)
                    obf = bridge.obfuscate(part_copy["text"])
                    part_copy["text"] = obf["text"]
                    parts_copy.append(part_copy)
                else:
                    parts_copy.append(part)
            msg_copy["content"] = parts_copy

        result.append(msg_copy)
    return result


def _tc_to_dict(tc) -> dict:
    """Convert an OpenAI ToolCall object to a plain dict."""
    if isinstance(tc, dict):
        return tc
    return {
        "id": getattr(tc, "id", ""),
        "type": getattr(tc, "type", "function"),
        "function": {
            "name": getattr(getattr(tc, "function", None), "name", ""),
            "arguments": getattr(getattr(tc, "function", None), "arguments", ""),
        },
    }


# ---------------------------------------------------------------------------
# Inbound deobfuscation (non-streaming)
# ---------------------------------------------------------------------------

def _deobfuscate_response(bridge, response) -> Any:
    """Deobfuscate a non-streaming chat completion response."""
    try:
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if msg is None:
                continue

            content = getattr(msg, "content", None)
            if isinstance(content, str) and content:
                deob = bridge.deobfuscate(content)
                _setattr_safe(msg, "content", deob["text"])

            tool_calls = getattr(msg, "tool_calls", None)
            if tool_calls:
                for tc in tool_calls:
                    fn = getattr(tc, "function", None)
                    if fn and getattr(fn, "arguments", None):
                        deob = bridge.deobfuscate(fn.arguments)
                        _setattr_safe(fn, "arguments", deob["text"])
    except Exception as e:
        logger.debug("Deobfuscation error (non-stream): %s", e)

    return response


def _setattr_safe(obj, attr, value):
    """Set attribute, handling frozen Pydantic models."""
    try:
        setattr(obj, attr, value)
    except (TypeError, ValueError, AttributeError):
        try:
            object.__setattr__(obj, attr, value)
        except Exception:
            try:
                obj.__dict__[attr] = value
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Inbound deobfuscation (streaming) — buffered approach
# ---------------------------------------------------------------------------

class _DeobfuscatingStream:
    """Wraps an OpenAI streaming response to deobfuscate content in-place.

    Uses buffered deobfuscation: accumulates the full content text, deobfuscates
    the entire buffer on each chunk, and emits only the incremental diff.
    This handles fake values that span chunk boundaries correctly.

    From Hermes's perspective, this is just a normal stream that happens to
    yield deobfuscated content.  No Hermes code is modified.
    """

    def __init__(self, stream, bridge):
        self._stream = stream
        self._bridge = bridge

        # Proxy .response for rate limit header capture
        self.response = getattr(stream, "response", None)

    def __iter__(self):
        return self._wrap_iter()

    def __enter__(self):
        if hasattr(self._stream, "__enter__"):
            self._stream.__enter__()
        return self

    def __exit__(self, *exc):
        if hasattr(self._stream, "__exit__"):
            self._stream.__exit__(*exc)

    def _wrap_iter(self) -> Iterator:
        """Yield chunks with deobfuscated content deltas.

        Each delta is deobfuscated immediately — no holdback buffer.
        This ensures the gateway stream consumer (which progressively
        edits Slack/Telegram messages) never shows fake values to users.

        Trade-off: if a fake value is split across two chunks (rare with
        real LLM tokenizers), the split fake won't be deobfuscated.
        In practice, fake emails/IPs/SSNs are single tokens.
        """
        HOLDBACK = 80

        content_buffer = ""
        emitted_len = 0

        for chunk in self._stream:
            if not chunk.choices:
                yield chunk
                continue

            delta = chunk.choices[0].delta
            finish_reason = getattr(chunk.choices[0], "finish_reason", None)

            content_delta = getattr(delta, "content", None)
            if content_delta:
                content_buffer += content_delta

            # How much of the buffer is safe to deob and emit?
            if finish_reason:
                safe_len = len(content_buffer)
            else:
                safe_len = max(0, len(content_buffer) - HOLDBACK)

            if safe_len > emitted_len:
                deob = self._bridge.deobfuscate(content_buffer[:safe_len])
                emit_text = deob["text"][emitted_len:]
                emitted_len = len(deob["text"])
                _setattr_safe(delta, "content", emit_text if emit_text else None)
            elif content_delta is not None:
                # Held back — set to None so Hermes and Slack skip it
                _setattr_safe(delta, "content", None)

            # Tool call argument deltas are NOT deobfuscated in the stream.
            # The pre_tool_call hook deobfuscates the full parsed dict
            # before tool execution.

            yield chunk

    # Proxy any other attribute access to the underlying stream
    def __getattr__(self, name):
        return getattr(self._stream, name)
