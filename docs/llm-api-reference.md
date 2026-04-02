# LLM API Reference — Request & Response Formats

How Anthropic, OpenAI, and Google structure their chat completion APIs. This is what Shroud sees when intercepting fetch requests (OpenClaw path) or what agents send through APP `sanitize()` calls.

## Anthropic (`/v1/messages`)

### Request

```json
{
  "model": "claude-sonnet-4-20250514",
  "system": "You are a network configuration automation agent...",
  "messages": [
    {
      "role": "user",
      "content": "Generate config for CORE-SW-1A"
    },
    {
      "role": "assistant",
      "content": [
        {"type": "text", "text": "I'll generate that config."},
        {"type": "tool_use", "id": "toolu_01A", "name": "generate_config", "input": {"device": "CORE-SW-1A"}}
      ]
    },
    {
      "role": "user",
      "content": [
        {"type": "tool_result", "tool_use_id": "toolu_01A", "content": "hostname CORE-SW-1A\ninterface Gi0/1\n..."}
      ]
    }
  ],
  "tools": [
    {
      "name": "generate_config",
      "description": "Generate Cisco IOS .cfg file for a device",
      "input_schema": {
        "type": "object",
        "properties": {
          "device": {"type": "string", "description": "Device name"}
        },
        "required": ["device"]
      }
    }
  ],
  "max_tokens": 4096,
  "stream": true
}
```

### Response (streaming SSE)

**Message start:**
```
event: message_start
data: {"type": "message_start", "message": {"id": "msg_01X", "type": "message", "role": "assistant", "model": "claude-sonnet-4-20250514", "usage": {"input_tokens": 1200, "output_tokens": 0}}}
```

**Text block:**
```
event: content_block_start
data: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Here's the"}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " generated config"}}

event: content_block_stop
data: {"type": "content_block_stop", "index": 0}
```

**Tool use block:**
```
event: content_block_start
data: {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_01B", "name": "exec"}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"command\":"}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": " \"show run\"}"}}

event: content_block_stop
data: {"type": "content_block_stop", "index": 1}
```

**Message end:**
```
event: message_delta
data: {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 85}}

event: message_stop
data: {"type": "message_stop"}
```

### Response (non-streaming)

```json
{
  "id": "msg_01X",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-4-20250514",
  "content": [
    {"type": "text", "text": "Here's the generated config."},
    {"type": "tool_use", "id": "toolu_01B", "name": "generate_config", "input": {"device": "CORE-SW-1A"}}
  ],
  "stop_reason": "tool_use",
  "usage": {"input_tokens": 1200, "output_tokens": 85}
}
```

---

## OpenAI (`/v1/chat/completions`)

### Request

```json
{
  "model": "gpt-4o",
  "messages": [
    {
      "role": "system",
      "content": "You are a network configuration automation agent..."
    },
    {
      "role": "user",
      "content": "Generate config for CORE-SW-1A"
    },
    {
      "role": "assistant",
      "content": "I'll generate that config.",
      "tool_calls": [
        {
          "id": "call_01A",
          "type": "function",
          "function": {
            "name": "generate_config",
            "arguments": "{\"device\": \"CORE-SW-1A\"}"
          }
        }
      ]
    },
    {
      "role": "tool",
      "tool_call_id": "call_01A",
      "content": "hostname CORE-SW-1A\ninterface Gi0/1\n..."
    }
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "generate_config",
        "description": "Generate Cisco IOS .cfg file for a device",
        "parameters": {
          "type": "object",
          "properties": {
            "device": {"type": "string", "description": "Device name"}
          },
          "required": ["device"]
        }
      }
    }
  ],
  "max_tokens": 4096,
  "stream": true
}
```

### Response (streaming SSE)

**Text chunk:**
```
data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "model": "gpt-4o", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": null}]}

data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "Here's the"}, "finish_reason": null}]}

data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": " generated config"}, "finish_reason": null}]}
```

**Tool call chunk:**
```
data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_01B", "type": "function", "function": {"name": "exec", "arguments": ""}}]}, "finish_reason": null}]}

data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"command\":"}}]}, "finish_reason": null}]}

data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": " \"show run\"}"}}]}, "finish_reason": null}]}
```

**End:**
```
data: {"id": "chatcmpl-X", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}

data: [DONE]
```

### Response (non-streaming)

```json
{
  "id": "chatcmpl-X",
  "object": "chat.completion",
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Here's the generated config.",
        "tool_calls": [
          {
            "id": "call_01B",
            "type": "function",
            "function": {
              "name": "generate_config",
              "arguments": "{\"device\": \"CORE-SW-1A\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ],
  "usage": {"prompt_tokens": 1200, "completion_tokens": 85, "total_tokens": 1285}
}
```

---

## Google Gemini (`/v1beta/models/*:generateContent`)

### Request

```json
{
  "systemInstruction": {
    "parts": [{"text": "You are a network configuration automation agent..."}]
  },
  "contents": [
    {
      "role": "user",
      "parts": [{"text": "Generate config for CORE-SW-1A"}]
    },
    {
      "role": "model",
      "parts": [
        {"text": "I'll generate that config."},
        {"functionCall": {"name": "generate_config", "args": {"device": "CORE-SW-1A"}}}
      ]
    },
    {
      "role": "user",
      "parts": [
        {"functionResponse": {"name": "generate_config", "response": {"result": "hostname CORE-SW-1A\ninterface Gi0/1\n..."}}}
      ]
    }
  ],
  "tools": [
    {
      "functionDeclarations": [
        {
          "name": "generate_config",
          "description": "Generate Cisco IOS .cfg file for a device",
          "parameters": {
            "type": "object",
            "properties": {
              "device": {"type": "string", "description": "Device name"}
            },
            "required": ["device"]
          }
        }
      ]
    }
  ],
  "generationConfig": {
    "maxOutputTokens": 4096
  }
}
```

### Response (streaming)

```json
{"candidates": [{"content": {"parts": [{"text": "Here's the"}], "role": "model"}, "finishReason": null}]}

{"candidates": [{"content": {"parts": [{"text": " generated config"}], "role": "model"}, "finishReason": null}]}

{"candidates": [{"content": {"parts": [{"functionCall": {"name": "generate_config", "args": {"device": "CORE-SW-1A"}}}], "role": "model"}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 1200, "candidatesTokenCount": 85}}
```

### Response (non-streaming)

```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          {"text": "Here's the generated config."},
          {"functionCall": {"name": "generate_config", "args": {"device": "CORE-SW-1A"}}}
        ],
        "role": "model"
      },
      "finishReason": "STOP"
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 1200,
    "candidatesTokenCount": 85,
    "totalTokenCount": 1285
  }
}
```

---

## Key Differences Summary

### Request Structure

| Field | Anthropic | OpenAI | Gemini |
|-------|-----------|--------|--------|
| System prompt | `system` (top-level string) | `messages[0].role: "system"` | `systemInstruction.parts[].text` |
| Messages | `messages[]` | `messages[]` | `contents[]` |
| User role | `"user"` | `"user"` | `"user"` |
| Assistant role | `"assistant"` | `"assistant"` | `"model"` |
| Text content | `content` (string or blocks) | `content` (string) | `parts[].text` |
| Tool definitions | `tools[].input_schema` | `tools[].function.parameters` | `tools[].functionDeclarations[].parameters` |
| Tool call (in response) | `type: "tool_use"` block | `tool_calls[].function` | `parts[].functionCall` |
| Tool result | `type: "tool_result"` in user msg | `role: "tool"` message | `parts[].functionResponse` in user msg |
| Tool call ID | `id` / `tool_use_id` | `id` / `tool_call_id` | Not used (matched by name) |
| Tool args format | JSON object | JSON string (must parse) | JSON object |
| Max tokens | `max_tokens` | `max_tokens` | `generationConfig.maxOutputTokens` |
| Stream flag | `stream: true` | `stream: true` | URL suffix `:streamGenerateContent` |

### Streaming Format

| Feature | Anthropic | OpenAI | Gemini |
|---------|-----------|--------|--------|
| Protocol | SSE with named events | SSE with `data:` lines | Newline-delimited JSON |
| Text deltas | `content_block_delta` + `text_delta` | `choices[].delta.content` | `candidates[].content.parts[].text` |
| Block boundaries | `content_block_start` / `content_block_stop` | None (implicit) | None (implicit) |
| End signal | `message_stop` event | `data: [DONE]` | Last chunk has `finishReason` |
| Stop reason | `stop_reason` in `message_delta` | `finish_reason` in last chunk | `finishReason` in last chunk |

### How Shroud Handles Each

**OpenClaw path (fetch intercept):**
- Detects API from URL path (`/v1/messages`, `/v1/chat/completions`, `:streamGenerateContent`)
- Parses request body — finds text fields in whichever format
- Obfuscates all message text content before forwarding
- Deobfuscates SSE response by buffering per content block (Anthropic) or per chunk (OpenAI/Gemini)

**APP path (NCG and other agents):**
- Agent calls `sanitize(text)` / `desanitize(text)` — format-agnostic
- Agent is responsible for structuring the API call
- Shroud never sees the raw API request — only the text blobs
- Classification inferred from text content keywords

### NCG Specifics

NCG uses the **Anthropic Python SDK** directly:
```python
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-6",
    system=sanitized_system_prompt,
    messages=sanitized_messages,
    tools=sanitized_tools,
    max_tokens=4096
)
```

The system prompt, messages, and tool definitions are each sanitized separately before being passed to the SDK. The SDK handles the Anthropic JSON format internally.
