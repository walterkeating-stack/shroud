#!/usr/bin/env node
/**
 * Mock LLM Server — OpenAI-compatible chat completions endpoint.
 *
 * Pure Node.js, zero dependencies. Logs every request for assertion checks.
 * Supports streaming (SSE) and non-streaming modes, plus tool_call responses.
 */

import http from "node:http";
import { randomUUID } from "node:crypto";

const requestLog = [];

/**
 * Extract the last user message content from an OpenAI-format request body.
 */
function lastUserContent(body) {
  const msgs = body.messages || [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i].role === "user") {
      return typeof msgs[i].content === "string"
        ? msgs[i].content
        : JSON.stringify(msgs[i].content);
    }
  }
  return "";
}

/**
 * Check if text contains an IP address or hostname pattern, and if the request
 * declares tools. If so, return a tool_call response shape instead of text.
 */
function maybeToolCall(body, userText) {
  if (!body.tools || body.tools.length === 0) return null;

  const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const hostPattern = /\b(?:[a-zA-Z][a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b/;

  const ipMatch = userText.match(ipPattern);
  const hostMatch = userText.match(hostPattern);
  const entity = ipMatch ? ipMatch[0] : hostMatch ? hostMatch[0] : null;

  if (!entity) return null;

  const toolName = body.tools[0].function?.name || "lookup";
  return {
    toolName,
    entity,
    callId: `call_test_${randomUUID().slice(0, 8)}`,
  };
}

function buildNonStreamingResponse(content, model) {
  return {
    id: `chatcmpl-${randomUUID().slice(0, 12)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model || "mock-model",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: content.length,
      completion_tokens: content.length,
      total_tokens: content.length * 2,
    },
  };
}

function buildNonStreamingToolCall(tc, model) {
  return {
    id: `chatcmpl-${randomUUID().slice(0, 12)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model || "mock-model",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: tc.callId,
              type: "function",
              function: {
                name: tc.toolName,
                arguments: JSON.stringify({ query: tc.entity }),
              },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
  };
}

/**
 * Write SSE streaming response for text content.
 */
function streamTextResponse(res, content, model) {
  const id = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = Math.floor(Date.now() / 1000);
  const words = content.split(/(\s+)/);

  // Group into chunks of ~3 words (keeping whitespace attached)
  const chunks = [];
  let buf = "";
  let wordCount = 0;
  for (const w of words) {
    buf += w;
    if (w.trim()) wordCount++;
    if (wordCount >= 3) {
      chunks.push(buf);
      buf = "";
      wordCount = 0;
    }
  }
  if (buf) chunks.push(buf);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  // Role chunk
  const roleChunk = {
    id,
    object: "chat.completion.chunk",
    created,
    model: model || "mock-model",
    choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
  };
  res.write(`data: ${JSON.stringify(roleChunk)}\n\n`);

  for (const chunk of chunks) {
    const obj = {
      id,
      object: "chat.completion.chunk",
      created,
      model: model || "mock-model",
      choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
    };
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  }

  // Final chunk with stop + usage
  const stopChunk = {
    id,
    object: "chat.completion.chunk",
    created,
    model: model || "mock-model",
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    usage: {
      prompt_tokens: content.length,
      completion_tokens: content.length,
      total_tokens: content.length * 2,
    },
  };
  res.write(`data: ${JSON.stringify(stopChunk)}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}

/**
 * Write SSE streaming response for a tool call.
 */
function streamToolCallResponse(res, tc, model) {
  const id = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = Math.floor(Date.now() / 1000);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  const chunk = {
    id,
    object: "chat.completion.chunk",
    created,
    model: model || "mock-model",
    choices: [
      {
        index: 0,
        delta: {
          tool_calls: [
            {
              index: 0,
              id: tc.callId,
              type: "function",
              function: {
                name: tc.toolName,
                arguments: JSON.stringify({ query: tc.entity }),
              },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
  };
  res.write(`data: ${JSON.stringify(chunk)}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost`);

  // Health check
  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, requests: requestLog.length }));
    return;
  }

  // Request log retrieval
  if (req.method === "GET" && url.pathname === "/requests") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(requestLog));
    return;
  }

  // Clear request log
  if (req.method === "DELETE" && url.pathname === "/requests") {
    requestLog.length = 0;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // Chat completions
  if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
    const raw = await readBody(req);
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    requestLog.push(body);

    const userText = lastUserContent(body);
    const noTools = body._no_tool_calls ||
      url.searchParams.has("no_tools") ||
      (req.headers["x-no-tool-calls"] === "1") ||
      (process.env.MOCK_LLM_NO_TOOLS === "1");
    const tc = noTools ? null : maybeToolCall(body, userText);
    const responseText = `Based on my analysis, ${userText}. This information has been verified.`;
    const streaming = body.stream !== false;
    const model = body.model || "mock-model";

    if (tc) {
      if (streaming) {
        streamToolCallResponse(res, tc, model);
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(buildNonStreamingToolCall(tc, model)));
      }
    } else if (streaming) {
      streamTextResponse(res, responseText, model);
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(buildNonStreamingResponse(responseText, model)));
    }
    return;
  }

  // 404
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 0;
server.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  const out = JSON.stringify({ port: addr.port, ready: true });
  process.stdout.write(out + "\n");
});

// Graceful shutdown
process.on("SIGTERM", () => server.close());
process.on("SIGINT", () => server.close());
