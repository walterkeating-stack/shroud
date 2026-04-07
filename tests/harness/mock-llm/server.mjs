#!/usr/bin/env node
/**
 * Mock LLM Server — multi-provider chat completions endpoint.
 *
 * Implements realistic SSE streaming for:
 *   - OpenAI  /v1/chat/completions  (chat.completion.chunk with delta.content)
 *   - Anthropic  /v1/messages  (content_block_delta/content_block_stop with named events)
 *   - Google Gemini  /v1beta/models/*  (GenerateContentResponse chunks)
 *
 * Pure Node.js, zero dependencies. Logs every request for assertion checks.
 * Supports streaming and non-streaming modes, echo mode, and tool calls.
 */

import http from "node:http";
import { randomUUID } from "node:crypto";

const requestLog = [];

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function isEchoMode(body, url, req) {
  return body._echo ||
    url.searchParams.has("echo") ||
    (req.headers["x-mock-echo"] === "1") ||
    (process.env.MOCK_LLM_ECHO === "1");
}

function isNoTools(body, url, req) {
  return body._no_tool_calls ||
    url.searchParams.has("no_tools") ||
    (req.headers["x-no-tool-calls"] === "1") ||
    (process.env.MOCK_LLM_NO_TOOLS === "1");
}

function tokenize(text, wordsPerChunk = 3) {
  const words = text.split(/(\s+)/);
  const chunks = [];
  let buf = "";
  let wordCount = 0;
  for (const w of words) {
    buf += w;
    if (w.trim()) wordCount++;
    if (wordCount >= wordsPerChunk) {
      chunks.push(buf);
      buf = "";
      wordCount = 0;
    }
  }
  if (buf) chunks.push(buf);
  return chunks;
}

function maybeToolCall(body, userText, toolsKey = "tools") {
  const tools = body[toolsKey];
  if (!tools || tools.length === 0) return null;
  const ipMatch = userText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const hostMatch = userText.match(/\b(?:[a-zA-Z][a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b/);
  const entity = ipMatch ? ipMatch[0] : hostMatch ? hostMatch[0] : null;
  if (!entity) return null;
  const toolName = (tools[0].function?.name) || (tools[0].name) || "lookup";
  return { toolName, entity, callId: `call_test_${randomUUID().slice(0, 8)}` };
}

function lastUserContentOpenAI(body) {
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

function openaiNonStreaming(content, model) {
  return {
    id: `chatcmpl-${randomUUID().slice(0, 12)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model || "mock-model",
    choices: [{
      index: 0,
      message: { role: "assistant", content },
      finish_reason: "stop",
    }],
    usage: {
      prompt_tokens: content.length,
      completion_tokens: content.length,
      total_tokens: content.length * 2,
      prompt_tokens_details: { cached_tokens: Math.ceil(content.length * 0.7) },
    },
  };
}

function openaiNonStreamingToolCall(tc, model) {
  return {
    id: `chatcmpl-${randomUUID().slice(0, 12)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model || "mock-model",
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: tc.callId, type: "function",
          function: { name: tc.toolName, arguments: JSON.stringify({ query: tc.entity }) },
        }],
      },
      finish_reason: "tool_calls",
    }],
    usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
  };
}

function openaiStreamText(res, content, model) {
  const id = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = Math.floor(Date.now() / 1000);
  const m = model || "mock-model";
  const chunks = tokenize(content);

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  res.write(`data: ${JSON.stringify({
    id, object: "chat.completion.chunk", created, model: m,
    choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
  })}\n\n`);

  for (const chunk of chunks) {
    res.write(`data: ${JSON.stringify({
      id, object: "chat.completion.chunk", created, model: m,
      choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
    })}\n\n`);
  }

  res.write(`data: ${JSON.stringify({
    id, object: "chat.completion.chunk", created, model: m,
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    usage: { prompt_tokens: content.length, completion_tokens: content.length, total_tokens: content.length * 2 },
  })}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}

function openaiStreamToolCall(res, tc, model) {
  const id = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = Math.floor(Date.now() / 1000);
  const m = model || "mock-model";

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  res.write(`data: ${JSON.stringify({
    id, object: "chat.completion.chunk", created, model: m,
    choices: [{
      index: 0,
      delta: { tool_calls: [{ index: 0, id: tc.callId, type: "function", function: { name: tc.toolName, arguments: JSON.stringify({ query: tc.entity }) } }] },
      finish_reason: "tool_calls",
    }],
  })}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}

function handleOpenAI(req, res, url, body) {
  requestLog.push(body);
  const userText = lastUserContentOpenAI(body);
  const tc = isNoTools(body, url, req) ? null : maybeToolCall(body, userText);
  const echoMode = isEchoMode(body, url, req);
  const responseText = echoMode ? userText : `Based on my analysis, ${userText}. This information has been verified.`;
  const streaming = body.stream !== false;
  const model = body.model || "mock-model";

  if (tc) {
    if (streaming) openaiStreamToolCall(res, tc, model);
    else { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(openaiNonStreamingToolCall(tc, model))); }
  } else if (streaming) {
    openaiStreamText(res, responseText, model);
  } else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(openaiNonStreaming(responseText, model)));
  }
}

function lastUserContentAnthropic(body) {
  const msgs = body.messages || [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i].role === "user") {
      const c = msgs[i].content;
      if (typeof c === "string") return c;
      if (Array.isArray(c)) {
        const textBlock = c.find((b) => b.type === "text");
        return textBlock ? textBlock.text : JSON.stringify(c);
      }
      return JSON.stringify(c);
    }
  }
  return "";
}

function anthropicNonStreaming(content, model) {
  return {
    id: `msg_${randomUUID().slice(0, 24)}`,
    type: "message",
    role: "assistant",
    model: model || "claude-3-haiku-20240307",
    stop_reason: "end_turn",
    stop_sequence: null,
    content: [{ type: "text", text: content }],
    usage: {
      input_tokens: Math.ceil(content.length / 4),
      output_tokens: Math.ceil(content.length / 4),
      cache_creation_input_tokens: Math.ceil(content.length / 8),
      cache_read_input_tokens: Math.ceil(content.length / 4 * 0.7),
    },
  };
}

function anthropicNonStreamingToolCall(tc, model) {
  return {
    id: `msg_${randomUUID().slice(0, 24)}`,
    type: "message",
    role: "assistant",
    model: model || "claude-3-haiku-20240307",
    stop_reason: "tool_use",
    stop_sequence: null,
    content: [{
      type: "tool_use",
      id: tc.callId,
      name: tc.toolName,
      input: { query: tc.entity },
    }],
    usage: { input_tokens: 10, output_tokens: 10 },
  };
}

function sseEvent(res, eventName, data) {
  res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
}

function anthropicStreamText(res, content, model) {
  const m = model || "claude-3-haiku-20240307";
  const msgId = `msg_${randomUUID().slice(0, 24)}`;
  const inputTokens = Math.ceil(content.length / 4);
  const chunks = tokenize(content, 2);

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });

  sseEvent(res, "message_start", {
    type: "message_start",
    message: {
      id: msgId, type: "message", role: "assistant", model: m,
      stop_reason: null, stop_sequence: null,
      usage: {
        input_tokens: inputTokens,
        output_tokens: 1,
        cache_creation_input_tokens: Math.ceil(inputTokens * 0.15),
        cache_read_input_tokens: Math.ceil(inputTokens * 0.7),
      },
      content: [],
    },
  });

  sseEvent(res, "content_block_start", {
    type: "content_block_start", index: 0,
    content_block: { type: "text", text: "" },
  });
  sseEvent(res, "ping", { type: "ping" });

  for (const chunk of chunks) {
    sseEvent(res, "content_block_delta", {
      type: "content_block_delta", index: 0,
      delta: { type: "text_delta", text: chunk },
    });
  }

  sseEvent(res, "content_block_stop", { type: "content_block_stop", index: 0 });
  sseEvent(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: Math.ceil(content.length / 4) },
  });
  sseEvent(res, "message_stop", { type: "message_stop" });
  res.end();
}

function anthropicStreamToolCall(res, tc, model) {
  const m = model || "claude-3-haiku-20240307";
  const msgId = `msg_${randomUUID().slice(0, 24)}`;

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });

  sseEvent(res, "message_start", {
    type: "message_start",
    message: {
      id: msgId, type: "message", role: "assistant", model: m,
      stop_reason: null, stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 1 },
      content: [],
    },
  });

  sseEvent(res, "content_block_start", {
    type: "content_block_start", index: 0,
    content_block: { type: "tool_use", id: tc.callId, name: tc.toolName, input: {} },
  });

  const inputJson = JSON.stringify({ query: tc.entity });
  const mid = Math.floor(inputJson.length / 2);
  sseEvent(res, "content_block_delta", {
    type: "content_block_delta", index: 0,
    delta: { type: "input_json_delta", partial_json: inputJson.slice(0, mid) },
  });
  sseEvent(res, "content_block_delta", {
    type: "content_block_delta", index: 0,
    delta: { type: "input_json_delta", partial_json: inputJson.slice(mid) },
  });

  sseEvent(res, "content_block_stop", { type: "content_block_stop", index: 0 });
  sseEvent(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: "tool_use", stop_sequence: null },
    usage: { output_tokens: 10 },
  });
  sseEvent(res, "message_stop", { type: "message_stop" });
  res.end();
}

function handleAnthropic(req, res, url, body) {
  requestLog.push(body);
  const userText = lastUserContentAnthropic(body);
  const tc = isNoTools(body, url, req) ? null : maybeToolCall(body, userText, "tools");
  const echoMode = isEchoMode(body, url, req);
  const responseText = echoMode ? userText : `Based on my analysis, ${userText}. This information has been verified.`;
  const streaming = body.stream === true;
  const model = body.model || "claude-3-haiku-20240307";

  if (tc) {
    if (streaming) anthropicStreamToolCall(res, tc, model);
    else { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(anthropicNonStreamingToolCall(tc, model))); }
  } else if (streaming) {
    anthropicStreamText(res, responseText, model);
  } else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(anthropicNonStreaming(responseText, model)));
  }
}

function lastUserContentGemini(body) {
  const contents = body.contents || [];
  for (let i = contents.length - 1; i >= 0; i--) {
    if (contents[i].role === "user") {
      const parts = contents[i].parts || [];
      const textPart = parts.find((p) => p.text != null);
      return textPart ? textPart.text : JSON.stringify(parts);
    }
  }
  return "";
}

function geminiNonStreaming(content, model) {
  return {
    candidates: [{
      content: { parts: [{ text: content }], role: "model" },
      finishReason: "STOP",
      index: 0,
      safetyRatings: [
        { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", probability: "NEGLIGIBLE" },
        { category: "HARM_CATEGORY_HATE_SPEECH", probability: "NEGLIGIBLE" },
        { category: "HARM_CATEGORY_HARASSMENT", probability: "NEGLIGIBLE" },
        { category: "HARM_CATEGORY_DANGEROUS_CONTENT", probability: "NEGLIGIBLE" },
      ],
    }],
    usageMetadata: {
      promptTokenCount: Math.ceil(content.length / 4),
      candidatesTokenCount: Math.ceil(content.length / 4),
      totalTokenCount: Math.ceil(content.length / 2),
    },
    modelVersion: model || "gemini-1.5-flash",
  };
}

function geminiStreamText(res, content, model) {
  const m = model || "gemini-1.5-flash";
  const chunks = tokenize(content, 6);

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });

  for (let i = 0; i < chunks.length; i++) {
    const isLast = i === chunks.length - 1;
    const candidate = {
      content: { parts: [{ text: chunks[i] }], role: "model" },
      index: 0,
    };
    if (isLast) {
      candidate.finishReason = "STOP";
      candidate.safetyRatings = [
        { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", probability: "NEGLIGIBLE" },
        { category: "HARM_CATEGORY_HATE_SPEECH", probability: "NEGLIGIBLE" },
      ];
    }
    const response = { candidates: [candidate] };
    if (isLast) {
      response.usageMetadata = {
        promptTokenCount: Math.ceil(content.length / 4),
        candidatesTokenCount: Math.ceil(content.length / 4),
        totalTokenCount: Math.ceil(content.length / 2),
      };
      response.modelVersion = m;
    }
    res.write(`data: ${JSON.stringify(response)}\n\n`);
  }
  res.end();
}

function handleGemini(req, res, url, body) {
  requestLog.push(body);
  const userText = lastUserContentGemini(body);
  const echoMode = isEchoMode(body, url, req);
  const responseText = echoMode ? userText : `Based on my analysis, ${userText}. This information has been verified.`;
  const model = body.model || "gemini-1.5-flash";
  const isStream = url.pathname.includes(":streamGenerateContent");

  if (isStream) {
    geminiStreamText(res, responseText, model);
  } else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(geminiNonStreaming(responseText, model)));
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, requests: requestLog.length, providers: ["openai", "anthropic", "gemini"] }));
    return;
  }

  if (req.method === "GET" && url.pathname === "/requests") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(requestLog));
    return;
  }

  if (req.method === "DELETE" && url.pathname === "/requests") {
    requestLog.length = 0;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (req.method === "POST") {
    const raw = await readBody(req);
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    if (url.pathname === "/v1/chat/completions" || url.pathname === "/chat/completions") {
      handleOpenAI(req, res, url, body);
      return;
    }
    if (url.pathname === "/v1/messages" || url.pathname === "/messages") {
      handleAnthropic(req, res, url, body);
      return;
    }
    if (url.pathname.includes(":streamGenerateContent") || url.pathname.includes(":generateContent")) {
      handleGemini(req, res, url, body);
      return;
    }
    if (url.pathname.startsWith("/v1beta/models/") || url.pathname.startsWith("/v1/models/")) {
      handleGemini(req, res, url, body);
      return;
    }
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found", path: url.pathname }));
});

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 0;
server.listen(port, "127.0.0.1", () => {
  const addr = server.address();
  process.stdout.write(JSON.stringify({ port: addr.port, ready: true }) + "\n");
});

process.on("SIGTERM", () => server.close());
process.on("SIGINT", () => server.close());
