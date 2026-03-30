/**
 * Real-time security dashboard — lightweight HTTP endpoint.
 *
 * Serves JSON snapshots of all agent sessions, security events,
 * profiling baselines, and injection detection stats. Designed
 * for Grafana, custom UIs, or direct curl consumption.
 *
 * Zero external dependencies — uses Node's built-in http module.
 *
 * Endpoints:
 *   GET /health                    — liveness check
 *   GET /api/overview              — high-level security summary
 *   GET /api/agents                — all agent sessions with profiling status
 *   GET /api/agents/:buildId       — single agent detail
 *   GET /api/events                — recent security events (last 100)
 *   GET /api/events/stream         — SSE stream of security events (real-time)
 *   GET /api/profiling             — profiling baselines for all agents
 *   GET /api/profiling/:buildId    — single agent baseline detail
 *   GET /api/stats                 — obfuscation + security stats combined
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import type { SecurityEventBus, SecurityEvent } from "./security-event.js";
import type { AgentSessionTracker } from "./agent-session.js";
import type { BaselineStore } from "./profiler-store.js";
import type { Obfuscator } from "./obfuscator.js";
import type { BehaviouralProfiler } from "./profiler.js";
import type { ShroudConfig } from "./types.js";
import type { PolicyEngine } from "./policy.js";

export interface DashboardDeps {
  securityBus: SecurityEventBus | null;
  agentTracker: AgentSessionTracker;
  baselineStore: BaselineStore | null;
  obfuscator: Obfuscator;
  profiler: BehaviouralProfiler | null;
  config: ShroudConfig;
  policyEngine: PolicyEngine | null;
}

/**
 * Start the dashboard HTTP server.
 * Returns the server instance for cleanup.
 */
export function startDashboard(
  port: number,
  deps: DashboardDeps,
): ReturnType<typeof createServer> {
  const sseClients: Set<ServerResponse> = new Set();

  // Subscribe to security events for real-time SSE streaming
  if (deps.securityBus) {
    deps.securityBus.onEvent((event: SecurityEvent) => {
      const data = JSON.stringify(event);
      for (const client of sseClients) {
        try {
          client.write(`data: ${data}\n\n`);
        } catch {
          sseClients.delete(client);
        }
      }
    });
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url || "/";
    const method = req.method || "GET";

    // CORS headers for dashboard UIs
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Policy endpoints accept POST/PUT
    if ((method === "POST" || method === "PUT") && url?.startsWith("/api/policy")) {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        try {
          handlePolicyWrite(res, deps, url!, method, body);
        } catch (err: any) {
          json(res, 500, { error: err.message });
        }
      });
      return;
    }

    if (method !== "GET") {
      json(res, 405, { error: "Method not allowed" });
      return;
    }

    try {
      // Route dispatch
      if (url === "/" || url === "/dashboard") {
        serveDashboardHtml(res);
      }
      else if (url === "/health") {
        json(res, 200, { status: "ok", timestamp: new Date().toISOString() });
      }
      else if (url === "/api/overview") {
        handleOverview(res, deps);
      }
      else if (url === "/api/agents") {
        handleAgents(res, deps);
      }
      else if (url?.startsWith("/api/agents/")) {
        const buildId = url.slice("/api/agents/".length);
        handleAgentDetail(res, deps, buildId);
      }
      else if (url?.startsWith("/api/events?") || url === "/api/events") {
        handleEvents(res, deps, url);
      }
      else if (url === "/api/events/stream") {
        handleEventStream(req, res, sseClients);
      }
      else if (url === "/api/profiling") {
        handleProfiling(res, deps);
      }
      else if (url?.startsWith("/api/profiling/")) {
        const buildId = url.slice("/api/profiling/".length);
        handleProfilingDetail(res, deps, buildId);
      }
      else if (url === "/api/stats") {
        handleStats(res, deps);
      }
      else if (url === "/api/policy") {
        handlePolicyRead(res, deps);
      }
      else if (url === "/api/policy/history") {
        handlePolicyHistory(res, deps);
      }
      else {
        json(res, 404, { error: "Not found", endpoints: [
          "/health", "/api/overview", "/api/agents", "/api/agents/:buildId",
          "/api/events", "/api/events/stream", "/api/profiling",
          "/api/profiling/:buildId", "/api/stats",
        ]});
      }
    } catch (err: any) {
      json(res, 500, { error: err.message || "Internal server error" });
    }
  });

  const bindAddr = process.env.SHROUD_DASHBOARD_BIND || "0.0.0.0";
  server.listen(port, bindAddr, () => {
    // Default: 0.0.0.0 (all interfaces including Tailscale)
    // Set SHROUD_DASHBOARD_BIND=127.0.0.1 to restrict to localhost
  });

  return server;
}

// ── Route handlers ──────────────────────────────────

function handleOverview(res: ServerResponse, deps: DashboardDeps) {
  const agents = deps.agentTracker.getAllSessions();
  const secStats = deps.securityBus?.getStats();
  const profiler = deps.profiler;

  json(res, 200, {
    timestamp: new Date().toISOString(),
    security: {
      injectionDetection: deps.config.injectionDetection,
      profilingEnabled: deps.config.profilingEnabled,
      profilingMode: deps.config.profilingMode,
      totalEvents: secStats?.totalEvents ?? 0,
      blockedCount: secStats?.blockedCount ?? 0,
      flaggedCount: secStats?.flaggedCount ?? 0,
    },
    agents: {
      total: agents.length,
      totalLlmCalls: agents.reduce((sum, a) => sum + a.llmCallCount, 0),
      totalSecurityEvents: agents.reduce((sum, a) => sum + a.securityEventCount, 0),
      withBaseline: deps.baselineStore
        ? agents.filter(a => deps.baselineStore!.exists(a.agentBuildId)).length
        : 0,
    },
    obfuscation: {
      storeMappings: (deps.obfuscator.getStats() as any).storeMappings,
      totalObfuscated: (deps.obfuscator.getStats() as any).totalEntitiesObfuscated,
      totalDeobfuscated: (deps.obfuscator.getStats() as any).totalReplacementsDeobfuscated,
    },
    anomalyAlerts: profiler ? profiler.getAlerts().length : 0,
  });
}

function handleAgents(res: ServerResponse, deps: DashboardDeps) {
  const agents = deps.agentTracker.getAllSessions();
  const enriched = agents.map(agent => {
    const baseline = deps.baselineStore?.load(agent.agentBuildId);
    return {
      ...agent,
      profiling: baseline ? {
        maturity: baseline.maturity,
        sessionCount: baseline.sessionCount,
        learningProgress: Math.min(100, Math.round(
          (baseline.sessionCount / deps.config.profilingMinBaseline) * 100,
        )),
        sessionsUntilActive: Math.max(0, deps.config.profilingMinBaseline - baseline.sessionCount),
        knownTools: baseline.toolProfile,
        knownCategories: baseline.categoryProfile,
        lastUpdated: new Date(baseline.lastUpdated).toISOString(),
      } : {
        maturity: "none",
        sessionCount: 0,
        learningProgress: 0,
        sessionsUntilActive: deps.config.profilingMinBaseline,
      },
    };
  });

  json(res, 200, { agents: enriched });
}

function handleAgentDetail(res: ServerResponse, deps: DashboardDeps, buildId: string) {
  const agent = deps.agentTracker.getSession(buildId);
  if (!agent) {
    json(res, 404, { error: `Agent ${buildId} not found` });
    return;
  }

  const baseline = deps.baselineStore?.load(buildId);
  const events = deps.securityBus?.getEvents().filter(e => e.agentBuildId === buildId) ?? [];

  json(res, 200, {
    agent,
    baseline: baseline ? {
      maturity: baseline.maturity,
      sessionCount: baseline.sessionCount,
      features: baseline.features,
      toolProfile: baseline.toolProfile,
      categoryProfile: baseline.categoryProfile,
      lastUpdated: new Date(baseline.lastUpdated).toISOString(),
    } : null,
    recentEvents: events.slice(-20),
  });
}

function handleEvents(res: ServerResponse, deps: DashboardDeps, urlStr = "/api/events") {
  let events = [...(deps.securityBus?.getEvents() ?? [])];
  const stats = deps.securityBus?.getStats();

  // Parse query params for filtering
  const qIdx = urlStr.indexOf("?");
  if (qIdx >= 0) {
    const params = new URLSearchParams(urlStr.slice(qIdx));

    // Filter by agent
    const agent = params.get("agent");
    if (agent) events = events.filter(e => e.agentBuildId === agent || e.agentLabel?.includes(agent));

    // Filter by threat class
    const threat = params.get("threat");
    if (threat) events = events.filter(e => e.threatClass === threat);

    // Filter by severity
    const severity = params.get("severity");
    if (severity) events = events.filter(e => e.severity === severity);

    // Filter by event type
    const type = params.get("type");
    if (type) events = events.filter(e => e.eventType === type);

    // Filter by direction
    const direction = params.get("direction");
    if (direction) events = events.filter(e => e.direction === direction);

    // Filter by time range (unix ms)
    const since = params.get("since");
    if (since) events = events.filter(e => e.timestamp >= parseInt(since, 10));
    const until = params.get("until");
    if (until) events = events.filter(e => e.timestamp <= parseInt(until, 10));

    // Text search in matchedText and description
    const q = params.get("q");
    if (q) {
      const lower = q.toLowerCase();
      events = events.filter(e =>
        e.matchedText.toLowerCase().includes(lower) ||
        e.description.toLowerCase().includes(lower) ||
        e.signatureId.toLowerCase().includes(lower),
      );
    }

    // Limit
    const limit = parseInt(params.get("limit") || "100", 10);
    events = events.slice(-limit);
  } else {
    events = events.slice(-100);
  }

  json(res, 200, { stats, count: events.length, events });
}

function handleEventStream(req: IncomingMessage, res: ServerResponse, clients: Set<ServerResponse>) {
  // SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });
  res.write("data: {\"type\":\"connected\"}\n\n");

  clients.add(res);

  req.on("close", () => {
    clients.delete(res);
  });
}

function handleProfiling(res: ServerResponse, deps: DashboardDeps) {
  if (!deps.config.profilingEnabled) {
    json(res, 200, { enabled: false });
    return;
  }

  const agents = deps.agentTracker.getAllSessions();
  const profiles = agents.map(agent => {
    const baseline = deps.baselineStore?.load(agent.agentBuildId);
    return {
      agentBuildId: agent.agentBuildId,
      agentLabel: agent.agentLabel,
      baseline: baseline ? {
        maturity: baseline.maturity,
        sessionCount: baseline.sessionCount,
        featureCount: Object.keys(baseline.features).length,
        toolProfile: baseline.toolProfile,
        categoryProfile: baseline.categoryProfile,
      } : null,
    };
  });

  json(res, 200, {
    enabled: true,
    mode: deps.config.profilingMode,
    sigma: deps.config.profilingSigma,
    minBaseline: deps.config.profilingMinBaseline,
    profiles,
  });
}

function handleProfilingDetail(res: ServerResponse, deps: DashboardDeps, buildId: string) {
  const baseline = deps.baselineStore?.load(buildId);
  if (!baseline) {
    json(res, 404, { error: `No baseline for agent ${buildId}` });
    return;
  }

  json(res, 200, { baseline });
}

function handleStats(res: ServerResponse, deps: DashboardDeps) {
  json(res, 200, {
    obfuscation: deps.obfuscator.getStats(),
    security: deps.securityBus?.getStats() ?? null,
    agentCount: deps.agentTracker.getAllSessions().length,
  });
}

// ── Policy handlers ──────────────────────────────────

function handlePolicyRead(res: ServerResponse, deps: DashboardDeps) {
  if (!deps.policyEngine) {
    json(res, 200, { enabled: false, message: "Policy engine not initialized" });
    return;
  }
  json(res, 200, {
    version: deps.policyEngine.getCurrentVersion(),
    policy: deps.policyEngine.getFullPolicy(),
  });
}

function handlePolicyHistory(res: ServerResponse, deps: DashboardDeps) {
  if (!deps.policyEngine) {
    json(res, 200, { enabled: false });
    return;
  }
  const history = deps.policyEngine.getHistory();
  json(res, 200, {
    current: history.current,
    commits: history.commits.map(c => ({
      version: c.version,
      timestamp: c.timestamp,
      description: c.description,
    })),
  });
}

function handlePolicyWrite(
  res: ServerResponse,
  deps: DashboardDeps,
  url: string,
  method: string,
  body: string,
) {
  if (!deps.policyEngine) {
    json(res, 400, { error: "Policy engine not initialized" });
    return;
  }

  const parsed = JSON.parse(body);

  // POST /api/policy/commit — commit current policy with description
  if (url === "/api/policy/commit") {
    const description = parsed.description || "Manual commit";
    const commit = deps.policyEngine.commit(description);
    json(res, 200, { committed: true, version: commit.version, timestamp: commit.timestamp });
    return;
  }

  // POST /api/policy/rollback — rollback to a specific version
  if (url === "/api/policy/rollback") {
    const version = parsed.version;
    if (typeof version !== "number") {
      json(res, 400, { error: "version (number) required" });
      return;
    }
    const commit = deps.policyEngine.rollback(version);
    if (!commit) {
      json(res, 404, { error: `Version ${version} not found` });
      return;
    }
    json(res, 200, { rolledBack: true, version: commit.version, timestamp: commit.timestamp });
    return;
  }

  // PUT /api/policy/default — update default policy
  if (url === "/api/policy/default") {
    deps.policyEngine.setDefaultPolicy(parsed);
    json(res, 200, { updated: true, scope: "default" });
    return;
  }

  // PUT /api/policy/agent/:buildId — update agent-specific policy
  if (url.startsWith("/api/policy/agent/")) {
    const buildId = url.slice("/api/policy/agent/".length);
    deps.policyEngine.setAgentPolicy(buildId, parsed);
    json(res, 200, { updated: true, scope: "agent", buildId });
    return;
  }

  json(res, 404, { error: "Unknown policy endpoint" });
}

// ── Helpers ──────────────────────────────────────────

function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data, null, 2));
}

function serveDashboardHtml(res: ServerResponse) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(DASHBOARD_HTML);
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shroud Security Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; }
  .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 18px; color: #58a6ff; }
  .header .badge { background: #238636; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
  .header .badge.warn { background: #d29922; }
  .header .badge.danger { background: #da3633; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; padding: 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .card h2 { font-size: 14px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .stat { font-size: 32px; font-weight: bold; color: #58a6ff; }
  .stat.green { color: #3fb950; }
  .stat.red { color: #f85149; }
  .stat.yellow { color: #d29922; }
  .stat-label { font-size: 12px; color: #8b949e; margin-top: 4px; }
  .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #21262d; }
  .row:last-child { border-bottom: none; }
  .row .label { color: #8b949e; }
  .row .value { color: #c9d1d9; font-weight: 500; }
  .agent-card { margin-bottom: 8px; padding: 12px; background: #0d1117; border-radius: 6px; border-left: 3px solid #30363d; }
  .agent-card.mature { border-left-color: #3fb950; }
  .agent-card.reliable { border-left-color: #58a6ff; }
  .agent-card.learning { border-left-color: #d29922; }
  .agent-card.none { border-left-color: #484f58; }
  .agent-name { font-weight: 600; color: #c9d1d9; font-size: 13px; margin-bottom: 4px; }
  .agent-meta { font-size: 11px; color: #8b949e; }
  .progress { height: 4px; background: #21262d; border-radius: 2px; margin-top: 6px; }
  .progress-bar { height: 100%; border-radius: 2px; background: #58a6ff; transition: width 0.5s; }
  .events-list { max-height: 400px; overflow-y: auto; }
  .event { padding: 8px; margin-bottom: 4px; background: #0d1117; border-radius: 4px; font-size: 12px; border-left: 3px solid #30363d; }
  .event.high { border-left-color: #f85149; }
  .event.medium { border-left-color: #d29922; }
  .event.low { border-left-color: #3fb950; }
  .event .sig { color: #58a6ff; font-weight: 600; }
  .event .agent { color: #8b949e; }
  .event .time { color: #484f58; font-size: 10px; float: right; }
  .event .match { color: #c9d1d9; margin-top: 4px; font-family: monospace; font-size: 11px; }
  .threat-bar { display: flex; gap: 4px; margin-top: 8px; }
  .threat-bar .bar { flex: 1; height: 24px; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 600; }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; display: inline-block; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .refresh { color: #484f58; font-size: 11px; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid #30363d; padding: 0 24px; background: #161b22; }
  .tab { padding: 10px 20px; cursor: pointer; color: #8b949e; border-bottom: 2px solid transparent; font-size: 13px; }
  .tab:hover { color: #c9d1d9; }
  .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  .policy-section { padding: 24px; }
  .rule-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .rule-card h3 { color: #58a6ff; font-size: 14px; margin-bottom: 8px; }
  .input-group { margin-bottom: 12px; }
  .input-group label { display: block; color: #8b949e; font-size: 12px; margin-bottom: 4px; }
  .input-group select, .input-group input { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 10px; border-radius: 4px; font-size: 13px; width: 100%; }
  .input-group select:focus, .input-group input:focus { border-color: #58a6ff; outline: none; }
  .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; }
  .btn-primary { background: #238636; color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-danger { background: #da3633; color: #fff; }
  .btn-danger:hover { background: #f85149; }
  .btn-secondary { background: #30363d; color: #c9d1d9; }
  .btn-secondary:hover { background: #484f58; }
  .btn-group { display: flex; gap: 8px; margin-top: 12px; }
  .history-item { padding: 8px 12px; background: #0d1117; border-radius: 4px; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center; font-size: 12px; }
  .history-item .ver { color: #58a6ff; font-weight: 600; }
  .toast { position: fixed; bottom: 24px; right: 24px; background: #238636; color: #fff; padding: 12px 20px; border-radius: 8px; font-size: 13px; display: none; z-index: 100; }
  .toast.error { background: #da3633; }
</style>
</head>
<body>
<div class="header">
  <h1>Shroud Security Dashboard</h1>
  <span class="live-dot"></span>
  <span class="refresh" id="lastUpdate">Loading...</span>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('overview')">Overview</div>
  <div class="tab" onclick="switchTab('rules')">Firewall Rules</div>
</div>
<div class="grid" id="content">
  <div class="card"><h2>Loading...</h2></div>
</div>
<div id="rulesContent" style="display:none"></div>
<div class="toast" id="toast"></div>

<script>
const BASE = location.origin;
let eventSource = null;

async function fetchJson(path) {
  const r = await fetch(BASE + path);
  return r.json();
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  return Math.floor(s/3600) + 'h ago';
}

function truncate(s, n) { return s.length > n ? s.slice(0, n) + '...' : s; }

async function refresh() {
  try {
    const [overview, agents, events] = await Promise.all([
      fetchJson('/api/overview'),
      fetchJson('/api/agents'),
      fetchJson('/api/events?limit=30'),
    ]);

    const sec = overview.security;
    const ag = overview.agents;
    const obf = overview.obfuscation;

    let html = '';

    // Overview cards
    html += '<div class="card"><h2>Security Events</h2>';
    html += '<div class="stat ' + (sec.totalEvents > 0 ? 'yellow' : 'green') + '">' + sec.totalEvents + '</div>';
    html += '<div class="stat-label">Total events detected</div>';
    html += '<div class="row"><span class="label">Flagged</span><span class="value">' + sec.flaggedCount + '</span></div>';
    html += '<div class="row"><span class="label">Blocked</span><span class="value" style="color:#f85149">' + sec.blockedCount + '</span></div>';
    html += '<div class="row"><span class="label">Mode</span><span class="value">' + sec.injectionDetection + '</span></div>';
    html += '</div>';

    html += '<div class="card"><h2>Agents</h2>';
    html += '<div class="stat">' + ag.total + '</div>';
    html += '<div class="stat-label">Active agents tracked</div>';
    html += '<div class="row"><span class="label">LLM Calls</span><span class="value">' + ag.totalLlmCalls + '</span></div>';
    html += '<div class="row"><span class="label">With Baseline</span><span class="value">' + ag.withBaseline + '/' + ag.total + '</span></div>';
    html += '<div class="row"><span class="label">Profiling</span><span class="value">' + (sec.profilingEnabled ? sec.profilingMode : 'off') + '</span></div>';
    html += '</div>';

    html += '<div class="card"><h2>Obfuscation</h2>';
    html += '<div class="stat green">' + obf.totalObfuscated + '</div>';
    html += '<div class="stat-label">Entities obfuscated</div>';
    html += '<div class="row"><span class="label">Store Mappings</span><span class="value">' + obf.storeMappings + '</span></div>';
    html += '<div class="row"><span class="label">Deobfuscated</span><span class="value">' + obf.totalDeobfuscated + '</span></div>';
    html += '</div>';

    // Threat breakdown
    if (events.stats && Object.keys(events.stats.byThreatClass || {}).length > 0) {
      html += '<div class="card"><h2>Threats by Class</h2>';
      const colors = { instruction_override: '#f85149', role_switch: '#da3633', prompt_extraction: '#d29922', conversation_mockup: '#d29922', encoding_bypass: '#58a6ff', data_exfiltration: '#f85149', privilege_escalation: '#da3633', mcp_tool_poisoning: '#bc4c00' };
      for (const [cls, count] of Object.entries(events.stats.byThreatClass)) {
        const pct = Math.round(count / events.stats.totalEvents * 100);
        html += '<div class="row"><span class="label">' + cls.replace(/_/g, ' ') + '</span><span class="value" style="color:' + (colors[cls]||'#c9d1d9') + '">' + count + ' (' + pct + '%)</span></div>';
      }
      html += '</div>';
    }

    // Agent details
    html += '<div class="card" style="grid-column: span 2"><h2>Agent Profiles</h2>';
    for (const a of agents.agents || []) {
      const p = a.profiling || {};
      const maturity = p.maturity || 'none';
      const cats = (p.knownCategories || []).join(', ') || 'none yet';
      const tools = (p.knownTools || []).join(', ') || 'none';
      const sessNeeded = p.sessionsUntilActive || 0;
      const statusText = maturity === 'none' ? 'No baseline - first session'
        : sessNeeded > 0 ? 'Learning - ' + sessNeeded + ' more sessions needed'
        : 'Active - ' + maturity + ' baseline';

      html += '<div class="agent-card ' + maturity + '" onclick="showAgent(\\'' + a.agentBuildId + '\\')" style="cursor:pointer">';
      html += '<div style="display:flex;justify-content:space-between;align-items:center">';
      html += '<div class="agent-name" style="font-size:15px">' + (a.agentLabel || a.agentBuildId) + '</div>';
      html += '<span class="badge' + (a.securityEventCount > 5 ? ' danger' : a.securityEventCount > 0 ? ' warn' : '') + '">' + a.securityEventCount + ' events</span>';
      html += '</div>';
      html += '<table style="width:100%;margin-top:8px;font-size:12px;color:#8b949e"><tr>';
      html += '<td>Build: <span style="color:#58a6ff">' + a.agentBuildId.slice(0,12) + '</span></td>';
      html += '<td>Calls: <span style="color:#c9d1d9">' + a.llmCallCount + '</span></td>';
      html += '<td>Sessions: <span style="color:#c9d1d9">' + (p.sessionCount||0) + '</span></td>';
      html += '<td>Model: <span style="color:#c9d1d9">' + (a.detectedModel || 'unknown') + '</span></td>';
      html += '</tr></table>';
      html += '<table style="width:100%;margin-top:4px;font-size:12px;color:#8b949e"><tr>';
      html += '<td>Entity categories: <span style="color:#d2a8ff">' + cats + '</span></td>';
      html += '<td>Tools: <span style="color:#d2a8ff">' + tools + '</span></td>';
      html += '</tr></table>';
      html += '<div style="display:flex;align-items:center;gap:8px;margin-top:8px">';
      html += '<div class="progress" style="flex:1"><div class="progress-bar" style="width:' + (p.learningProgress||0) + '%;background:' + (maturity==='mature'?'#3fb950':maturity==='reliable'?'#58a6ff':'#d29922') + '"></div></div>';
      html += '<span style="font-size:11px;color:#8b949e">' + statusText + '</span>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // Recent events
    html += '<div class="card" style="grid-column: span 2"><h2>Recent Security Events</h2><div class="events-list">';
    for (const e of (events.events || []).reverse()) {
      html += '<div class="event ' + e.severity + '">';
      html += '<span class="time">' + timeAgo(e.timestamp) + '</span>';
      html += '<span class="sig">' + e.signatureId + '</span> ';
      html += '<span class="agent">' + truncate(e.agentLabel || e.agentBuildId || '', 40) + '</span>';
      html += '<div class="match">' + truncate(e.matchedText || '', 120) + '</div>';
      html += '</div>';
    }
    html += '</div></div>';

    document.getElementById('content').innerHTML = html;
    document.getElementById('lastUpdate').textContent = 'Updated: ' + new Date().toLocaleTimeString();
  } catch (err) {
    document.getElementById('lastUpdate').textContent = 'Error: ' + err.message;
  }
}

// Agent detail view
async function showAgent(buildId) {
  try {
    const data = await fetchJson('/api/agents/' + buildId);
    const a = data.agent;
    const b = data.baseline;
    const evts = data.recentEvents || [];

    let html = '<div class="card" style="grid-column: span 2">';
    html += '<h2 style="cursor:pointer" onclick="refresh()">< Back to Overview</h2>';
    html += '<h2 style="margin-top:12px;color:#58a6ff;font-size:16px">' + (a.agentLabel || a.agentBuildId) + '</h2>';

    html += '<table style="width:100%;margin-top:12px;font-size:13px"><tbody>';
    html += '<tr class="row"><td class="label">Build ID</td><td class="value">' + a.agentBuildId + '</td></tr>';
    html += '<tr class="row"><td class="label">Session ID</td><td class="value">' + a.sessionId + '</td></tr>';
    html += '<tr class="row"><td class="label">LLM Calls</td><td class="value">' + a.llmCallCount + '</td></tr>';
    html += '<tr class="row"><td class="label">Security Events</td><td class="value">' + a.securityEventCount + '</td></tr>';
    html += '<tr class="row"><td class="label">Model</td><td class="value">' + (a.detectedModel || 'unknown') + '</td></tr>';
    html += '<tr class="row"><td class="label">Channel</td><td class="value">' + (a.channelSource || 'none') + '</td></tr>';
    html += '<tr class="row"><td class="label">Started</td><td class="value">' + new Date(a.startedAt).toLocaleString() + '</td></tr>';
    html += '</tbody></table>';
    html += '</div>';

    if (b) {
      html += '<div class="card"><h2>Baseline Profile</h2>';
      html += '<div class="row"><span class="label">Maturity</span><span class="value">' + b.maturity + '</span></div>';
      html += '<div class="row"><span class="label">Sessions</span><span class="value">' + b.sessionCount + '</span></div>';
      html += '<div class="row"><span class="label">Tools</span><span class="value">' + (b.toolProfile||[]).join(', ') + '</span></div>';
      html += '<div class="row"><span class="label">Categories</span><span class="value">' + (b.categoryProfile||[]).join(', ') + '</span></div>';
      html += '<div class="row"><span class="label">Updated</span><span class="value">' + b.lastUpdated + '</span></div>';

      if (b.features) {
        html += '<h2 style="margin-top:16px">Feature Baselines</h2>';
        for (const [name, stats] of Object.entries(b.features)) {
          const s = stats;
          html += '<div class="row"><span class="label">' + name + '</span><span class="value">mean=' + s.mean.toFixed(2) + ' stddev=' + Math.sqrt(s.m2/Math.max(s.n,1)).toFixed(2) + ' (n=' + s.n + ')</span></div>';
        }
      }
      html += '</div>';
    }

    if (evts.length > 0) {
      html += '<div class="card"><h2>Recent Events for this Agent</h2><div class="events-list">';
      for (const e of evts.reverse()) {
        html += '<div class="event ' + e.severity + '">';
        html += '<span class="time">' + timeAgo(e.timestamp) + '</span>';
        html += '<span class="sig">' + e.signatureId + '</span>';
        html += '<div class="match">' + truncate(e.matchedText || '', 120) + '</div>';
        html += '</div>';
      }
      html += '</div></div>';
    }

    document.getElementById('content').innerHTML = html;
  } catch(err) {
    document.getElementById('content').innerHTML = '<div class="card"><h2>Error loading agent: ' + err.message + '</h2></div>';
  }
}

// Tab switching
let currentTab = 'overview';
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab[onclick*=\"' + tab + '\"]').classList.add('active');
  if (tab === 'overview') {
    document.getElementById('content').style.display = 'grid';
    document.getElementById('rulesContent').style.display = 'none';
    refresh();
  } else if (tab === 'rules') {
    document.getElementById('content').style.display = 'none';
    document.getElementById('rulesContent').style.display = 'block';
    refreshRules();
  }
}

function showToast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

async function refreshRules() {
  try {
    const [policy, history, agents] = await Promise.all([
      fetchJson('/api/policy'),
      fetchJson('/api/policy/history'),
      fetchJson('/api/agents'),
    ]);

    const defPolicy = policy.policy?.default || {};
    const agentPolicies = policy.policy?.agents || {};
    const agentList = agents.agents || [];

    let html = '<div class="policy-section">';

    // Rulebase header bar (Palo Alto style)
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
    html += '<div><h2 style="color:#c9d1d9;font-size:16px;margin:0">Security Policy Rulebase</h2>';
    html += '<span style="color:#484f58;font-size:11px">' + (agentList.length + 1) + ' rules | Version ' + (history.current || 0) + '</span></div>';
    html += '<div class="btn-group">';
    html += '<input id="commit-desc" placeholder="Change description..." style="width:250px;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;border-radius:4px;font-size:12px">';
    html += '<button class="btn btn-primary" onclick="commitPolicy()">Commit</button>';
    html += '</div></div>';

    // Rulebase table
    html += '<table style="width:100%;border-collapse:collapse;font-size:12px">';
    html += '<thead><tr style="background:#161b22;border-bottom:2px solid #30363d">';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:35px">#</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e">Name</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:70px">Scope</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:90px">Action</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:90px">Severity</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:90px">Profiling</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e">Exceptions</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:50px">Hits</th>';
    html += '<th style="padding:8px 12px;text-align:left;color:#8b949e;width:80px"></th>';
    html += '</tr></thead><tbody>';

    // Rule 1: Default
    const defAction = defPolicy.injectionDetection || 'flag';
    const defSev = defPolicy.injectionMinSeverity || 'low';
    const defDisabled = (defPolicy.injectionDisabledSignatures || []).join(', ');
    const actionColors = { block: '#f85149', flag: '#d29922', off: '#484f58' };
    const actionIcons = { block: '&#x1f6d1;', flag: '&#x26a0;', off: '&#x23f8;' };

    html += '<tr id="rule-default" style="border-bottom:1px solid #21262d;background:#0d1117">';
    html += '<td style="padding:10px 12px;color:#484f58">1</td>';
    html += '<td style="padding:10px 12px"><span style="color:#3fb950;font-weight:600">Default Policy</span><br><span style="color:#484f58">All agents without custom rules</span></td>';
    html += '<td style="padding:10px 12px"><span style="background:#238636;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px">GLOBAL</span></td>';
    html += '<td style="padding:10px 12px"><select id="def-mode" style="background:#161b22;border:1px solid #30363d;color:' + actionColors[defAction] + ';padding:4px;border-radius:3px;font-size:11px;font-weight:600;width:75px">';
    ['flag','block','off'].forEach(m => { html += '<option value="' + m + '"' + (defAction===m?' selected':'') + ' style="color:' + actionColors[m] + '">' + m.toUpperCase() + '</option>'; });
    html += '</select></td>';
    html += '<td style="padding:10px 12px"><select id="def-severity" style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:4px;border-radius:3px;font-size:11px;width:75px">';
    ['low','medium','high'].forEach(s => { html += '<option value="' + s + '"' + (defSev===s?' selected':'') + '>' + s + '</option>'; });
    html += '</select></td>';
    html += '<td style="padding:10px 12px;color:#8b949e">—</td>';
    html += '<td style="padding:10px 12px"><input id="def-disabled" value="' + defDisabled + '" placeholder="none" style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:3px 6px;border-radius:3px;font-size:11px;width:100%"></td>';
    html += '<td style="padding:10px 12px;color:#8b949e">—</td>';
    html += '<td style="padding:10px 12px"><button class="btn btn-primary" style="padding:3px 10px;font-size:11px" onclick="saveDefault()">Save</button></td>';
    html += '</tr>';

    // Per-agent rules
    let ruleNum = 2;
    for (const a of agentList) {
      const ap = agentPolicies[a.agentBuildId] || {};
      const bid = a.agentBuildId;
      const hasOverride = Object.keys(ap).filter(k => k !== 'label' && k !== 'notes').length > 0;
      const agentAction = ap.injectionDetection || '';
      const agentSev = ap.injectionMinSeverity || '';
      const agentDisabled = (ap.injectionDisabledSignatures || []).join(', ');
      const agentProfile = ap.profilingMode || '';
      const effectiveAction = agentAction || defAction;

      html += '<tr style="border-bottom:1px solid #21262d;' + (hasOverride ? 'background:#0d1117' : '') + '">';
      html += '<td style="padding:10px 12px;color:#484f58">' + ruleNum + '</td>';
      html += '<td style="padding:10px 12px">';
      html += '<span style="color:#58a6ff;font-weight:600;cursor:pointer" onclick="showAgent(\\'' + bid + '\\')">' + (a.agentLabel || bid.slice(0,12)) + '</span>';
      html += '<br><span style="color:#484f58;font-size:10px">' + bid.slice(0,12) + ' | ' + (a.profiling?.maturity || 'none') + ' | ' + (a.profiling?.knownCategories || []).join(', ') + '</span>';
      html += '</td>';
      html += '<td style="padding:10px 12px"><span style="background:#1f6feb;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px">AGENT</span></td>';

      // Action select
      html += '<td style="padding:10px 12px"><select id="agent-mode-' + bid + '" style="background:#161b22;border:1px solid #30363d;color:' + (agentAction ? actionColors[agentAction] : '#484f58') + ';padding:4px;border-radius:3px;font-size:11px;font-weight:600;width:75px">';
      html += '<option value=""' + (!agentAction?' selected':'') + ' style="color:#484f58">inherit</option>';
      ['flag','block','off'].forEach(m => { html += '<option value="' + m + '"' + (agentAction===m?' selected':'') + ' style="color:' + actionColors[m] + '">' + m.toUpperCase() + '</option>'; });
      html += '</select></td>';

      // Severity select
      html += '<td style="padding:10px 12px"><select id="agent-severity-' + bid + '" style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:4px;border-radius:3px;font-size:11px;width:75px">';
      html += '<option value=""' + (!agentSev?' selected':'') + '>inherit</option>';
      ['low','medium','high'].forEach(s => { html += '<option value="' + s + '"' + (agentSev===s?' selected':'') + '>' + s + '</option>'; });
      html += '</select></td>';

      // Profiling mode
      html += '<td style="padding:10px 12px"><select id="agent-profile-' + bid + '" style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:4px;border-radius:3px;font-size:11px;width:75px">';
      html += '<option value=""' + (!agentProfile?' selected':'') + '>inherit</option>';
      ['learning','active','strict'].forEach(m => { html += '<option value="' + m + '"' + (agentProfile===m?' selected':'') + '>' + m + '</option>'; });
      html += '</select></td>';

      // Exceptions
      html += '<td style="padding:10px 12px"><input id="agent-disabled-' + bid + '" value="' + agentDisabled + '" placeholder="none" style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:3px 6px;border-radius:3px;font-size:11px;width:100%"></td>';

      // Hits
      html += '<td style="padding:10px 12px;color:' + (a.securityEventCount > 0 ? '#f85149' : '#3fb950') + ';font-weight:600">' + a.securityEventCount + '</td>';

      // Save
      html += '<td style="padding:10px 12px"><button class="btn btn-primary" style="padding:3px 10px;font-size:11px" onclick="saveAgent(\\'' + bid + '\\')">Save</button></td>';
      html += '</tr>';
      ruleNum++;
    }

    html += '</tbody></table>';

    // Version history (compact)
    html += '<div style="margin-top:24px;display:flex;gap:24px">';

    // Left: history
    html += '<div style="flex:1"><h2 style="color:#8b949e;font-size:13px;margin-bottom:8px">COMMIT HISTORY</h2>';
    if (history.commits && history.commits.length > 0) {
      for (const c of [...history.commits].reverse().slice(0, 8)) {
        const isCurrent = c.version === history.current;
        html += '<div class="history-item">';
        html += '<span><span class="ver">v' + c.version + '</span> ' + c.description + '</span>';
        html += '<span style="display:flex;align-items:center;gap:8px">';
        html += '<span style="color:#484f58;font-size:10px">' + c.timestamp.slice(0,16) + '</span>';
        html += isCurrent ? '<span style="color:#3fb950;font-size:10px">ACTIVE</span>' : '<button class="btn btn-secondary" style="padding:2px 8px;font-size:10px" onclick="rollbackPolicy(' + c.version + ')">Rollback</button>';
        html += '</span></div>';
      }
    } else {
      html += '<div style="color:#484f58;font-size:12px;padding:8px">No commits yet</div>';
    }
    html += '</div>';

    // Right: signature reference
    html += '<div style="width:280px"><h2 style="color:#8b949e;font-size:13px;margin-bottom:8px">SIGNATURE GROUPS</h2>';
    const sigGroups = [
      { prefix: 'io_', name: 'Instruction Override', count: 8 },
      { prefix: 'rs_', name: 'Role Switch', count: 8 },
      { prefix: 'pe_', name: 'Prompt Extraction', count: 6 },
      { prefix: 'cm_', name: 'Conversation Mockup', count: 5 },
      { prefix: 'eb_', name: 'Encoding Bypass', count: 6 },
      { prefix: 'de_', name: 'Data Exfiltration', count: 7 },
      { prefix: 'priv_', name: 'Privilege Escalation', count: 5 },
      { prefix: 'mcp_', name: 'MCP Tool Poisoning', count: 4 },
      { prefix: 'ml_', name: 'Multilingual (14 lang)', count: 38 },
      { prefix: 'tg_', name: 'Tool Guard', count: 22 },
    ];
    for (const g of sigGroups) {
      html += '<div style="display:flex;justify-content:space-between;padding:4px 8px;font-size:11px;border-bottom:1px solid #21262d">';
      html += '<span style="color:#8b949e">' + g.name + '</span>';
      html += '<span style="color:#58a6ff">' + g.prefix + '* (' + g.count + ')</span>';
      html += '</div>';
    }
    html += '<div style="padding:4px 8px;font-size:11px;color:#484f58;margin-top:4px">Use prefix in Exceptions to disable a group</div>';
    html += '</div></div>';

    html += '</div>';
    document.getElementById('rulesContent').innerHTML = html;
  } catch(err) {
    document.getElementById('rulesContent').innerHTML = '<div class="policy-section"><div class="rule-card"><h3>Error: ' + err.message + '</h3></div></div>';
  }
}

async function saveDefault() {
  const mode = document.getElementById('def-mode').value;
  const severity = document.getElementById('def-severity').value;
  const disabled = document.getElementById('def-disabled').value.split(',').map(s => s.trim()).filter(Boolean);
  try {
    await fetch(BASE + '/api/policy/default', {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ injectionDetection: mode, injectionMinSeverity: severity, injectionDisabledSignatures: disabled }),
    });
    showToast('Default policy saved');
    refreshRules();
  } catch(e) { showToast('Error: ' + e.message, true); }
}

async function saveAgent(bid) {
  const mode = document.getElementById('agent-mode-' + bid).value;
  const severity = document.getElementById('agent-severity-' + bid).value;
  const disabled = document.getElementById('agent-disabled-' + bid).value.split(',').map(s => s.trim()).filter(Boolean);
  const notes = document.getElementById('agent-notes-' + bid).value;
  const body = { notes };
  if (mode) body.injectionDetection = mode;
  if (severity) body.injectionMinSeverity = severity;
  if (disabled.length) body.injectionDisabledSignatures = disabled;
  try {
    await fetch(BASE + '/api/policy/agent/' + bid, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    showToast('Agent policy saved for ' + bid.slice(0,8));
    refreshRules();
  } catch(e) { showToast('Error: ' + e.message, true); }
}

async function removeAgent(bid) {
  if (!confirm('Remove custom rules for this agent? It will inherit default policy.')) return;
  try {
    await fetch(BASE + '/api/policy/agent/' + bid, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({}),
    });
    showToast('Agent override removed');
    refreshRules();
  } catch(e) { showToast('Error: ' + e.message, true); }
}

async function commitPolicy() {
  const desc = document.getElementById('commit-desc').value || 'Manual commit';
  try {
    const r = await fetch(BASE + '/api/policy/commit', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ description: desc }),
    });
    const data = await r.json();
    showToast('Committed as v' + data.version);
    document.getElementById('commit-desc').value = '';
    refreshRules();
  } catch(e) { showToast('Error: ' + e.message, true); }
}

async function rollbackPolicy(ver) {
  if (!confirm('Rollback to v' + ver + '? This will restore the policy from that point.')) return;
  try {
    const r = await fetch(BASE + '/api/policy/rollback', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ version: ver }),
    });
    const data = await r.json();
    showToast('Rolled back to v' + data.version);
    refreshRules();
  } catch(e) { showToast('Error: ' + e.message, true); }
}

// Auto-refresh every 3 seconds (only overview tab)
refresh();
setInterval(() => { if (currentTab === 'overview') refresh(); }, 3000);

// SSE for real-time event count badge
try {
  eventSource = new EventSource(BASE + '/api/events/stream');
  eventSource.onmessage = () => refresh();
} catch(e) {}
</script>
</body>
</html>`;
