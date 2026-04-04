#!/usr/bin/env node
/**
 * Catch-all HTTP server — returns 200 for any request.
 *
 * OC 2026.4.1+ processes URLs in messages (link preview, content enrichment).
 * In Docker with --internal network, these fetches fail and silently drop
 * the message. This server catches all those requests so OC can proceed.
 *
 * Listens on port 18888 (HTTP). The HTTPS proxy on 443 already handles TLS.
 * DNS is routed via /etc/hosts entries in entrypoint.sh.
 */

import http from "node:http";

const PORT = parseInt(process.env.MOCK_CATCHALL_PORT || "18888", 10);

const server = http.createServer((req, res) => {
  // Return a minimal valid response for any request
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Connection": "close",
  });
  res.end("<html><body>mock</body></html>");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Catch-all HTTP server listening on port ${PORT}`);
});
