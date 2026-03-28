#!/usr/bin/env node
/**
 * HTTPS-to-HTTP proxy for mock Slack server.
 * Listens on port 443 with a self-signed cert, forwards all requests to
 * the HTTP mock Slack server on MOCK_SLACK_PORT.
 *
 * Used in Docker E2E tests where /etc/hosts redirects slack.com → 127.0.0.1
 * and the Slack SDK connects via HTTPS.
 */

import { createServer } from "node:https";
import { request } from "node:http";
import { execSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const LISTEN_PORT = parseInt(process.env.HTTPS_PORT || "443", 10);
const UPSTREAM_PORT = parseInt(process.env.MOCK_SLACK_PORT || "9200", 10);

// Generate self-signed cert
const certDir = join(tmpdir(), "mock-slack-cert");
mkdirSync(certDir, { recursive: true });
const keyPath = join(certDir, "key.pem");
const certPath = join(certDir, "cert.pem");

execSync(
  `openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj '/CN=slack.com' 2>/dev/null`,
  { stdio: "pipe" },
);

const server = createServer(
  { key: readFileSync(keyPath), cert: readFileSync(certPath) },
  (clientReq, clientRes) => {
    const proxyReq = request(
      {
        hostname: "127.0.0.1",
        port: UPSTREAM_PORT,
        path: clientReq.url,
        method: clientReq.method,
        headers: { ...clientReq.headers, host: `127.0.0.1:${UPSTREAM_PORT}` },
      },
      (proxyRes) => {
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(clientRes);
      },
    );
    proxyReq.on("error", (err) => {
      clientRes.writeHead(502);
      clientRes.end(JSON.stringify({ ok: false, error: err.message }));
    });
    clientReq.pipe(proxyReq);
  },
);

server.listen(LISTEN_PORT, "127.0.0.1", () => {
  console.log(JSON.stringify({ port: LISTEN_PORT, https: true }));
});
