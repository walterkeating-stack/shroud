/**
 * Preload script that patches OpenClaw's Baileys integration to use a mock
 * WhatsApp socket instead of connecting to the real WhatsApp Web servers.
 *
 * Usage: NODE_OPTIONS="--require /path/to/intercept.cjs" openclaw gateway
 *
 * The mock socket:
 *   - Immediately emits connection.update { connection: "open" }
 *   - Forwards sendMessage() calls to the mock WhatsApp HTTP server
 *   - Accepts injected inbound messages via globalThis.__mockWhatsAppInject
 *
 * Reads MOCK_WHATSAPP_PORT from environment.
 */

const MOCK_PORT = process.env.MOCK_WHATSAPP_PORT;
if (!MOCK_PORT) return;

const fs = require('fs');
const http = require('http');
const path = require('path');
const { EventEmitter } = require('events');

// Find the session file that contains createWaSocket / makeWASocket
const sessionFile = '/usr/local/lib/node_modules/openclaw/dist/session-BBv1F7vj.js';
if (!fs.existsSync(sessionFile)) return;

let code = fs.readFileSync(sessionFile, 'utf-8');
if (code.includes('MOCK_WHATSAPP_INTERCEPT')) return; // already patched

// Patch: replace the createWaSocket function body to return a mock socket.
// The function signature is: async function createWaSocket(...)
// We replace the makeWASocket call and everything after it with our mock.
//
// Strategy: find `const sock = makeWASocket({` and replace the entire
// socket creation + event binding with mock code.

// Inject mock socket factory as a global
const mockFactory = `
// MOCK_WHATSAPP_INTERCEPT
if (process.env.MOCK_WHATSAPP_PORT) {
  const _http = await import('node:http');
  const _events = await import('node:events');
  const _EventEmitter = _events.EventEmitter;

  // Create mock event emitter that mimics Baileys ev interface
  const _ev = new _EventEmitter();
  _ev.buffer = () => {};
  _ev.flush = () => {};
  _ev.createBufferedFunction = (fn) => fn;
  _ev.process = (fn) => fn({ 'connection.update': [{ connection: 'open' }] });

  const _mockSock = {
    ev: _ev,
    ws: new _EventEmitter(),
    authState: { creds: {}, keys: {} },
    user: { id: '353850000000@s.whatsapp.net', name: 'MockBot' },
    type: 'md',
    sendMessage: async (jid, content, options) => {
      const text = content?.text || content?.caption || JSON.stringify(content);
      try {
        const body = JSON.stringify({ jid, text, content, options, ts: Date.now() });
        const req = (_http.request || _http.default.request)({
          hostname: '127.0.0.1',
          port: parseInt(process.env.MOCK_WHATSAPP_PORT),
          path: '/send',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        req.on('error', () => {});
        req.write(body);
        req.end();
      } catch {}
      return { status: 1, message: { key: { id: 'mock-' + Date.now() } } };
    },
    sendPresenceUpdate: async () => {},
    presenceSubscribe: async () => {},
    readMessages: async () => {},
    fetchStatus: async () => ({ status: 'Mock status', setAt: new Date() }),
    fetchBlocklist: async () => [],
    profilePictureUrl: async () => '',
    onWhatsApp: async (...jids) => jids.map(jid => ({ exists: true, jid })),
    fetchPrivacySettings: async () => ({}),
    waUploadToServer: async () => ({ url: 'https://mock.whatsapp.net/file' }),
    groupMetadata: async (jid) => ({ id: jid, subject: 'Mock Group', participants: [] }),
    groupFetchAllParticipating: async () => ({}),
    logout: async () => {},
    end: () => {},
    executeUSyncQuery: async () => ({ list: [] }),
  };

  // Start an injection HTTP server inside the gateway process.
  // This accepts POST /inject to emit messages.upsert on the mock socket.
  const _injectPort = parseInt(process.env.MOCK_WHATSAPP_INJECT_PORT || '9301');
  const _injectServer = (_http.createServer || _http.default.createServer)((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, {'Content-Type':'application/json'});
      res.end(JSON.stringify({ok:true}));
      return;
    }
    if (req.method === 'POST' && req.url === '/inject') {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        try {
          const msg = JSON.parse(Buffer.concat(chunks).toString());
          _injectMessage(msg);
          res.writeHead(200, {'Content-Type':'application/json'});
          res.end(JSON.stringify({injected:true}));
        } catch(e) {
          res.writeHead(400);
          res.end(JSON.stringify({error:e.message}));
        }
      });
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  // Retry bind on EADDRINUSE (stale server from prior run)
  let _bindAttempts = 0;
  _injectServer.on('error', function(err) {
    if (err.code === 'EADDRINUSE' && _bindAttempts < 5) {
      _bindAttempts++;
      console.error('[mock-whatsapp] Port ' + _injectPort + ' in use, retrying in 500ms (attempt ' + _bindAttempts + '/5)');
      setTimeout(function() { _injectServer.listen(_injectPort, '127.0.0.1'); }, 500);
    } else {
      console.error('[mock-whatsapp] Inject server failed to bind on ' + _injectPort + ': ' + err.message);
    }
  });
  _injectServer.listen(_injectPort, '127.0.0.1', function() {
    globalThis.__mockWhatsAppInjectReady = true;
    console.log('[mock-whatsapp] Inject server ready on port ' + _injectPort);
  });

  // Message injection function
  function _injectMessage(msg) {
    const message = {
      key: {
        remoteJid: msg.from || '353850000001@s.whatsapp.net',
        fromMe: false,
        id: 'mock-msg-' + Date.now(),
      },
      message: {
        conversation: msg.text || msg.message || '',
      },
      messageTimestamp: Math.floor(Date.now() / 1000),
      pushName: msg.pushName || 'Test User',
    };
    _ev.emit('messages.upsert', { messages: [message], type: 'notify' });
    // Also emit via the 'event' pattern that Baileys uses
    _ev.emit('event', { 'messages.upsert': { messages: [message], type: 'notify' } });
  };

  // Emit connection open after a tick (simulate async connection)
  setTimeout(() => {
    _ev.emit('connection.update', { connection: 'open' });
    _ev.emit('event', { 'connection.update': [{ connection: 'open' }] });
    _ev.emit('creds.update', {});
  }, 100);

  return _mockSock;
}
`;

// Patch: inject mock return at the top of the function that calls makeWASocket
// Find: `const sock = makeWASocket({`
// Before it, insert our mock factory that returns early if MOCK_WHATSAPP_PORT is set

const target = 'const sock = makeWASocket({';
const idx = code.indexOf(target);
if (idx === -1) {
  // Try alternative pattern
  const alt = 'sock = makeWASocket({';
  const altIdx = code.indexOf(alt);
  if (altIdx === -1) return;
  code = code.slice(0, altIdx) + mockFactory + '\n\t' + code.slice(altIdx);
} else {
  code = code.slice(0, idx) + mockFactory + '\n\t' + code.slice(idx);
}

fs.writeFileSync(sessionFile, code);
