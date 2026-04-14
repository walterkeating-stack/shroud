/**
 * SocketClient — connects to a running Shroud APP server via Unix socket.
 *
 * Shared by shroud-bridge.mjs and shroud-mcp.mjs so both use the same
 * request/response transport when talking to an APP server instance.
 *
 * The APP server must be started with --listen <socket-path> before
 * any client connects.
 *
 * Default socket path: /tmp/shroud-app.sock
 */

import { connect } from "node:net";
import { createInterface } from "node:readline";

const DEFAULT_SOCKET = "/tmp/shroud-app.sock";

export class SocketClient {
  #sock = null;
  #rl = null;
  #requestId = 0;
  #pending = new Map();
  #ready = false;
  #handshake = null;
  #socketPath;

  constructor(socketPath) {
    this.#socketPath = socketPath || process.env.SHROUD_SOCKET || DEFAULT_SOCKET;
  }

  connect() {
    return new Promise((resolve, reject) => {
      let resolved = false;

      this.#sock = connect(this.#socketPath, () => {
        this.#rl = createInterface({ input: this.#sock, crlfDelay: Infinity });

        this.#rl.on("line", (line) => {
          line = line.trim();
          if (!line) return;
          try {
            const msg = JSON.parse(line);
            // First message with "app" field is the handshake
            if (!this.#ready && msg.app) {
              this.#handshake = msg;
              this.#ready = true;
              if (!resolved) { resolved = true; resolve(msg); }
              return;
            }
            // JSON-RPC response
            if (msg.id !== undefined && this.#pending.has(msg.id)) {
              const { resolve: res, reject: rej, timer } = this.#pending.get(msg.id);
              clearTimeout(timer);
              this.#pending.delete(msg.id);
              if (msg.error) rej(new Error(`${msg.error.code}: ${msg.error.message}`));
              else res(msg.result);
            }
          } catch {}
        });
      });

      this.#sock.on("error", (err) => {
        if (!resolved) { resolved = true; reject(err); }
        this.#ready = false;
        for (const { reject: rej, timer } of this.#pending.values()) {
          clearTimeout(timer);
          rej(new Error(`Socket error: ${err.message}`));
        }
        this.#pending.clear();
      });

      this.#sock.on("close", () => {
        this.#ready = false;
      });

      setTimeout(() => {
        if (!resolved) { resolved = true; reject(new Error(`Socket connect timeout: ${this.#socketPath}`)); }
      }, 5_000);
    });
  }

  call(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this.#ready) return reject(new Error("Not connected to APP server"));
      const id = ++this.#requestId;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`Request ${id} (${method}) timed out`));
      }, 10_000);
      this.#pending.set(id, { resolve, reject, timer });
      this.#sock.write(JSON.stringify({ id, method, params }) + "\n");
    });
  }

  identify(agent, version, channel) { return this.call("identify", { agent, version, channel }); }
  obfuscate(text) { return this.call("obfuscate", { text }); }
  deobfuscate(text) { return this.call("deobfuscate", { text }); }
  toolCall(tool, args) { return this.call("tool_call", { tool, args }); }
  toolResult(tool, result) {
    return this.call("tool_result", {
      tool,
      result: typeof result === "string" ? result : JSON.stringify(result),
    });
  }
  stats() { return this.call("stats"); }
  security() { return this.call("security"); }
  health() { return this.call("health"); }
  configure(config) { return this.call("configure", { config }); }
  reset() { return this.call("reset"); }

  close() {
    this.#sock?.end();
    this.#ready = false;
  }

  get handshake() { return this.#handshake; }
  get ready() { return this.#ready; }
  get socketPath() { return this.#socketPath; }
}
