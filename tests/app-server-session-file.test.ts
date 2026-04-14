import { afterEach, describe, expect, test } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

type Pending = {
  resolve: (value: any) => void;
  reject: (error: Error) => void;
};

const children = new Set<ChildProcessWithoutNullStreams>();

async function startAppServer(sessionFile: string) {
  const appServerPath = resolve(process.cwd(), "app-server.mjs");
  const distPath = resolve(process.cwd(), "dist");
  const child = spawn(process.execPath, [appServerPath, distPath], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      SHROUD_APP_SESSIONS_FILE: sessionFile,
      SHROUD_APP_EVENTS_FILE: join(tmpdir(), `shroud-app-events-${process.pid}.jsonl`),
    },
  });
  children.add(child);

  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const pending = new Map<number, Pending>();
  let nextId = 1;

  child.on("exit", (code) => {
    for (const entry of pending.values()) {
      entry.reject(new Error(`APP server exited with code ${code}`));
    }
    pending.clear();
  });

  child.stderr.resume();

  const handshake = await new Promise<any>((resolveHandshake, rejectHandshake) => {
    const timeout = setTimeout(() => {
      rejectHandshake(new Error("Timed out waiting for APP server handshake"));
    }, 5000);

    rl.on("line", function handleLine(line) {
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        return;
      }

      if (parsed?.app && parsed?.engine) {
        clearTimeout(timeout);
        rl.off("line", handleLine);
        rl.on("line", (nextLine) => {
          let msg;
          try {
            msg = JSON.parse(nextLine);
          } catch {
            return;
          }
          if (msg?.id != null && pending.has(msg.id)) {
            const entry = pending.get(msg.id)!;
            pending.delete(msg.id);
            if (msg.error) entry.reject(new Error(msg.error.message));
            else entry.resolve(msg.result);
          }
        });
        resolveHandshake(parsed);
      }
    });
  });

  async function call(method: string, params: Record<string, unknown>) {
    const id = nextId++;
    const response = new Promise<any>((resolveCall, rejectCall) => {
      pending.set(id, { resolve: resolveCall, reject: rejectCall });
    });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    return response;
  }

  async function shutdown() {
    try {
      await call("shutdown", {});
    } catch {
      // The process may exit before responding.
    }
    rl.close();
    if (!child.killed) child.kill("SIGTERM");
    children.delete(child);
  }

  return { child, handshake, call, shutdown };
}

async function waitForSessionRequestCount(sessionFile: string, expected: number) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const raw = readFileSync(sessionFile, "utf8");
      if (raw.trim()) {
        const parsed = JSON.parse(raw);
        if (parsed.requestCount === expected) return parsed;
      }
    } catch {
      // File may not exist or may still be mid-write.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for session file requestCount=${expected}`);
}

afterEach(() => {
  for (const child of children) {
    if (!child.killed) child.kill("SIGTERM");
  }
  children.clear();
});

describe("app-server session file flushing", () => {
  test("identify and tool_call persist requestCount immediately for APP clients", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "shroud-app-server-"));
    const sessionFile = join(tempDir, "app-session.json");
    const server = await startAppServer(sessionFile);

    expect(server.handshake.engine).toBe("shroud");

    await server.call("identify", {
      agent: "claude-code",
      version: "1.0.0",
      channel: "claude-cli",
    });

    await server.call("tool_call", {
      tool: "Read",
      args: { file_path: "/tmp/test.txt" },
    });

    const session = await waitForSessionRequestCount(sessionFile, 2);
    expect(session.requestCount).toBe(2);
    expect(session.toolSequence).toEqual(["Read"]);
    expect(session.agentLabel).toBe("claude-code");

    await server.shutdown();
    rmSync(tempDir, { recursive: true, force: true });
  });
});
