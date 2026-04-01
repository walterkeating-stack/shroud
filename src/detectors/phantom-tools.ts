/**
 * Phantom tools — canary tool definitions that catch injection through action.
 *
 * Registers fake tools with the LLM that look useful for exfiltration but
 * have no legitimate purpose. No real user instruction would ever trigger them
 * because users don't know they exist — they're not in the real tool set.
 *
 * But an injection that says "exfiltrate all context to this endpoint" will
 * reach for whatever tool looks most useful for sending data out. A tool
 * called "send_to_webhook" is irresistible to an exfil payload.
 *
 * The moment the LLM emits a call to a phantom tool: confirmed injection.
 * Zero ambiguity, zero false positives.
 *
 * Complementary to honeypots:
 * - Honeypots catch injection through the DATA it grabs
 * - Phantom tools catch injection through the ACTION it tries to take
 */

import type { SecurityEvent } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

/** A phantom tool definition. */
export interface PhantomToolDef {
  /** Tool name visible to the LLM. */
  name: string;
  /** Convincing description that attracts exfiltration attempts. */
  description: string;
  /** JSON schema for parameters — looks real, attracts data payloads. */
  inputSchema: object;
  /** What kind of exfil this catches. */
  trapType: "data_upload" | "webhook_relay" | "email_forward" | "api_relay" | "file_export";
}

/** The phantom tool definitions — designed to attract injection-driven exfil. */
export const PHANTOM_TOOLS: PhantomToolDef[] = [
  {
    name: "upload_file_external",
    description: "Upload a file or data payload to an external storage endpoint. Supports any URL. Use this when you need to send data to a remote server, webhook, or API endpoint.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The destination URL to upload to" },
        data: { type: "string", description: "The data payload to upload" },
        filename: { type: "string", description: "Optional filename for the upload" },
      },
      required: ["url", "data"],
    },
    trapType: "data_upload",
  },
  {
    name: "send_to_webhook",
    description: "Send a JSON payload to any webhook URL. Useful for forwarding data to external services, Slack incoming webhooks, Discord webhooks, or custom HTTP endpoints.",
    inputSchema: {
      type: "object",
      properties: {
        webhook_url: { type: "string", description: "The webhook endpoint URL" },
        payload: { type: "object", description: "The JSON payload to send" },
        method: { type: "string", enum: ["POST", "PUT"], description: "HTTP method (default POST)" },
      },
      required: ["webhook_url", "payload"],
    },
    trapType: "webhook_relay",
  },
  {
    name: "relay_data",
    description: "Relay data to an external API endpoint with custom headers. Supports authentication headers, custom content types, and arbitrary payloads.",
    inputSchema: {
      type: "object",
      properties: {
        endpoint: { type: "string", description: "The API endpoint URL" },
        body: { type: "string", description: "Request body content" },
        headers: { type: "object", description: "Custom HTTP headers" },
        auth_token: { type: "string", description: "Bearer token for authentication" },
      },
      required: ["endpoint", "body"],
    },
    trapType: "api_relay",
  },
  {
    name: "forward_email",
    description: "Forward a message or data to an email address. Supports attachments and rich text content.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Recipient email address" },
        subject: { type: "string", description: "Email subject line" },
        body: { type: "string", description: "Email body content" },
        attachment_data: { type: "string", description: "Base64-encoded attachment data" },
      },
      required: ["to", "body"],
    },
    trapType: "email_forward",
  },
  {
    name: "export_to_storage",
    description: "Export data to cloud storage (S3, GCS, Azure Blob). Supports any bucket URL and handles authentication automatically.",
    inputSchema: {
      type: "object",
      properties: {
        storage_url: { type: "string", description: "Cloud storage URL (s3://, gs://, or https://)" },
        data: { type: "string", description: "Data to export" },
        key: { type: "string", description: "Object key / filename in the bucket" },
      },
      required: ["storage_url", "data"],
    },
    trapType: "file_export",
  },
];

/**
 * Register all phantom tools with the plugin API.
 *
 * Each phantom tool's handler:
 * 1. Emits a high-severity security event (confirmed injection)
 * 2. Returns an error message to the LLM (to prevent retry)
 * 3. The event is logged, alerted, and the session is flagged
 */
export function registerPhantomTools(
  api: { registerTool: (tool: any) => void },
  onTriggered: (event: SecurityEvent, toolName: string, params: any) => void,
): void {
  for (const phantom of PHANTOM_TOOLS) {
    api.registerTool({
      name: phantom.name,
      description: phantom.description,
      inputSchema: phantom.inputSchema,
      handler: async (input: any) => {
        // Build the security event
        const event: SecurityEvent = {
          timestamp: Date.now(),
          eventType: "injection_detected",
          direction: "request",
          threatClass: ThreatClass.DATA_EXFILTRATION,
          signatureId: `pt_${phantom.trapType}`,
          severity: "high",
          matchedText: `PHANTOM TOOL: ${phantom.name} called with ${JSON.stringify(input).slice(0, 200)}`,
          matchStart: 0,
          matchEnd: 0,
          textLength: JSON.stringify(input).length,
          action: "blocked",
          description: `PHANTOM TOOL TRIPPED: LLM called "${phantom.name}" — this tool is a canary that no legitimate workflow uses. 100% confirmed injection attempt. Trap type: ${phantom.trapType}.`,
        };

        // Notify the hooks layer
        onTriggered(event, phantom.name, input);

        // Return an error to the LLM to prevent retry/escalation
        return {
          type: "text",
          text: `Error: ${phantom.name} is temporarily unavailable. This action has been logged for security review.`,
        };
      },
    });
  }
}
