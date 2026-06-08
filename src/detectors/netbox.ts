/** NetBox-aware detector for sensitive infrastructure inventory fields. */

import { Category, DetectedEntity } from "../types.js";
import { BaseDetector } from "./base.js";

const NETBOX_HINT_RE =
  /"endpoint"\s*:\s*"(?:dcim|ipam|circuits|tenancy|extras|virtualization|wireless|vpn|plugins)\//i;
const NETBOX_TOOL_RE = /\bnetbox_(?:list|get|create|update|delete|bulk|request|graphql|pull|push|status|schema)\b/i;
const NETBOX_RESOURCE_RE = /\b(?:dcim|ipam|circuits|tenancy|extras|virtualization|wireless|vpn)\/[a-z0-9_\/-]+/i;

const SKIP_KEYS = new Set([
  "id",
  "url",
  "display_url",
  "api_url",
  "endpoint",
  "next",
  "previous",
  "count",
  "returned",
  "status",
  "value",
  "color",
  "created",
  "last_updated",
  "last_synced",
]);

const SKIP_PATHS = new Set([
  "status",
  "manufacturer",
  "platform",
  "device_type",
  "module_type",
  "interface_type",
  "cable_type",
]);

const GENERIC_VALUES = new Set([
  "active",
  "planned",
  "staged",
  "offline",
  "decommissioning",
  "decommissioned",
  "failed",
  "inventory",
  "connected",
  "provisioning",
  "available",
  "reserved",
  "deprecated",
  "primary",
  "secondary",
  "unknown",
  "none",
  "true",
  "false",
]);

const LOCATION_HINTS = new Set([
  "site",
  "sites",
  "region",
  "regions",
  "site_group",
  "site_groups",
  "location",
  "locations",
  "rack",
  "racks",
  "rack_group",
  "rack_groups",
  "facility",
]);

const HOST_HINTS = new Set([
  "device",
  "devices",
  "virtual_machine",
  "virtual_machines",
  "vm",
  "cluster",
  "clusters",
]);

const ORG_HINTS = new Set([
  "tenant",
  "tenants",
  "tenant_group",
  "tenant_groups",
  "provider",
  "providers",
  "contact",
  "contacts",
]);

const LINK_HINTS = new Set([
  "circuit",
  "circuits",
  "cable",
  "cables",
  "interface",
  "interfaces",
  "front_port",
  "rear_port",
  "console_port",
  "power_port",
]);

const NAME_KEYS = new Set(["name", "slug", "display"]);
const LOCATION_KEYS = new Set(["site", "region", "location", "rack", "facility", "physical_address", "address"]);
const HOST_KEYS = new Set(["device", "host", "hostname", "virtual_machine", "cluster"]);
const ORG_KEYS = new Set(["tenant", "provider", "customer", "owner", "contact"]);
const CUSTOM_KEYS = new Set([
  "serial",
  "asset_tag",
  "facility_id",
  "circuit_id",
  "cid",
  "inventory_id",
  "inventory_item",
  "external_id",
]);
const DESCRIPTION_KEYS = new Set(["description", "comments", "comment", "notes"]);

type ClassifiedValue = {
  key: string;
  value: string;
  category: Category;
  confidence: number;
  detector: string;
};

function looksLikeNetBox(text: string): boolean {
  return NETBOX_HINT_RE.test(text) || NETBOX_TOOL_RE.test(text) || NETBOX_RESOURCE_RE.test(text);
}

function normalizeKey(key: string): string {
  return key.trim().toLowerCase().replace(/-/g, "_");
}

function pathHints(path: string[]): Set<string> {
  return new Set(path.filter((part) => !/^\d+$/.test(part)).map(normalizeKey));
}

function hasAny(set: Set<string>, values: Set<string>): boolean {
  for (const value of values) {
    if (set.has(value)) return true;
  }
  return false;
}

function endpointCategory(endpoint: string, key: string): Category | null {
  const ep = endpoint.toLowerCase();
  if (/^dcim\/(?:sites|regions|site-groups|locations|racks|rack-groups)\//.test(ep)) return Category.LOCATION;
  if (/^dcim\/devices\//.test(ep) || /^virtualization\/virtual-machines\//.test(ep)) return Category.HOSTNAME;
  if (/^(?:tenancy\/tenants|circuits\/providers)\//.test(ep)) return Category.ORG_NAME;
  if (/^circuits\/circuits\//.test(ep)) return Category.INTERFACE_DESC;
  if (/^dcim\/(?:interfaces|cables|front-ports|rear-ports|console-ports|power-ports)\//.test(ep)) {
    return key === "name" || key === "display" ? Category.INTERFACE_DESC : Category.CUSTOM;
  }
  return null;
}

function shouldSkipValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 3) return true;
  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^\d+$/.test(trimmed)) return true;
  if (GENERIC_VALUES.has(trimmed.toLowerCase())) return true;
  return false;
}

function classifyField(key: string, value: string, path: string[], endpoint: string): ClassifiedValue | null {
  const normalizedKey = normalizeKey(key);
  if (SKIP_KEYS.has(normalizedKey) || shouldSkipValue(value)) return null;

  const hints = pathHints(path);
  for (const skip of SKIP_PATHS) {
    if (hints.has(skip)) return null;
  }

  let category: Category | null = null;
  let suffix = normalizedKey;
  let confidence = 0.88;

  if (DESCRIPTION_KEYS.has(normalizedKey)) {
    category = Category.INTERFACE_DESC;
    confidence = 0.86;
  } else if (CUSTOM_KEYS.has(normalizedKey)) {
    category = Category.CUSTOM;
    confidence = 0.9;
  } else if (LOCATION_KEYS.has(normalizedKey) || hasAny(hints, LOCATION_HINTS)) {
    category = Category.LOCATION;
  } else if (HOST_KEYS.has(normalizedKey) || hasAny(hints, HOST_HINTS)) {
    category = Category.HOSTNAME;
  } else if (ORG_KEYS.has(normalizedKey) || hasAny(hints, ORG_HINTS)) {
    category = Category.ORG_NAME;
  } else if (hasAny(hints, LINK_HINTS)) {
    category = Category.INTERFACE_DESC;
    confidence = 0.84;
  } else if (NAME_KEYS.has(normalizedKey)) {
    category = endpointCategory(endpoint, normalizedKey) ?? Category.CUSTOM;
    suffix = `name_${category}`;
  }

  if (!category) return null;
  return {
    key,
    value,
    category,
    confidence,
    detector: `netbox:${suffix}`,
  };
}

function tryParseJson(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function collectValues(node: unknown, path: string[], endpoint: string, out: ClassifiedValue[]): void {
  if (Array.isArray(node)) {
    node.forEach((value, idx) => collectValues(value, [...path, String(idx)], endpoint, out));
    return;
  }
  if (!node || typeof node !== "object") return;

  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (typeof value === "string") {
      if (key === "endpoint") endpoint = value;
      const classified = classifyField(key, value, path, endpoint);
      if (classified) out.push(classified);
      continue;
    }
    collectValues(value, [...path, key], endpoint, out);
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function spanOverlaps(spans: Array<[number, number]>, start: number, end: number): boolean {
  return spans.some(([s, e]) => start < e && end > s);
}

function locateJsonValue(
  text: string,
  key: string,
  value: string,
  spans: Array<[number, number]>,
): [number, number] | null {
  const keyLiteral = JSON.stringify(key);
  const valueLiteral = JSON.stringify(value);
  let cursor = 0;

  while (cursor < text.length) {
    const keyIdx = text.indexOf(keyLiteral, cursor);
    if (keyIdx === -1) return null;
    const colonIdx = text.indexOf(":", keyIdx + keyLiteral.length);
    if (colonIdx === -1) return null;
    const valueIdx = text.indexOf(valueLiteral, colonIdx + 1);
    if (valueIdx === -1) {
      cursor = keyIdx + keyLiteral.length;
      continue;
    }

    const between = text.slice(colonIdx + 1, valueIdx);
    if (/^\s*$/.test(between)) {
      const start = valueIdx + 1;
      const end = valueIdx + valueLiteral.length - 1;
      if (!spanOverlaps(spans, start, end)) return [start, end];
    }
    cursor = keyIdx + keyLiteral.length;
  }
  return null;
}

function unescapeJsonString(raw: string): string {
  try {
    return JSON.parse(`"${raw}"`);
  } catch {
    return raw;
  }
}

/**
 * Detect sensitive NetBox inventory values in serialized REST/GraphQL tool output.
 *
 * The detector is intentionally context-gated. It only runs when the text looks
 * like NetBox output, then classifies JSON fields using NetBox object paths.
 */
export class NetBoxDetector implements BaseDetector {
  readonly name = "netbox";

  detect(text: string): DetectedEntity[] {
    if (!looksLikeNetBox(text)) return [];

    const classified: ClassifiedValue[] = [];
    const parsed = tryParseJson(text);
    if (parsed !== null) {
      collectValues(parsed, [], "", classified);
    } else {
      this._collectFallback(text, classified);
    }

    const spans: Array<[number, number]> = [];
    const entities: DetectedEntity[] = [];
    for (const item of classified) {
      const span = locateJsonValue(text, item.key, item.value, spans);
      if (!span) continue;
      const [start, end] = span;
      spans.push([start, end]);
      entities.push({
        value: item.value,
        start,
        end,
        category: item.category,
        confidence: item.confidence,
        detector: item.detector,
      });
    }

    entities.sort((a, b) => a.start - b.start);
    return entities;
  }

  private _collectFallback(text: string, out: ClassifiedValue[]): void {
    const endpoint = NETBOX_RESOURCE_RE.exec(text)?.[0] ?? "";
    const fieldRe = new RegExp(
      `"(${[
        ...NAME_KEYS,
        ...LOCATION_KEYS,
        ...HOST_KEYS,
        ...ORG_KEYS,
        ...CUSTOM_KEYS,
        ...DESCRIPTION_KEYS,
      ].map(escapeRegex).join("|")})"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`,
      "gi",
    );

    for (const match of text.matchAll(fieldRe)) {
      const key = match[1];
      const value = unescapeJsonString(match[2]);
      const classified = classifyField(key, value, [], endpoint);
      if (classified) out.push(classified);
    }
  }
}
