/**
 * Fake generators for API keys, tokens, file paths, credit cards, SSNs.
 */

import { createHash } from "node:crypto";

import { Category } from "../types.js";
import type { BaseGenerator } from "./base.js";

export const FILE_DIRS = [
  "/opt/app/data", "/var/lib/service", "/home/user/projects",
  "/etc/app", "/tmp/cache", "/srv/web/static",
  "/opt/pipeline/output", "/var/log/app",
  "/home/user/docs", "/etc/ssl/certs",
];

export const FILE_NAMES = [
  "store.db", "config.yaml", "main.py", "settings.conf",
  "session.bin", "index.html", "results.csv", "service.log",
  "report.pdf", "app.pem", "weights.bin", "dump.json",
  "app.toml", "file.dat", "runner.sh", "artifact.tar.gz",
];

/** Compute Luhn check digit for a string of digits. */
function luhnCheckDigit(digits: string): number {
  let sum = 0;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if ((digits.length - i) % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return (10 - (sum % 10)) % 10;
}

export class CodeGenerator implements BaseGenerator {
  readonly categories = [
    Category.API_KEY,
    Category.FILE_PATH,
    Category.CREDIT_CARD,
    Category.SSN,
    Category.PHONE,
    Category.IBAN,
    Category.NATIONAL_ID,
    Category.JWT,
    Category.GPS_COORDINATE,
    Category.ICS_IDENTIFIER,
    Category.CERTIFICATE,
  ];

  generate(category: Category, seed: number, original = ""): string {
    if (category === Category.API_KEY) {
      return this._fakeApiKey(seed, original);
    } else if (category === Category.FILE_PATH) {
      return this._fakeFilePath(seed, original);
    } else if (category === Category.CREDIT_CARD) {
      return this._fakeCreditCard(seed, original);
    } else if (category === Category.SSN) {
      return this._fakeSsn(seed);
    } else if (category === Category.PHONE) {
      return this._fakePhone(seed, original);
    } else if (category === Category.IBAN) {
      return this._fakeIban(seed, original);
    } else if (category === Category.NATIONAL_ID) {
      return this._fakeNationalId(seed, original);
    } else if (category === Category.JWT) {
      return this._fakeJwt(seed);
    } else if (category === Category.GPS_COORDINATE) {
      return this._fakeGps(seed);
    } else if (category === Category.ICS_IDENTIFIER) {
      return `ICS-${String(seed % 100000).padStart(5, "0")}`;
    } else if (category === Category.CERTIFICATE) {
      return `[REDACTED-CERT-${String(seed % 10000).padStart(4, "0")}]`;
    }
    return `code-${String(seed % 10000).padStart(4, "0")}`;
  }

  _fakeApiKey(seed: number, original: string): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(seed >>> 0, 0);
    buf.writeUInt32BE(((seed >>> 16) ^ 0xcafebabe) >>> 0, 4);
    const h = createHash("sha256").update(buf).digest("hex");

    if (original) {
      // Preserve prefix pattern (e.g., "sk-prod-" -> "sk-test-")
      const prefixMatch = original.match(/^([a-zA-Z]+[-_](?:[a-zA-Z]+[-_])?)/);
      if (prefixMatch) {
        const prefix = prefixMatch[1];
        const remainingLen = Math.max(8, original.length - prefix.length);
        const fakeBody = h.slice(0, remainingLen);
        return `${prefix}${fakeBody}`;
      }
    }

    return `sk-test-${h.slice(0, 32)}`;
  }

  _fakeFilePath(seed: number, original: string): string {
    if (!original) {
      const d = FILE_DIRS[seed % FILE_DIRS.length];
      const f =
        FILE_NAMES[
          Math.floor(seed / FILE_DIRS.length) % FILE_NAMES.length
        ];
      return `${d}/${f}`;
    }

    // Preserve path depth and extension
    const normalised = original.replace(/\\/g, "/");
    const parts = normalised.split("/");
    let ext = "";
    const lastPart = parts[parts.length - 1];
    if (lastPart.includes(".")) {
      ext = "." + lastPart.split(".").slice(1).join(".");
    }

    // Match depth
    const dirNames = [
      "opt", "var", "home", "etc", "srv", "tmp", "app", "lib", "data", "logs",
    ];
    const fakeParts: string[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (!part) {
        fakeParts.push("");
        continue;
      }
      if (i === parts.length - 1) {
        // Filename
        let fname = FILE_NAMES[(seed + i) % FILE_NAMES.length];
        if (ext) {
          fname = fname.split(".")[0] + ext;
        }
        fakeParts.push(fname);
      } else {
        fakeParts.push(dirNames[(seed + i) % dirNames.length]);
      }
    }

    // Preserve separator
    if (original.includes("\\")) {
      return fakeParts.join("\\");
    }
    return fakeParts.join("/");
  }

  _fakeCreditCard(seed: number, original: string): string {
    // Generate 15 digits, then compute Luhn check digit for digit 16
    const part1 = String((seed & 0xffffffff) >>> 0).padStart(8, "0").slice(0, 8);
    const part2 = String(((seed >>> 4) ^ 0x12345678) >>> 0).padStart(8, "0").slice(0, 7);
    const first15 = (part1 + part2).slice(0, 15).padStart(15, "0");
    const checkDigit = luhnCheckDigit(first15 + "0");
    const digits = first15 + String(checkDigit);

    if (original) {
      // Detect separator
      const sep = original.includes("-")
        ? "-"
        : original.includes(" ")
          ? " "
          : "";
      if (sep) {
        return `${digits.slice(0, 4)}${sep}${digits.slice(4, 8)}${sep}${digits.slice(8, 12)}${sep}${digits.slice(12, 16)}`;
      }
    }

    return `${digits.slice(0, 4)}-${digits.slice(4, 8)}-${digits.slice(8, 12)}-${digits.slice(12, 16)}`;
  }

  _fakeSsn(seed: number): string {
    // Avoid invalid area numbers: 000, 666, 900-999
    let area = (seed % 898) + 1; // 1-898
    if (area >= 666) area++; // skip 666 -> gives us 1-665, 667-899

    // Avoid invalid group 00 and serial 0000
    const group = (Math.floor(seed / 898) % 99) + 1; // 01-99
    const serial = (Math.floor(seed / (898 * 99)) % 9999) + 1; // 0001-9999

    return `${String(area).padStart(3, "0")}-${String(group).padStart(2, "0")}-${String(serial).padStart(4, "0")}`;
  }

  _fakePhone(seed: number, original: string): string {
    const area = 200 + (seed % 800);
    const mid = 200 + (Math.floor(seed / 800) % 800);
    const last = seed % 10000;
    const lastStr = String(last).padStart(4, "0");

    if (!original) {
      return `(${area}) ${mid}-${lastStr}`;
    }

    // Detect format: +1, parens, dashes, spaces, dots
    const hasCountry = original.startsWith("+");
    const hasParens = original.includes("(");
    const hasSep = original.includes("-") || original.includes(".") || original.includes(" ");
    const sep = original.includes("-")
      ? "-"
      : original.includes(".")
        ? "."
        : original.includes(" ")
          ? " "
          : "";

    if (hasCountry) {
      // International format — preserve original separator style (or none)
      const countryMatch = original.match(/^\+(\d{1,3})/);
      const cc = countryMatch ? countryMatch[1] : "1";
      if (!hasSep) {
        // Original had no separators (e.g. +15551234567) — keep it compact
        return `+${cc}${area}${mid}${lastStr}`;
      }
      return `+${cc}${sep}${area}${sep}${mid}${sep}${lastStr}`;
    } else if (hasParens) {
      return `(${area}) ${mid}-${lastStr}`;
    } else {
      return `${area}${sep}${mid}${sep}${lastStr}`;
    }
  }

  _fakeIban(seed: number, original: string): string {
    // Preserve country code, generate fake digits
    const cc = original.slice(0, 2).toUpperCase() || "DE";
    const check = String(seed % 98).padStart(2, "0");
    const body = String(seed).padStart(18, "0").slice(0, 18);
    return `${cc}${check}${body}`;
  }

  _fakeNationalId(seed: number, original: string): string {
    // Preserve length and format (digits/letters)
    const len = original.length || 10;
    const digits = String(seed).padStart(len, "0").slice(0, len);
    return digits;
  }

  _fakeJwt(seed: number): string {
    const h = createHash("sha256").update(String(seed)).digest("base64url");
    return `eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.${h}`;
  }

  _fakeGps(seed: number): string {
    // Generate coordinates near null island (0,0) — clearly fake
    const lat = ((seed % 18000) / 100 - 90).toFixed(6);
    const lon = (((seed >>> 8) % 36000) / 100 - 180).toFixed(6);
    return `${lat}, ${lon}`;
  }
}
