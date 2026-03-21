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

export class CodeGenerator implements BaseGenerator {
  readonly categories = [
    Category.API_KEY,
    Category.FILE_PATH,
    Category.CREDIT_CARD,
    Category.SSN,
    Category.PHONE,
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
    }
    return `code-${String(seed % 10000).padStart(4, "0")}`;
  }

  _fakeApiKey(seed: number, original: string): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(seed >>> 0, 0);
    buf.writeUInt32BE(((seed >>> 16) ^ 0xcafebabe) >>> 0, 4);
    const h = createHash("sha256").update(buf).digest("hex");

    if (original) {
      // Preserve prefix pattern (e.g., "sk-prod-" -> "sk-shroud-")
      const prefixMatch = original.match(/^([a-zA-Z]+[-_])/);
      if (prefixMatch) {
        const prefix = prefixMatch[1];
        // Match original length
        const remainingLen = Math.max(8, original.length - prefix.length);
        const fakeBody = h.slice(0, remainingLen);
        return `${prefix}shroud-${fakeBody}`;
      }
    }

    return `sk-shroud-${h.slice(0, 32)}`;
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
    // Use two seed portions to generate 16 digits without BigInt
    const part1 = String((seed & 0xffffffff) >>> 0).padStart(8, "0").slice(0, 8);
    const part2 = String(((seed >>> 4) ^ 0x12345678) >>> 0).padStart(8, "0").slice(0, 8);
    const digits = (part1 + part2).slice(0, 16).padStart(16, "0");

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
    const n = seed % 1000000000;
    const s = String(n).padStart(9, "0");
    return `${s.slice(0, 3)}-${s.slice(3, 5)}-${s.slice(5, 9)}`;
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
    const sep = original.includes("-")
      ? "-"
      : original.includes(".")
        ? "."
        : " ";

    if (hasCountry) {
      // International format
      const countryMatch = original.match(/^\+(\d{1,3})/);
      const cc = countryMatch ? countryMatch[1] : "1";
      return `+${cc}${sep}${area}${sep}${mid}${sep}${lastStr}`;
    } else if (hasParens) {
      return `(${area}) ${mid}-${lastStr}`;
    } else {
      return `${area}${sep}${mid}${sep}${lastStr}`;
    }
  }
}
