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
    Category.DATE_OF_BIRTH,
    Category.MEDICAL_RECORD_NUMBER,
    Category.BANK_ACCOUNT_NUMBER,
    Category.TAX_ID,
    Category.PASSPORT_NUMBER,
    Category.DRIVERS_LICENSE,
    Category.CASE_NUMBER,
    Category.CRYPTOCURRENCY_ADDRESS,
    Category.AWS_ARN,
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
      return this._fakeIcsId(seed, original);
    } else if (category === Category.CERTIFICATE) {
      return this._fakeCertificate(seed, original);
    } else if (category === Category.DATE_OF_BIRTH) {
      return this._fakeDob(seed, original);
    } else if (category === Category.MEDICAL_RECORD_NUMBER) {
      return this._fakeMedicalId(seed, original);
    } else if (category === Category.BANK_ACCOUNT_NUMBER) {
      return this._fakeBankAccount(seed, original);
    } else if (category === Category.TAX_ID) {
      return this._fakeTaxId(seed, original);
    } else if (category === Category.PASSPORT_NUMBER) {
      return this._fakePassport(seed, original);
    } else if (category === Category.DRIVERS_LICENSE) {
      return this._fakeDriversLicense(seed, original);
    } else if (category === Category.CASE_NUMBER) {
      return this._fakeCaseNumber(seed, original);
    } else if (category === Category.CRYPTOCURRENCY_ADDRESS) {
      return this._fakeCryptoAddress(seed, original);
    } else if (category === Category.AWS_ARN) {
      return this._fakeAwsArn(seed, original);
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
      // International format — always E.164 compact (no separators).
      // WhatsApp and other telephony systems require pure digits after "+".
      // Spaces/dashes break E.164 validation and deobfuscation roundtrip.
      const countryMatch = original.match(/^\+(\d{1,3})/);
      const cc = countryMatch ? countryMatch[1] : "1";
      return `+${cc}${area}${mid}${lastStr}`;
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

  /**
   * Format-aware national ID generator.
   * Preserves structure per detected sub-type rather than generic zero-padding.
   */
  _fakeNationalId(seed: number, original: string): string {
    const h = createHash("sha256").update(`natid:${seed}`).digest("hex");
    const len = original.length || 10;

    // Austrian SVNR: 4 digits + DDMMYY (e.g., "1234 010190")
    if (/^\d{4}\s?\d{6}$/.test(original)) {
      const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));
      const hasSpace = original.includes(" ");
      return hasSpace
        ? `${d.slice(0, 4)} ${d.slice(4, 10)}`
        : d.slice(0, 10);
    }

    // German Personalausweis: alphanumeric 9-10 chars with specific char set
    if (/^[CFGHJKLMNPRTVWXYZ0-9]{9,10}$/.test(original)) {
      const charset = "CFGHJKLMNPRTVWXYZ0123456789";
      let result = "";
      for (let i = 0; i < len; i++) {
        result += charset[parseInt(h[i * 2] + h[i * 2 + 1], 16) % charset.length];
      }
      return result;
    }

    // Generic: preserve format character-by-character (letters stay letters, digits stay digits)
    let result = "";
    for (let i = 0; i < len; i++) {
      const c = original[i];
      if (!c || /[0-9]/.test(c)) {
        result += String(parseInt(h[i] || "0", 16) % 10);
      } else if (/[A-Z]/.test(c)) {
        result += "ABCDEFGHJKLMNPRSTUVWXYZ"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[a-z]/.test(c)) {
        result += "abcdefghjklmnprstuvwxyz"[parseInt(h[i * 2] || "0", 16) % 23];
      } else {
        result += c; // preserve dashes, spaces, etc.
      }
    }
    return result;
  }

  _fakeJwt(seed: number): string {
    const h = createHash("sha256").update(String(seed)).digest("base64url");
    return `eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.${h}`;
  }

  /**
   * GPS coordinate generator — distributes across plausible world locations
   * instead of clustering near null island (0,0).
   */
  _fakeGps(seed: number): string {
    // Anchor points across continents for realistic-looking coordinates
    const anchors = [
      [48.2, 16.4],    // Vienna area
      [40.7, -74.0],   // New York area
      [51.5, -0.1],    // London area
      [35.7, 139.7],   // Tokyo area
      [-33.9, 151.2],  // Sydney area
      [55.8, 37.6],    // Moscow area
      [-23.5, -46.6],  // São Paulo area
      [37.8, -122.4],  // San Francisco area
      [52.5, 13.4],    // Berlin area
      [1.3, 103.8],    // Singapore area
    ];
    const anchor = anchors[seed % anchors.length];
    // Add deterministic offset ±2 degrees (stays in the general area)
    const latOffset = ((seed >>> 4) % 400 - 200) / 100;
    const lonOffset = ((seed >>> 12) % 400 - 200) / 100;
    const lat = (anchor[0] + latOffset).toFixed(6);
    const lon = (anchor[1] + lonOffset).toFixed(6);
    return `${lat}, ${lon}`;
  }

  /**
   * ICS/SCADA identifier — format-aware per sub-type.
   * Preserves structure for OPC UA endpoints, Modbus addresses, BACnet IDs, etc.
   */
  _fakeIcsId(seed: number, original: string): string {
    const h = createHash("sha256").update(`ics:${seed}`).digest("hex");
    const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));

    // OPC UA endpoint: "opc.tcp://host:port/path"
    if (/^opc\.tcp:\/\//i.test(original)) {
      return `opc.tcp://plc-${d.slice(0, 4)}.local:${4840 + (seed % 100)}/${h.slice(0, 8)}`;
    }

    // Modbus/slave/unit address: small number
    if (/^\d{1,3}$/.test(original)) {
      return String((seed % 247) + 1); // Modbus range 1-247
    }

    // BACnet device instance: up to 7 digits
    if (/^\d{1,7}$/.test(original) && original.length > 3) {
      return d.slice(0, original.length);
    }

    // DNP3 outstation address: up to 5 digits
    if (/^\d{1,5}$/.test(original)) {
      return d.slice(0, original.length);
    }

    // IEC 61850 IED name: alphanumeric device name
    if (/^[A-Z][A-Za-z0-9_\-]{2,}$/.test(original)) {
      const prefixes = ["PLC", "RTU", "IED", "HMI", "DCS"];
      return prefixes[seed % prefixes.length] + "-" + d.slice(0, 4);
    }

    // Historian tag: dotted path like "Plant.Area.Tag"
    if (original.includes(".") && /^[A-Za-z]/.test(original)) {
      const parts = original.split(".");
      const fakeParts = parts.map((_, i) => {
        const labels = i === 0 ? ["Plant", "Site", "Facility"]
          : i === parts.length - 1 ? ["Tag", "Point", "Value", "Status"]
          : ["Area", "Unit", "Zone", "Line"];
        return labels[parseInt(h[i * 2] || "0", 16) % labels.length] + d.slice(i, i + 2);
      });
      return fakeParts.join(".");
    }

    // Fallback: prefix + digits
    return `ICS-${d.slice(0, 5)}`;
  }

  /**
   * Certificate generator — produces structurally valid PEM-like blocks
   * instead of [REDACTED-CERT-XXXX] placeholders.
   */
  _fakeCertificate(seed: number, original: string): string {
    const h = createHash("sha256").update(`cert:${seed}`).digest("hex");

    // PEM private key
    if (/BEGIN.*PRIVATE KEY/i.test(original)) {
      const fakeKey = Buffer.from(h + h + h + h).toString("base64");
      const lines = [];
      for (let i = 0; i < fakeKey.length; i += 64) {
        lines.push(fakeKey.slice(i, i + 64));
      }
      return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
    }

    // PEM certificate
    if (/BEGIN CERTIFICATE/i.test(original)) {
      const fakeCert = Buffer.from(h + h + h + h + h + h).toString("base64");
      const lines = [];
      for (let i = 0; i < fakeCert.length; i += 64) {
        lines.push(fakeCert.slice(i, i + 64));
      }
      return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
    }

    // Short cert/key reference
    return `CERT-${h.slice(0, 12).toUpperCase()}`;
  }

  /**
   * Format-preserving fake date of birth.
   * Shifts the date by a deterministic offset (30-300 days) derived from seed,
   * preserving the original format (MM/DD/YYYY, YYYY-MM-DD, DD.MM.YYYY, written month).
   */
  _fakeDob(seed: number, original: string): string {
    const offset = (seed % 270) + 30; // 30-300 day shift

    // Try to parse and reformat
    // ISO: 1987-03-15
    const isoMatch = original.match(/(\d{4})-(\d{2})-(\d{2})/);
    if (isoMatch) {
      const d = new Date(+isoMatch[1], +isoMatch[2] - 1, +isoMatch[3]);
      d.setDate(d.getDate() + offset);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    }

    // US: MM/DD/YYYY or MM-DD-YYYY or MM.DD.YYYY
    const usMatch = original.match(/(\d{1,2})([\/\-\.])(\d{1,2})\2(\d{2,4})/);
    if (usMatch) {
      const year = usMatch[4].length === 2 ? 1900 + +usMatch[4] : +usMatch[4];
      const d = new Date(year, +usMatch[1] - 1, +usMatch[3]);
      d.setDate(d.getDate() + offset);
      const yStr = usMatch[4].length === 2 ? String(d.getFullYear()).slice(2) : String(d.getFullYear());
      return `${String(d.getMonth() + 1).padStart(usMatch[1].length, "0")}${usMatch[2]}${String(d.getDate()).padStart(usMatch[3].length, "0")}${usMatch[2]}${yStr}`;
    }

    // Written month: "March 15, 1987"
    const months = ["January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December"];
    const writtenMatch = original.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(\d{4})/i);
    if (writtenMatch) {
      const mi = months.findIndex(m => m.toLowerCase() === writtenMatch[1].toLowerCase());
      const d = new Date(+writtenMatch[3], mi, +writtenMatch[2]);
      d.setDate(d.getDate() + offset);
      return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
    }

    // Fallback: shift digits
    const shifted = String((seed % 28) + 1).padStart(2, "0") + "/" +
      String((seed % 12) + 1).padStart(2, "0") + "/" +
      String(1950 + (seed % 60));
    return shifted;
  }

  /**
   * Fake medical record / provider ID.
   * Preserves format structure (letter+digits, pure digits, with dashes).
   */
  _fakeMedicalId(seed: number, original: string): string {
    const h = createHash("sha256").update(`mrn:${seed}`).digest("hex");

    // DEA format: 2 letters + 7 digits
    if (/^[A-Z][A-Z9]\d{7}$/.test(original)) {
      const letters = "ABCDEFGHJKLMNPRSTUVWXYZ";
      return letters[seed % letters.length] + letters[(seed >>> 4) % letters.length] +
        h.replace(/[a-f]/g, d => String((parseInt(d, 16) % 10))).slice(0, 7);
    }

    // NPI: 10 digits
    if (/^\d{10}$/.test(original)) {
      return h.replace(/[a-f]/g, d => String((parseInt(d, 16) % 10))).slice(0, 10);
    }

    // Generic: preserve length, replace with alphanumeric
    const len = original.length || 8;
    let result = "";
    for (let i = 0; i < len; i++) {
      const c = original[i];
      if (!c || /[A-Z]/.test(c)) {
        result += "ABCDEFGHJKLMNPRSTUVWXYZ"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[0-9]/.test(c)) {
        result += h[i] ? String(parseInt(h[i], 16) % 10) : "0";
      } else {
        result += c; // preserve dashes, etc.
      }
    }
    return result;
  }

  /**
   * Fake bank account / routing number.
   * Preserves format (digit count, dashes, sort code format).
   */
  _fakeBankAccount(seed: number, original: string): string {
    const h = createHash("sha256").update(`bank:${seed}`).digest("hex");

    // SWIFT/BIC: 8 or 11 alphanumeric
    if (/^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/.test(original)) {
      const banks = ["SHROUD", "FAKEBK", "TESTBK", "DEMOFI", "SYNBNK"];
      const bank = banks[seed % banks.length];
      const country = original.slice(4, 6); // preserve country code
      const suffix = h.slice(0, 2).toUpperCase();
      const branch = original.length === 11 ? h.slice(2, 5).toUpperCase() : "";
      return bank + country + suffix + branch;
    }

    // Sort code: XX-XX-XX
    if (/^\d{2}-\d{2}-\d{2}$/.test(original)) {
      const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));
      return `${d.slice(0, 2)}-${d.slice(2, 4)}-${d.slice(4, 6)}`;
    }

    // Digit-only: preserve length
    const len = original.replace(/\D/g, "").length || 9;
    const digits = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10)).slice(0, len);
    return digits.padStart(len, "0");
  }

  /**
   * Fake tax ID / EIN.
   * Preserves format (XX-XXXXXXX for EIN, pure digits for others).
   */
  _fakeTaxId(seed: number, original: string): string {
    const h = createHash("sha256").update(`tax:${seed}`).digest("hex");
    const digits = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));

    // EIN format: XX-XXXXXXX
    if (/^\d{2}-\d{7}$/.test(original)) {
      return `${digits.slice(0, 2)}-${digits.slice(2, 9)}`;
    }

    // Pure digits: preserve length
    const len = original.replace(/\D/g, "").length || 10;
    return digits.slice(0, len).padStart(len, "0");
  }

  /**
   * Fake passport number.
   * Preserves format: letter prefix + digit count, or pure alphanumeric.
   */
  _fakePassport(seed: number, original: string): string {
    const h = createHash("sha256").update(`passport:${seed}`).digest("hex");
    const len = original.length || 9;
    let result = "";
    for (let i = 0; i < len; i++) {
      const c = original[i];
      if (!c || /[A-Z]/.test(c)) {
        result += "ABCDEFGHJKLMNPRSTUVWXYZ"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[a-z]/.test(c)) {
        result += "abcdefghjklmnprstuvwxyz"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[0-9]/.test(c)) {
        result += String(parseInt(h[i] || "0", 16) % 10);
      } else {
        result += c; // preserve spaces, dashes
      }
    }
    return result;
  }

  /**
   * Fake driver's license / license plate.
   * Preserves format structure (letter/digit positions, dashes, spaces).
   */
  _fakeDriversLicense(seed: number, original: string): string {
    const h = createHash("sha256").update(`dl:${seed}`).digest("hex");
    const len = original.length || 8;
    let result = "";
    for (let i = 0; i < len; i++) {
      const c = original[i];
      if (!c || /[A-Z]/.test(c)) {
        result += "ABCDEFGHJKLMNPRSTUVWXYZ"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[0-9]/.test(c)) {
        result += String(parseInt(h[i] || "0", 16) % 10);
      } else {
        result += c; // preserve dashes, spaces
      }
    }
    return result;
  }

  /**
   * Fake case / docket / patent number.
   * Preserves format: digit:digit-letters-digits, or prefix + digits.
   */
  _fakeCaseNumber(seed: number, original: string): string {
    const h = createHash("sha256").update(`case:${seed}`).digest("hex");

    // US federal: X:XX-xx-XXXXX
    const fedMatch = original.match(/^(\d{1,2}):(\d{2})-([a-z]{2})-(\d{3,6})$/);
    if (fedMatch) {
      const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));
      return `${d.slice(0, fedMatch[1].length)}:${d.slice(2, 4)}-${fedMatch[3]}-${d.slice(4, 4 + fedMatch[4].length)}`;
    }

    // Patent: preserve country prefix + fake digits
    const patentMatch = original.match(/^([A-Z]{2})\s?(\d+)(.*)$/);
    if (patentMatch) {
      const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));
      return `${patentMatch[1]}${d.slice(0, patentMatch[2].length)}${patentMatch[3]}`;
    }

    // German Aktenzeichen: preserve structure
    const azMatch = original.match(/^(\d{1,3})\s+([A-Z][a-z]*)\s+(\d{1,5})\/(\d{2,4})$/);
    if (azMatch) {
      const d = h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10));
      return `${d.slice(0, azMatch[1].length)} ${azMatch[2]} ${d.slice(2, 2 + azMatch[3].length)}/${d.slice(5, 5 + azMatch[4].length)}`;
    }

    // Generic: preserve format character-by-character
    const len = original.length || 10;
    let result = "";
    for (let i = 0; i < len; i++) {
      const c = original[i];
      if (!c || /[A-Z]/.test(c)) {
        result += "ABCDEFGHJKLMNPRSTUVWXYZ"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[a-z]/.test(c)) {
        result += "abcdefghjklmnprstuvwxyz"[parseInt(h[i * 2] || "0", 16) % 23];
      } else if (/[0-9]/.test(c)) {
        result += String(parseInt(h[i] || "0", 16) % 10);
      } else {
        result += c;
      }
    }
    return result;
  }

  /**
   * Fake cryptocurrency address.
   * Preserves format: Ethereum (0x + 40 hex), Bitcoin P2PKH/P2SH (base58),
   * Bitcoin Bech32 (bc1 + lowercase alphanum).
   */
  _fakeCryptoAddress(seed: number, original: string): string {
    const h = createHash("sha256").update(`crypto:${seed}`).digest("hex");

    // Ethereum: 0x + 40 hex
    if (/^0x[0-9a-fA-F]{40}$/.test(original)) {
      return "0x" + h.slice(0, 40);
    }

    // Bitcoin Bech32: bc1 + lowercase alphanum
    if (/^bc1[a-z0-9]{39,59}$/.test(original)) {
      const len = original.length - 3; // minus "bc1"
      const chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; // bech32 charset
      let result = "bc1";
      for (let i = 0; i < len; i++) {
        result += chars[parseInt(h[(i * 2) % 64] + h[(i * 2 + 1) % 64], 16) % chars.length];
      }
      return result;
    }

    // Bitcoin P2PKH (starts with 1) or P2SH (starts with 3)
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(original)) {
      const prefix = original[0];
      const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      const len = original.length - 1;
      let result = prefix;
      for (let i = 0; i < len; i++) {
        result += base58[parseInt(h[(i * 2) % 64] + h[(i * 2 + 1) % 64], 16) % base58.length];
      }
      return result;
    }

    // Generic: preserve length with hex-like replacement
    return h.slice(0, original.length || 42);
  }

  /**
   * Fake AWS ARN.
   * Preserves service and resource type, replaces account ID and resource name.
   */
  _fakeAwsArn(seed: number, original: string): string {
    const h = createHash("sha256").update(`arn:${seed}`).digest("hex");

    // Full ARN: arn:partition:service:region:account-id:resource
    const arnMatch = original.match(/^(arn:[a-z\-]+:[a-z0-9\-]+:[a-z0-9\-]*:)(\d{0,12}):(.+)$/);
    if (arnMatch) {
      const accountLen = arnMatch[2].length;
      const fakeAccount = accountLen > 0
        ? h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10)).slice(0, accountLen)
        : ""; // S3-style ARN with no account
      const resourceParts = arnMatch[3].split("/");
      // Preserve resource type (first part), fake the rest
      const fakeResource = resourceParts.length > 1
        ? resourceParts[0] + "/shroud-" + h.slice(12, 20)
        : "shroud-" + h.slice(12, 20);
      return arnMatch[1] + fakeAccount + ":" + fakeResource;
    }

    // Bare account ID (12 digits)
    if (/^\d{12}$/.test(original)) {
      return h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10)).slice(0, 12);
    }

    return `arn:aws:iam::${h.replace(/[a-f]/g, c => String(parseInt(c, 16) % 10)).slice(0, 12)}:shroud-${h.slice(0, 8)}`;
  }
}
