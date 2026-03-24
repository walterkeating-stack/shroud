/**
 * Reproducing test for IP corruption during deobfuscation.
 *
 * Root cause: overlapping fake subnet allocation + wrong subnet match +
 * fakeToRealMap collision in range description handler.
 */
import { describe, test, expect } from "vitest";

import { ShroudConfig } from "../src/types.js";
import { Obfuscator } from "../src/obfuscator.js";
import { SubnetMapper, CGNAT_BASE, ipToInt, intToIp } from "../src/generators/network.js";

const testConfig: ShroudConfig = {
  secretKey: "test-secret-key-1234567890abcdef",
  persistentSalt: "fixed-test-salt",
  minConfidence: 0,
  allowlist: [],
  denylist: [],
  canaryEnabled: false,
  canaryPrefix: "SHROUD-CANARY",
  auditEnabled: false,
  logMappings: false,
  customPatterns: [],
  verboseLogging: false,
  auditLogFormat: "human" as const,
  auditIncludeProofHashes: false,
  auditHashSalt: "",
  auditHashTruncate: 12,
  auditMaxFakesSample: 0,
  detectorOverrides: {},
  tenantId: "",
  maxToolDepth: 10,
  lockedCategories: [],
  exposureWindow: 60000,
  exposureThresholds: {},
  exposureGlobalThreshold: 100,
  policyFile: "",
  redactionLevel: "full" as const,
  sharedStorePath: "",
  sharedStoreTtlMs: 5000,
  provenanceTagging: false,
  sessionHandoff: false,
  dryRun: false,
  maxStoreMappings: 0,
};

function makeObfuscator(overrides?: Partial<ShroudConfig>): Obfuscator {
  return new Obfuscator({ ...testConfig, ...overrides });
}

describe("Deobfuscation IP corruption", () => {
  /**
   * Bug 1: Overlapping fake subnet allocation.
   *
   * mapSubnet() places fake networks at CGNAT_BASE + slot * subnetSize.
   * When subnets have different prefix lengths, the shared slot counter
   * causes later (smaller) subnets to land inside earlier (larger) ones.
   *
   * E.g., slot 0 with /24 (256 IPs) → 100.64.0.0
   *       slot 1 with /28 (16 IPs)  → 100.64.0.16 (inside the /24!)
   */
  test("SubnetMapper allocates non-overlapping fake subnets for mixed prefix lengths", () => {
    const mapper = new SubnetMapper();

    // Allocate a /24 subnet (256 IPs)
    const realNet24 = ipToInt("10.16.26.0");
    const fakeNet24 = mapper.mapSubnet(realNet24, 24);

    // Allocate a /28 subnet (16 IPs)
    const realNet28 = ipToInt("10.50.2.224");
    const fakeNet28 = mapper.mapSubnet(realNet28, 28);

    // The /28 fake network MUST NOT fall inside the /24 fake network range
    const net24End = (fakeNet24 + 256) >>> 0;
    const net28End = (fakeNet28 + 16) >>> 0;

    const overlaps =
      (fakeNet28 >= fakeNet24 && fakeNet28 < net24End) ||
      (fakeNet24 >= fakeNet28 && fakeNet24 < net28End);

    // This FAILS currently — fakeNet28 = 100.64.0.16 is inside 100.64.0.0/24
    expect(overlaps).toBe(false);
  });

  /**
   * Bug 2: Wrong subnet match during residual CGNAT deobfuscation.
   *
   * _deobfuscateResidualCgnat iterates subnetRev and takes the FIRST
   * matching fake subnet. With overlapping allocations, a broader
   * subnet (e.g., /24) matches IPs intended for a narrower one (/28),
   * producing the wrong real IP.
   */
  test("residual CGNAT deobfuscation matches correct subnet with mixed prefix lengths", () => {
    const obf = makeObfuscator();

    // Input text has CIDR notation so subnets get learned
    const inputText = [
      "Configure interface on 10.16.26.0/24 network.",
      "The firewall is at 10.16.26.1 and gateway at 10.16.26.254.",
      "DHCP pool for 10.50.2.224/28 is limited.",
      "Server at 10.50.2.229 responds on port 443.",
    ].join("\n");

    const obfResult = obf.obfuscate(inputText);

    // Verify obfuscation happened
    expect(obfResult.obfuscated).not.toContain("10.16.26.");
    expect(obfResult.obfuscated).not.toContain("10.50.2.");

    // Find the fake IPs that were assigned to each real IP
    const fakeFor229 = obfResult.mappingsUsed["10.50.2.229"];
    expect(fakeFor229).toBeDefined();

    // Now simulate an LLM generating a summary that includes a derived
    // CGNAT IP in the /28 subnet range
    const fakeIpParts = fakeFor229.split(".");
    const lastOctet = parseInt(fakeIpParts[3], 10);
    // Create a sibling IP in the same /28 (change last 4 bits)
    const siblingOctet = (lastOctet & 0xf0) | ((lastOctet + 1) & 0x0f);
    fakeIpParts[3] = String(siblingOctet);
    const siblingFakeIp = fakeIpParts.join(".");

    const llmSummary = `The server at ${siblingFakeIp} is in the same subnet.`;

    // Deobfuscate the LLM summary
    const deobfuscated = obf.deobfuscate(llmSummary);

    // The result MUST be in the 10.50.2.224/28 range, not 10.16.26.x
    expect(deobfuscated).not.toContain("10.16.26.");
    expect(deobfuscated).toMatch(/10\.50\.2\.\d+/);

    // All octets must be valid (0-255)
    const ipMatch = deobfuscated.match(/(\d+\.\d+\.\d+\.\d+)/);
    expect(ipMatch).toBeTruthy();
    if (ipMatch) {
      const octets = ipMatch[1].split(".").map(Number);
      for (const octet of octets) {
        expect(octet).toBeGreaterThanOrEqual(0);
        expect(octet).toBeLessThanOrEqual(255);
      }
    }
  });

  /**
   * Bug 3: fakeToRealMap collision in _deobfuscateCgnatRangeDescriptions.
   *
   * The handler maps fake IP prefix (first two octets) to real prefix.
   * ALL CGNAT fakes start with "100.64" (or similar second octets in
   * the 64-127 range), so multiple real subnets collide on the same key.
   * Last write wins, producing wrong real prefixes.
   */
  test("range description deobfuscation preserves correct real prefix for each subnet", () => {
    const obf = makeObfuscator();

    // Obfuscate IPs from two different real networks
    const inputText = [
      "Network A: 10.16.26.0/24 with host 10.16.26.5.",
      "Network B: 20.50.2.224/28 with host 20.50.2.229.",
    ].join("\n");

    const obfResult = obf.obfuscate(inputText);
    expect(obfResult.obfuscated).not.toContain("10.16.26.");
    expect(obfResult.obfuscated).not.toContain("20.50.2.");

    // LLM generates a summary using CGNAT range description (with CIDR, not bare IP)
    // The range handler processes these textually, not through intToIp
    const llmRangeText = "All servers are in the 100.64.x.x/24 address space.";

    const deobfuscated = obf.deobfuscate(llmRangeText);

    // The result should NOT contain "100.64" (CGNAT range should be cleaned up)
    expect(deobfuscated).not.toContain("100.64");

    // The replaced prefix should be a valid real prefix (10.x or 20.x),
    // not a corrupted value
    expect(deobfuscated).toMatch(/\d{1,3}\.\d{1,3}\.x\.x\/\d+/);
  });

  /**
   * Bug 4: Invalid octets pass through range description handler.
   *
   * If the LLM generates a CGNAT IP with an invalid octet (> 255),
   * the range handler replaces only the first two octets textually,
   * leaving the invalid octet in the output.
   */
  test("deobfuscation validates octets and rejects invalid IPs", () => {
    const obf = makeObfuscator();

    // First establish some subnet mappings
    obf.obfuscate("Server at 10.16.26.5 on 10.16.26.0/24 network.");

    // Simulate LLM generating an invalid CGNAT IP with octet > 255
    // (LLMs sometimes make arithmetic errors when computing IPs)
    const llmBadIp = "The range 100.64.26.352/28 is allocated.";

    const deobfuscated = obf.deobfuscate(llmBadIp);

    // Shroud must NOT convert CGNAT garbage into real-looking garbage.
    // The invalid IP should either stay as CGNAT (left alone) or be
    // unchanged. It must NOT become e.g. "10.16.26.352/28" (real prefix
    // with invalid octet).
    expect(deobfuscated).not.toMatch(/\b(?:10|172|192)\.\d+\.26\.352\b/);

    // If there are any valid-looking IPs in the output, they should have valid octets
    const validIps = deobfuscated.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g) || [];
    for (const ip of validIps) {
      const octets = ip.split(".").map(Number);
      // Skip the garbage IP from the LLM (100.64.26.352 is not a real IP)
      if (octets.some(o => o > 255)) continue;
      // All valid IPs should have octets 0-255
      for (const octet of octets) {
        expect(octet).toBeLessThanOrEqual(255);
      }
    }
  });

  /**
   * End-to-end scenario: multiple subnets with different prefix lengths,
   * LLM-generated summary with derived IPs, deobfuscation produces valid output.
   */
  test("end-to-end: multi-subnet obfuscation→LLM summary→deobfuscation produces valid IPs", () => {
    const obf = makeObfuscator();

    // Step 1: Obfuscate real network config with multiple subnets
    const realConfig = [
      "ip route 10.16.26.0/24 via 10.16.26.1",
      "ip route 10.50.2.224/28 via 10.50.2.225",
      "interface Vlan100",
      "  ip address 10.16.26.1 255.255.255.0",
      "interface Vlan200",
      "  ip address 10.50.2.225 255.255.240.0",
    ].join("\n");

    const obfResult = obf.obfuscate(realConfig);

    // Record all fake IPs assigned
    const fakeMappings = obfResult.mappingsUsed;
    const fakeIps = Object.values(fakeMappings).filter(
      (v) => /^\d+\.\d+\.\d+\.\d+$/.test(v)
    );

    // Step 2: Simulate LLM generating a summary that references these IPs
    // and derives new ones (e.g., next IP in subnet)
    const llmSummary = obfResult.obfuscated.replace(
      /^.*$/m,
      (line) => `Summary: ${line}`
    );

    // Step 3: Deobfuscate
    const deobfuscated = obf.deobfuscate(llmSummary);

    // Verify: all IPs in output are valid (octets 0-255)
    const outputIps = deobfuscated.match(/\b(\d+\.\d+\.\d+\.\d+)\b/g) || [];
    for (const ip of outputIps) {
      const octets = ip.split(".").map(Number);
      for (let i = 0; i < octets.length; i++) {
        expect(octets[i]).toBeLessThanOrEqual(255);
        expect(octets[i]).toBeGreaterThanOrEqual(0);
      }
    }

    // Verify: no CGNAT IPs leaked through
    for (const ip of outputIps) {
      const firstOctet = parseInt(ip.split(".")[0], 10);
      const secondOctet = parseInt(ip.split(".")[1], 10);
      const isCgnat = firstOctet === 100 && secondOctet >= 64 && secondOctet <= 127;
      expect(isCgnat).toBe(false);
    }

    // Verify: deobfuscated IPs should be in real network ranges
    expect(deobfuscated).toContain("10.");
  });
});
