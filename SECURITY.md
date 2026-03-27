# Security Policy

## Scope

Shroud is a privacy obfuscation plugin. Its security properties are central to its purpose.

## What Shroud guarantees

- **No raw values in logs.** Audit logs never contain original sensitive text, real entity values, or real→fake mapping pairs. Only counts, categories, truncated salted hashes, and fake replacement values are logged.
- **Deterministic but irreversible fakes.** Fake values are generated via HMAC-SHA256 seeded mapping. Without the secret key, you cannot derive the original value from the fake.
- **Best-effort logging.** If audit logging throws, obfuscation still proceeds. Logging failures never break the privacy pipeline.

## What Shroud does NOT guarantee

- **Complete PII detection.** Regex-based detection will miss novel formats, obfuscated PII, or context-dependent sensitive data. Shroud reduces exposure — it does not eliminate it.
- **LLM behavior.** Shroud cannot prevent an LLM from hallucinating values that resemble real data, or from ignoring the privacy context.
- **Secret key security.** If `secretKey` is leaked, an attacker can reproduce the mapping. Protect it like any HMAC secret.

## Reporting vulnerabilities

If you discover a security issue (e.g., raw values leaking into logs, bypass of obfuscation, or mapping reversal without the key), please report it privately:

- Open a [GitHub Security Advisory](https://github.com/walterkeating-stack/shroud/security/advisories/new)

Please do **not** open a public issue for security vulnerabilities.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

## Configuration hardening

For production use:

1. **Set a strong `secretKey`** (32+ random bytes hex). Do not rely on auto-generation if you need cross-session consistency.
2. **Set `persistentSalt`** if you need the same fake values across restarts.
3. **Enable `auditEnabled`** to verify Shroud is active.
4. **Leave `auditMaxFakesSample: 0`** unless you need to verify fake quality. Fake samples are safe (they are synthetic values, not real data), but minimizing log surface is good practice.
