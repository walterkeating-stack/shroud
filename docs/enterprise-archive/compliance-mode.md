# Compliance Mode

> Status: Config key exists, not implemented

## Concept

Enforce that certain entity categories MUST be detected in every obfuscation pass. If a locked category isn't found, the compliance check fails and a report is generated — useful for regulatory requirements where you need proof that PII categories are being actively monitored.

## Config Keys

```json
{
  "lockedCategories": ["email", "ip_address", "credit_card", "ssn"]
}
```

## Intended Behavior

- After obfuscation, check if all `lockedCategories` were detected
- If a locked category has zero detections, flag it in `ComplianceReport`
- `ComplianceReport` returned on every `ObfuscationResult`:
  ```typescript
  {
    compliant: boolean,
    missingCategories: Category[],
    detectedCategories: Category[],
    timestamp: string
  }
  ```
- Integrates with SIEM — compliance failures sent as alert events
- Integrates with policy-as-code — policy file can define locked categories

## Implementation Notes

- Referenced in obfuscation pipeline step 8: "Compliance check — verify locked categories were found"
- `ComplianceReport` type referenced in `ObfuscationResult` but not defined
- Consider: compliance mode should probably be per-request opt-in (not every text will contain every category)
