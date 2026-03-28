# Provenance Tagging

> Status: Config key exists, not implemented

## Concept

Embed invisible markers in obfuscated text that identify which category and mapping produced each fake value. Enables downstream systems to understand what was obfuscated without needing access to the mapping store.

## Config Keys

```json
{
  "provenanceTagging": true
}
```

## Intended Behavior

- Each fake value gets a marker: `«shroud:category:hash»`
- Markers are invisible in rendered text (zero-width characters or HTML comments)
- Deobfuscation strips provenance tags before reversing fakes
- Tags enable:
  - Audit trail without store access
  - Category-aware downstream processing
  - Leak detection (provenance tag found in unexpected location = data leak)

## Implementation Notes

- Referenced in obfuscation pipeline step 6: "Optionally add provenance tag"
- Deobfuscation step 1: "Strip canary tokens and provenance tags"
- Similar to existing canary token injection — could share infrastructure
- Consider: tag format that survives copy-paste, markdown rendering, SSE streaming
