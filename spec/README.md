# Specification

**ARIA 1.0 — first stable release — September 7, 2026.** The canonical, normative text is
published at **[aria.bar/spec](https://aria.bar/spec)** (12 normative sections and 5 appendices, CC-BY-4.0). This
repository holds the machine-readable artefacts that text refers to:

| Artefact | Where |
|---|---|
| AID schema (preview-line shape adopted by 1.0; `legalName` deprecated for natural persons) | [`../schema/aid-v1.2.json`](../schema/aid-v1.2.json) |
| ATP policy, intent declaration and enrollment manifest schemas | [`../schema/`](../schema/) |
| JSON-LD context | [`../context/v1.jsonld`](../context/v1.jsonld) |
| Conformance vectors (ABNF cases, canonical JSON) | [`../conformance/`](../conformance/) |
| Federation contract (registry → authority) | [`../federation/openapi.yaml`](../federation/openapi.yaml) |
| The invariants that cannot change | [`../INVARIANTS.md`](../INVARIANTS.md) |
| What 1.0 retires | [`../DEPRECATIONS.md`](../DEPRECATIONS.md) |

The normative basis for the trust levels is the **Verification Requirements** (80
citable requirements, arbitrated August 31, 2026) and the **ATP/1** specification, both
summarized at aria.bar/spec §2 and §8. Their full texts are published there.

## Legacy

[`legacy/`](legacy/) keeps the preview-line prose (architecture and ATP as labeled v1.1)
verbatim, for verifiers of preview credentials. It is superseded and not maintained.
