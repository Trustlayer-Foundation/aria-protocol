# Specification

**ARIA 1.0 — first stable release — September 7, 2026.** The canonical, normative text is
published at **[aria.bar/spec](https://aria.bar/spec)** (12 normative sections and 5 appendices, CC-BY-4.0). This
repository holds the machine-readable artefacts that text refers to:

| Artefact | Where |
|---|---|
| AID schema (`legalName` is an organization name; natural persons never populate it) | [`../schema/aid-1.0.json`](../schema/aid-1.0.json) |
| AID schema for credentials issued before the cutover (`spec_version` 1.2); stays published while any is in circulation | [`../schema/aid-v1.2.json`](../schema/aid-v1.2.json) |
| ATP policy, intent declaration and enrollment manifest schemas | [`../schema/`](../schema/) |
| JSON-LD context | [`../context/v1.jsonld`](../context/v1.jsonld) |
| Conformance vectors (ABNF cases, canonical JSON) | [`../conformance/`](../conformance/) |
| Federation contract (registry → authority) | [`../federation/openapi.yaml`](../federation/openapi.yaml) |
| The invariants that cannot change | [`../INVARIANTS.md`](../INVARIANTS.md) |
| What 1.0 retires | [`../DEPRECATIONS.md`](../DEPRECATIONS.md) |

The normative basis for the trust levels is the **Verification Requirements** (80
citable requirements, arbitrated August 31, 2026) and the **ATP/1** specification, both
summarized at aria.bar/spec §2 and §8. Their full texts are published there.
