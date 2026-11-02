# Specification

The canonical, normative text of ARIA is published at **[aria.bar/spec](https://aria.bar/spec)**
(12 normative sections and 6 appendices, CC-BY-4.0). This repository holds the
machine-readable artefacts that text refers to, and says which edition of it goes with
what is here.

## Which edition

| Edition | Status | What it covers |
|---|---|---|
| **1 November 2026** | Published at aria.bar/spec; the edition of ARIA 1.0 | The 7 September text with §3, §5, §6, §7 and §8 revised as TLF adopted them (decision D7): issuance under the federation contract 1.0.0 with one `_aria-bind` record per account and domain; both signature halves required for as long as a credential is valid, judged as one; scopes of three segments in new issuance (D5); the holder key in ARIA's own encoding (D6); human approval refused when missing; a signed status list valid 24 hours and re-signed hourly; ARIA AP as the admission protocol, with ATP/1 kept as a deprecated appendix |
| **7 September 2026** | Superseded by the edition of 1 November 2026 | The text as first released |

The release manifest of ARIA 1.0 names the edition it ships with and pins the text by
hash. Where the text and a schema disagree, the schema is right and the text is a bug.

## Artefacts

| Artefact | Where |
|---|---|
| AID schema (`legalName` is an organization name; natural persons never populate it) | [`../schema/aid-1.0.json`](../schema/aid-1.0.json) |
| AID schema for credentials issued before the cutover (`spec_version` 1.2); stays published while any is in circulation | [`../schema/aid-v1.2.json`](../schema/aid-v1.2.json) |
| ARIA AP: receiver identity, receipt and retrieval schemas | [`../schema/`](../schema/README.md) (`aria-ap-*.json`) |
| An issuer's published key set | [`../schema/aria-keyset-1.json`](../schema/aria-keyset-1.json) |
| Federation contract (registration authority → authority), 1.0.0 | [`../federation/openapi.yaml`](../federation/openapi.yaml), [`../federation/exchange.schema.json`](../federation/exchange.schema.json) |
| JSON-LD context | [`../context/v1.jsonld`](../context/v1.jsonld) |
| Conformance vectors and harnesses | [`../conformance/`](../conformance/) |
| The invariants that cannot change | [`../INVARIANTS.md`](../INVARIANTS.md) |
| What 1.0 retires | [`../DEPRECATIONS.md`](../DEPRECATIONS.md) |
| Historical: ATP policy and intent declaration (deprecated), enrollment manifest (v1.2 flow) | [`../schema/`](../schema/README.md) |

The 7 September edition took the **Verification Requirements** (80 citable
requirements, arbitrated August 31, 2026) as the normative basis for the trust levels;
they are summarized at aria.bar/spec §2 and Appendix E. Its ATP/1 text (§8) is kept as
history.
