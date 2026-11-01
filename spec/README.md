# Specification

The canonical, normative text of ARIA is published at **[aria.bar/spec](https://aria.bar/spec)**
(12 normative sections and 5 appendices, CC-BY-4.0). This repository holds the
machine-readable artefacts that text refers to, and says which edition of it goes with
what is here.

## Which edition

| Edition | Status | What it covers |
|---|---|---|
| **7 September 2026** | Published at aria.bar/spec; the edition in force | The text as first released. Sections whose claims are under review are marked there: the end of the composite mode in 2029 (§5), per-half signature reporting, scope versions (§6), the three human-approval tiers (§6), revocation in under 60 seconds and freshness (§7), and ATP/1 (§8), now deprecated in favour of ARIA AP |
| **ARIA 1.0, revised** | In preparation; TLF adopts it (decision D7) | The same edition with those sections rewritten to what this repository implements and the owner has decided: ARIA AP over RFC 9421 with one receipt format, refusal without a required approval, explicit trust and a published key set, the federation contract. Proposed texts are prepared; none is adopted |

The release manifest of ARIA 1.0 names the edition it ships with and pins the text by
hash. Until the revised edition is adopted, where the text and this repository
disagree, the schemas and vectors here describe what is implemented, and the
specification's sections marked under review say so.

## Artefacts

| Artefact | Where |
|---|---|
| AID schema (`legalName` is an organization name; natural persons never populate it) | [`../schema/aid-1.0.json`](../schema/aid-1.0.json) |
| AID schema for credentials issued before the cutover (`spec_version` 1.2); stays published while any is in circulation | [`../schema/aid-v1.2.json`](../schema/aid-v1.2.json) |
| ARIA AP: receiver identity, receipt and retrieval schemas | [`../schema/`](../schema/README.md) (`aria-ap-*.json`) |
| An issuer's published key set | [`../schema/aria-keyset-1.json`](../schema/aria-keyset-1.json) |
| Federation contract (registration authority → authority), draft | [`../federation/openapi.yaml`](../federation/openapi.yaml), [`../federation/exchange.schema.json`](../federation/exchange.schema.json) |
| JSON-LD context | [`../context/v1.jsonld`](../context/v1.jsonld) |
| Conformance vectors and harnesses | [`../conformance/`](../conformance/) |
| The invariants that cannot change | [`../INVARIANTS.md`](../INVARIANTS.md) |
| What 1.0 retires | [`../DEPRECATIONS.md`](../DEPRECATIONS.md) |
| Historical: ATP policy and intent declaration (deprecated), enrollment manifest (v1.2 flow) | [`../schema/`](../schema/README.md) |

The 7 September edition took the **Verification Requirements** (80 citable
requirements, arbitrated August 31, 2026) as the normative basis for the trust levels;
they are summarized at aria.bar/spec §2 and Appendix E. Its ATP/1 text (§8) is kept as
history.
