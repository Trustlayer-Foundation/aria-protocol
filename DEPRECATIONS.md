# Deprecations

What ARIA 1.0 retires, why, and what replaces it. Nothing here breaks a credential
already issued: issued credentials carry their own version and remain valid against it.

| Item | Status in 1.0 | Why | Replacement |
|---|---|---|---|
| `principal.legalName` for natural-person principals | **Deprecated.** MUST NOT be populated. | The public AID never carries a natural person's name (`COM-09`, `L0-03`). | Organization name only. The person behind an L1+ credential is verified by the registry and recorded in its Case File, never in the AID. |
| Version labels `1.0` / `1.1` / `1.2` (April–August 2026) | **Reclassified as public previews.** | No production adoption; the stable line starts at 1.0 (September 7, 2026). | Regime is distinguished by **issuer DID**, not by `spec_version`. Preview credentials are sunset at cutover. |
| `schema/aid-v1.1.json`, `schema/aid-v1.2.json` file names | **Preview line.** Kept for verifiers of issued credentials. | The 1.0 stable schema adopts the v1.2 shape with the `legalName` rule above. | `schema/aid-1.0.json` at cutover. |
| ATP `qualify=` | **Reserved.** Never evaluated in ATP/1. | Depends on Trust Seals (spec §26), not implemented. | Processors treat it by the unknown-parameter rule (§3). `ATP-460` reserved accordingly. |
| ATP `ttl=` | **Removed from the normative set.** | Cache lifetime is not a policy statement. | `fresh=` bounds status-evidence age; DNS TTL governs record caching. |
| ATP `rate=` as an admission criterion | **Informative only.** | Rate enforcement is receiver infrastructure; its state is not part of admission. | `ATP-429` is emitted outside the algorithm. |
| Dotted / two-segment scopes (`commerce.*`, `finance:*`) | **Invalid.** | ATP/1 §5 grammar: three colon-separated segments, wildcard only in the last. | `commerce:order:*`, `finance:invoice:read`. |
| `_aria-enroll.` and `_aria-challenge.` TXT records | **Ephemeral, out of scope.** Not anchors, not policy. | Enrollment-time proof of domain control, equivalent to `_acme-challenge.`; retired after issuance. | Anchor: `_aria.<domain>`. Policy: `_aria-policy.<host>`. Recommendation to the protocol: one ephemeral family, registered with IANA alongside the two permanent ones. |
| `.well-known/aria-atp` as a policy location | **Not part of ATP/1.** | The policy lives in DNS and only in DNS; a second location without precedence is a second source of truth (ATP/1 §1). | `_aria-policy.<host>` TXT. Removal from the reference implementation is a backend task. |
| MCP resources `aria://spec/v1.1`, `aria://spec/v1.0` | **Preview-line URIs, still served.** | They name what the deployed server registers today. | ARIA 1.0 text and per-DID audit resources are [PLANNED]. |
| "StatusList 2021" naming | **Replaced.** | The Recommendation is W3C Bitstring Status List v1.0 (May 2025). | Bitstring Status List v1.0. |
| IAL/AAL badges per level; "Extended Validation" / "Beyond EV"; named entity-credential schemes | **Removed.** | Neutrality (Arbitration A5) and no-conformance-claim rule. | Aligned to NIST SP 800-63A-4, no conformance claimed; TLS analogies self-signed / DV / OV / EV+; equivalence by properties under TLF's acceptance list. |
