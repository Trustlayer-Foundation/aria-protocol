# Deprecations

What ARIA 1.0 retires, why, and what replaces it. Nothing here breaks a credential
already issued: an issued credential carries its own `spec_version` and remains valid against the schema it was issued under.

| Item | Status in 1.0 | Why | Replacement |
|---|---|---|---|
| `principal.legalName` for natural-person principals | **Deprecated.** MUST NOT be populated. | The public AID never carries a natural person's name (`COM-09`, `L0-03`). | Organization name only. The person behind an L1+ credential is verified by the registry and recorded in its Case File, never in the AID. |
| `schema/aid-v1.2.json` and `examples/aid-example-v1.2.json` | **Kept, not the 1.0 schema.** | Credentials in circulation declare `spec_version: "1.2"` and validate against it; the path is cited from the W3C DID Method Registry. | Removed only when the last such credential expires or is revoked. |
| ATP `qualify=` | **Reserved.** Never evaluated in ATP/1. | Depends on Trust Seals (spec Appendix C), not implemented. | Processors treat it by the unknown-parameter rule (§3). `ATP-460` reserved accordingly. |
| ATP `ttl=` | **Removed from the normative set.** | Cache lifetime is not a policy statement. | `fresh=` bounds status-evidence age; DNS TTL governs record caching. |
| ATP `rate=` as an admission criterion | **Informative only.** | Rate enforcement is receiver infrastructure; its state is not part of admission. | `ATP-429` is emitted outside the algorithm. |
| Dotted / two-segment scopes (`commerce.*`, `finance:*`) | **Invalid.** | ATP/1 §5 grammar: three colon-separated segments, wildcard only in the last. | `commerce:order:*`, `finance:invoice:read`. |
| `_aria-enroll.` and `_aria-challenge.` TXT records | **Ephemeral, out of scope.** Not anchors, not policy. | Enrollment-time proof of domain control, equivalent to `_acme-challenge.`; retired after issuance. | Anchor: `_aria.<domain>`. Policy: `_aria-policy.<host>`. Recommendation to the protocol: one ephemeral family, registered with IANA alongside the two permanent ones. |
| `.well-known/aria-atp` as a policy location | **Not part of ATP/1.** | The policy lives in DNS and only in DNS; a second location without precedence is a second source of truth (ATP/1 §1). | `_aria-policy.<host>` TXT. Removal from the reference implementation is a backend task. |
| MCP resources `aria://spec/v1.1`, `aria://spec/v1.0` | **Still served by the deployed server.** | They are the resource URIs the running server registers today. | Resources named for ARIA 1.0 and per-DID audit resources are [PLANNED]. |
| "StatusList 2021" naming | **Replaced.** | The Recommendation is W3C Bitstring Status List v1.0 (May 2025). | Bitstring Status List v1.0. |
| IAL/AAL badges per level; "Extended Validation" / "Beyond EV"; named entity-credential schemes | **Removed.** | Neutrality (Arbitration A5) and no-conformance-claim rule. | Aligned to NIST SP 800-63A-4, no conformance claimed; TLS analogies self-signed / DV / OV / EV+; equivalence by properties under TLF's acceptance list. |
