# Changelog

All notable changes to the ARIA Protocol specification.

> **ARIA 1.0 (September 7, 2026) is the first stable release.** Everything before it
> was pre-release; see "Before 1.0" at the end of this file.

## [1.0.0] — September 7, 2026 — first stable release

### Repository
- **History consolidated.** The development history before 1.0 was replaced by a
  single signed baseline commit; its history is archived off-repository. Commit
  identifiers from that line no longer resolve on `main`. The earlier `v1.0` tag and its April
  release were retired: keeping them would have kept the pre-release history reachable,
  which is what the consolidation set out to end.
- **Branch model.** `main` is what is published, reached only by a release pull request
  from `dev`. Everything lands on `dev` first, by reviewed pull request. Both branches are
  protected with no bypass.
- **Continuous integration.** SDK tests, a Developer Certificate of Origin and tool-trailer
  guard, a scheme-neutrality guard and a branch-name check run on every pull request. The
  conformance harness is advisory until it exists; it is the first change to land on `dev`.
- **Contribution.** Anyone may contribute, with their own identity and a sign-off; tool
  trailers are refused. Approval is concentrated in one Code Owner until the Technical
  Steering Committee is seated — declared in `GOVERNANCE.md` rather than left implicit.

### Repository hygiene for 1.0
- **One version, one primary schema.** `schema/aid-1.0.json` (`spec_version` const `"1.0"`,
  `legalName` rule) is the ARIA 1.0 schema; `examples/aid-example.json` its example.
  `schema/aid-v1.2.json` stays published for the credentials in circulation that declare
  it (see INVARIANTS §1); the never-issued draft schema and the earlier example are
  removed; `spec/legacy/` prose is archived off-repository.
- **SDK fixtures regenerated** with `spec_version: "1.0"` and the test keys; the
  compatibility fixture is named for what it is (`valid-aid-pre-cutover.json`).
- **Composite AND proven by test.** `test/vector11.test.ts` (ATP/1 conformance vector 11):
  a credential with one tampered signature half is rejected in both directions. 45 tests.
- **ATP artefacts aligned with ATP/1.** `schema/atp-policy-v1.json` drops `qualify`/`ttl`,
  adds `fresh`, requires `enforce`, three-segment scopes; `examples/atp-policy-example.txt`
  rewritten; `intent-declaration-v1.json` fixes `principal_ref` to a DID;
  `enrollment-manifest-v1.json` describes the ARIA canonical JSON, not JCS.

### Fixed
- **Scheme names removed from the SDK and the schemas.** A policy preset comment claimed an
  identity-assurance-level equivalence, and the `verificationStatus` documentation in
  `types.ts` and in the three AID schemas named a commercial entity-credential scheme as
  the example of an authoritative registry. Both now describe the property: confirmation
  against the Authoritative Source of the jurisdiction of incorporation. Schema
  descriptions only — no validation rule changed, and no issued credential is affected.
- **Retired Recommendation name.** Schema descriptions said "StatusList 2021"; the
  Recommendation is W3C Bitstring Status List v1.0.

### Invariants
- **Canonicalisation is not JCS.** Invariant 3 claimed RFC 8785. The implementation sorts
  keys by UTF-16 code unit with `JSON.stringify` escaping; the two agree for every AID
  issued to date and diverge on non-ASCII keys and floating-point numbers. The invariant
  now says what the vectors fix, because credentials already signed cannot be re-signed.
- **The issuer is not a fixed string.** Invariant 11 named `did:aria:registry.aria.bar`.
  It now says the issuer is the one named in the accreditation list TrustLayer Foundation
  signs — today that registry, TLF from the issuance cutover.
- **`aid-1.0.json` does not exist yet.** Invariant 1 no longer implies it does: the stable
  schema is re-cut at the cutover, when credentials begin to declare `spec_version: "1.0"`.

### Documentation
- **Every document in the repository read against the published site.** The SDK README,
  which is the npm front page, claimed the wrong minimum trust level for two policy
  presets (FINANCIAL is L2 and SOVEREIGN is L3, not L1 and L2), presented the presets as
  based on named regulatory standards, showed `maxOfflineAge: null` — the setting that
  lets a revoked credential keep passing — as an example, named a real company as the
  impersonation example, and said nothing about revocation on the page where a reader
  decides whether to trust `valid`. All corrected, and the levels now carry `[PLANNED]`
  because only L0 is issued.
- **`conformance/README.md` described files that do not exist** (`manifest-validation.json`,
  a `harness/` directory) and claimed the case set "already keeps four independent SDK
  implementations producing byte-identical canonical JSON". There is one published SDK.
  The missing vectors are now listed as missing, including the composite-signature case.
- `spec/README.md` said 27 sections and pointed at §02 and §05; the specification has 12
  normative sections and 5 appendices, and ATP is §8. `DEPRECATIONS.md` pointed Trust
  Seals at §26, retired in the restructure; it is Appendix C. `SECURITY.md` said the
  Technical Steering Committee ratifies emergency fixes; it is not seated until Q4 2026,
  so it says who does today.
- README says "verify a credential", not "verify an agent", and states what the SDK does
  not do: it never checks revocation (`revocationStatus` comes back `unknown` and the
  credential passes) and it does not resolve DIDs.

### Normative basis
- The **Verification Requirements** (80 citable requirements, arbitrated August 31, 2026)
  become the normative basis for the trust levels. Each level card quotes its requirement
  IDs. Only standards and public governance sources are named; no vendors.

### Changed
- **Trust levels redefined and derived from evidence.** L1 requires a verified natural
  person (ICAO 9303 document, ISO/IEC 30107-3 liveness, biometric match, age of majority,
  consent, human review, assisted path) plus domain control over DoH (RFC 8484) with RDAP
  cross-check — **not automatic**. L2 confirms the entity against its Authoritative Source
  (Route A direct / Route B documentary with ≥20 % spot-check; Class 3 jurisdictions cap
  at L1), links the person to the entity and screens OFAC/EU/UN lists ≤7 days old. L3
  requires a Binding Officer by public instrument, keys in FIPS 140-3 level 2+ (CMVP) or
  CC EAL4+ hardware (**MUST**, previously "recommended"), a named human approval and a
  signed accountability agreement. TLS analogies: self-signed / DV / **OV** / **EV+**.
- **Scheme neutrality.** All references to named entity-credential schemes and IDV vendors
  removed from normative and descriptive text. Equivalence is defined by properties: a
  credential or identifier verifiable to a root of trust, non-revoked, fully corroborated,
  under a scheme on TLF's acceptance list (separate, revisable document).
- **No per-level IAL/AAL badges.** Single statement: aligned to NIST SP 800-63A-4; no
  conformance assessment is claimed. No "satisfies" / "safe harbor" language.
- **ATP/1.** Formal ABNF; three-segment colon-separated scopes with a trailing-only
  wildcard; parameter classes (normative / informative / reserved); `fresh=` (default
  3600 s, floor 60 s — the receiver-side consumer of the ≤60 s revocation budget);
  `enforce=` mandatory in a published record; `!param` critical marker; `rate=`
  informative and outside the algorithm; `qualify=` and `ttl=` removed from the
  normative set (see DEPRECATIONS). Codes added: `ATP-410`, `ATP-412`, `ATP-421`;
  `ATP-429` moved outside the algorithm; `ATP-460` reserved; a literal `reason`
  accompanies every result. `principal_ref` is a DID, never a name (ATP-13).
- **did:aria §03.5** expanded into full Create / Read / Update / Deactivate algorithms
  with error conditions and resolution metadata.
- **Issuer.** Under 1.0 the issuer of record is TrustLayer Foundation; registries attest
  under their own signature and TLF signs on that attestation (CA/RA model).
- W3C **Bitstring Status List v1.0** (Recommendation, May 2025) replaces every
  "StatusList 2021" reference.
- EU AI Act article numbers aligned to Regulation (EU) 2024/1689 (Art. 14, 50, 72, 99).
  Colorado SB 24-205 recorded as replaced by SB 26-189 (effective January 1, 2027).

### Deprecated
- `principal.legalName` for natural-person principals (COM-09, L0-03). See DEPRECATIONS.md.

### Planned (not shipped in 1.0)
- Issuance cutover to `spec_version: "1.0"` under a TLF issuer DID.
- CAEP push revocation, ML-KEM-768, SLH-DSA, Shamir key recovery, Agent Interaction Log,
  Python and Rust verifier SDKs.

## Before 1.0 (pre-release)

Everything below predates the first stable release. The labels `1.0`–`1.2` shipped
between April and August 2026 were public previews with no production adoption;
`[1.3.0]`–`[1.6.0]` were pre-launch internal iterations. Kept as the record of what
happened; none of it is the current version.

## [1.2.0] — June 2026 — public preview

### Added
- `credentialSubject.holderKey` (required) — Ed25519 holder verification key bound to the AID, sealed inside the post-quantum proof. The corresponding private key is generated by the SDK on the agent's machine and is never transmitted to the registry. Presenters demonstrate possession by signing a compact holder proof over canonical JSON; verifiers extract `holderKey` from the signed credential and check the proof against it. Closes the bearer-credential gap of v1.x — a leaked AID is no longer sufficient to impersonate the agent without the holder secret.
- `credentialSubject.enrollmentAttestation` (required) — declarative record of the authenticated enrollment that produced this AID, including the immutable Terms of Service and Privacy Policy versions accepted by the principal at enrollment time. Anchors the bilateral contract under applicable electronic-signature law.
- `credentialSubject.alsoKnownAs` (optional) — list of external DIDs (e.g. `did:web`, `did:key`) declared at enrollment, each accompanied by a proof-of-control verified by the registry. In v1.2 these declarations are DORMANT for trust decisions; activation is on the v1.3 roadmap.
- `schema/enrollment-manifest-v1.json` — self-signed manifest constructed by the SDK during enrollment. Submitted to `POST /v1/enrollment/submit` and validated against a ten-step check sequence (magic token, DNS proof, DNSSEC, identity commitment, etc.) before the enrollment can advance to admin 2FA. Archived in the audit log; not embedded in the issued AID.
- `examples/aid-example-v1.2.json` — reference AID conformant to v1.2 with holder key, enrollment attestation, and a signed presentation example.
- `examples/holder-proof-example.json` — reference Ed25519 holder proof over canonical JSON, demonstrating the verification flow against a `holderKey` extracted from a signed AID.

### Changed
- `spec_version` const: `1.1` → `1.2`. AIDs claiming conformance to v1.2 MUST include both `holderKey` and `enrollmentAttestation`. Existing v1.1 AIDs remain valid against the v1.1 schema.
- `credentialSubject.id` regex now accepts the registry-namespaced fallback `did:aria:{registry-host}:{principal-short-id}:{agent-name}` in addition to the verified-domain form `did:aria:{verified-domain}:{agent-name}`. The fallback enables enrollment under the registry's own domain for principals that have not yet completed DNS verification of their own domain.

### Migration notes
- v1.1 AIDs do not need to be reissued to continue functioning. Holder-binding and enrollment attestation activate at the next reissuance of each AID under v1.2.
- Verifiers updated to v1.2 SHOULD reject v1.2 AIDs that arrive without a valid holder proof; they SHOULD continue to accept v1.1 AIDs without one for backward compatibility during the transition.

## [1.1.0] — April 27-28, 2026 — public preview

### Added
- `principal.verificationStatus` (required) — machine-readable provenance of `principal.legalName`. Enum: `self-declared` (L0, L1), `registry-confirmed` (L2), `legal-verified` (L3). Closes the L1 brand-impersonation gap surfaced in the April 14 adversarial audit: a verifier can now reject AIDs whose org name was self-asserted without consulting trustLevel separately.
- `credentialSubject.previousCredentialId` (optional) — URL of the prior AID instance superseded by this one. Enables explicit, signed chain-of-issuance: a verifier holding a current AID can walk backwards through the issuance history. Omitted on first issuance.

### Changed
- `spec_version` const: `1.0` → `1.1`. AIDs claiming conformance to v1.1 MUST include `principal.verificationStatus`. Existing v1.0 AIDs remain valid against the v1.0 schema; v1.1 verifiers SHOULD treat a missing `verificationStatus` as `self-declared`.
- **Top-level `id` is now a unique credential-instance URL per W3C VC 2.0 §4.4** (e.g. `https://api.aria.bar/v1/credentials/{uuidv7}`). Previously the schema reused the agent DID for both the credential `id` and `credentialSubject.id`, which conflated the credential instance with its subject. The agent DID continues to live in `credentialSubject.id` (stable across reissuances). The new top-level `id` is the equivalent of a TLS certificate serial number — unique per issuance, dereferenceable, signed inside the proof.

### Migration notes
- v1.0 AIDs with `id: "did:aria:..."` will not match the v1.1 schema regex for top-level `id`. Reissuance produces a v1.1-conformant AID. v1.0 verifiers continue to accept their own AIDs.
- Implementations SHOULD use UUIDv7 (RFC 9562) for the credential identifier so issuances are chronologically ordered.

## [1.6.0] — April 1, 2026 — public preview (labeled 1.0 at launch)

### Fixed
- B-01: L0 trust level no longer requires DNS (crypto keypair only)
- B-02: Trust Ledger scoped to credential lifecycle events only
- B-03: §09 Trust Ledger definition — removed ATP event overclaims
- B-04: ATP Phase 3 references Agent Interaction Log (future), not Trust Ledger
- B-05: ATP warn mode — references Agent Interaction Log
- B-06: Added qualify= and ttl= to ATP DNS tag table
- B-07: DID CREATE — L0 does not create DNS record (L1+ only)
- B-08: Auth Factor 1 (DNS domain control) applies to L1+, not L0
- B-09: "CTL records" → "Trust Ledger records" in §18
- B-10: §20 Audit — scoped to lifecycle events, ATP rows removed
- B-11: Scope format harmonized to "namespace:resource:action"
- B-12: ATP §XX.5 renamed to "Agent Interaction Log [PLANNED]"
- B-13: Removed pricing from spec (pricing does not belong in protocol spec)
- B-14: Glossary — 6 definitions corrected for Trust Ledger scope

### Added
- N-01: Three-role identity model (Registrant, Principal, Account Admin)
- N-02: Colorado AI Act SB 205 mapping, AAL column, EU AI Act 5-obligation mapping
- N-03: HITL tiers connected to EU AI Act Article 13 human oversight
- N-04: Trust Seals — three categories (Sector, Compliance, Capability)
- N-05: Insurance framework note (qualify=insured)

### Verified
- V-01: SDK status — TypeScript live, Python/Go [PLANNED Q2 2026]
- V-02: All resolver.aria.bar references changed to api.aria.bar
- V-03: @context URL updated to aria.bar/ns/v1.0, spec_version = 1.6

## [1.5.0] — March 23, 2026

### Added
- Agent Trust Protocol (ATP) — three-phase handshake (Declare, Evaluate, Admit)
- ATP DNS record format (_aria-policy.<domain>)
- ATP response codes (200, 401, 403, 406, 429, 451, 460, 462)
- Intent Declaration schema (purpose, principal_ref, action_requested, etc.)
- Trust Ledger terminology (replaces Credential Transparency Log)
- Trust Record terminology (single entry in Trust Ledger)
- Enforcement modes: monitor, warn, strict
- Credential states: active, suspended, revoked, expired, tombstoned, superseded

### Changed
- §11 Intent Architecture absorbed into ATP §XX.1
- §18 Counterparty Policy Declaration absorbed into ATP §XX.2

## [1.4.0] — March 20, 2026

### Changed
- Cryptography: adopted composite AND model (ML-DSA-65 + Ed25519)
- Trust levels: adopted operational verification ladder (email → DNS → legal)
- Scopes: adopted 8 immutable actions model
- DNS re-verification aligned with CA/B Forum SC-081v3

## [1.3.0] — March 9, 2026

- Initial specification filed with NIST (NIST-2025-0035)
