# ARIA Protocol

**Agent Registry for Identity & Authorization**

The open protocol for AI agent identity. DNS-anchored. Post-quantum native. Governed by a nonprofit.

ARIA here means Agent Registry for Identity & Authorization. It is unrelated to WAI-ARIA (accessibility).

[![Protocol Version](https://img.shields.io/badge/protocol-1.0.0-00D4AA)](https://aria.bar/spec)
[![ci](https://github.com/trustlayer-foundation/aria-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/trustlayer-foundation/aria-protocol/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE-code)
[![License: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-blue)](LICENSE-docs)
[![NIST Filing](https://img.shields.io/badge/NIST-2025--0035-orange)](https://aria.bar/nist)
[![npm](https://img.shields.io/npm/v/@aria-registry/verify)](https://www.npmjs.com/package/@aria-registry/verify)

---

## Versions

**ARIA 1.0 — first stable release — September 7, 2026.** Verification Requirements
(80 citable requirements) as the normative basis, four levels redefined and derived
from evidence, ATP/1, issuer = TrustLayer Foundation. The canonical text is
[aria.bar/spec](https://aria.bar/spec). Tagged `v1.0.0`. The schema files
keep their preview names until the issuance cutover re-cuts them for the stable
line; see [DEPRECATIONS.md](DEPRECATIONS.md).

**Public previews (no production adoption):** April 1, 2026 (labeled 1.0) · April 28
(1.1) · May (1.2). Their texts are kept under [`spec/legacy/`](spec/legacy/). Preview
credentials are distinguished by issuer DID and are sunset at cutover. External
references to 1.1/1.2 — the W3C CG thread, the FIDES submission, npm
`@aria-registry/verify` 1.x — refer to the preview line.

**[PLANNED] Issuance cutover.** Credentials under ARIA 1.0 will carry
`spec_version: "1.0"` and be issued by TrustLayer Foundation (issuer DID TBD). Until
then, preview credentials remain resolvable and are distinguished by their issuer.

## What is ARIA?

ARIA gives AI agents a verifiable, cryptographically signed identity — a passport for the agentic web.

Every agent gets a DID (`did:aria:*`), a trust level (L0–L3), a set of scopes defining what it can do, and a signed credential (AID) that any system can verify offline using post-quantum cryptography.

**The Agent Trust Protocol (ATP)** defines how receiving systems evaluate agent credentials against published DNS policies — like DMARC for AI agents.

## Quick links

| Resource | URL |
|----------|-----|
| **Live spec** | [aria.bar/spec](https://aria.bar/spec) |
| **API (public, no auth)** | [api.aria.bar](https://api.aria.bar) |
| **Registry (sign up)** | [registry.aria.bar](https://registry.aria.bar) |
| **SDK (npm)** | [@aria-registry/verify](https://www.npmjs.com/package/@aria-registry/verify) |
| **NIST filing** | NIST-2025-0035, March 9, 2026 |
| **NCCoE response** | AI-Identity@nist.gov, April 2, 2026 |

## Verify a credential in 3 lines

```bash
npm install @aria-registry/verify
```

```typescript
import { verifyAgent } from '@aria-registry/verify';

const result = await verifyAgent(credential);
console.log(result.valid, result.did, result.trustLevel);
```

**What this checks, and what it does not.** `verifyAgent()` verifies the composite
signature — ML-DSA-65 and Ed25519, both halves must pass — the validity window, the
trust level and the provenance of the principal's name. It does **not** check
revocation: `revocationStatus` comes back `'unknown'` and the credential passes.
Revocation is a separate, networked call, `checkRevocation(did)`, and it is enforced
only under a policy that requires it. Read
[INVARIANTS.md](INVARIANTS.md#not-an-invariant-but-a-documented-default) before you
gate anything on `valid` alone.

**It is a credential verifier, not a DID resolver.** Resolution as the
specification defines it — parse the identifier, follow the DNS pointer, pin the
document against its hash, bind the subject, derive the DID Document — is
`[PLANNED]`; see [spec §3.5.2](https://aria.bar/spec#3-5-2). What the SDK verifies
is a credential you already hold.

Or via API:

```bash
curl https://api.aria.bar/v1/verify/did:aria:aria.bar:u-cmDoHhM3:ordering-agent
```

## Protocol overview

ARIA is a six-layer protocol:

| Layer | Standard | Purpose |
|-------|----------|---------|
| **P1 — Anchor** | W3C DID Core | Every agent gets a DID anchored to DNS |
| **P2 — Certify** | W3C VC Data Model 2.0 | Signed, portable, offline-verifiable credentials |
| **P3 — Present** | OAuth 2.0 + DPoP | How credentials are presented and bound |
| **P4 — Protect** | FIPS 204 + RFC 8032 | ML-DSA-65 + Ed25519 composite signatures |
| **P5 — Revoke** | W3C Bitstring Status List v1.0 | Revocation in under 60 seconds; append-only Trust Ledger |
| **P6 — Govern** | TrustLayer Foundation | Nonprofit stewardship, open source |

## Trust levels

A level is derived from the evidence, never declared. Two independent axes — the
**person** who answers for the agent and the **entity** it represents — and only
standards and public governance sources are named; the specification names no vendors.
Full definitions and requirement IDs: [aria.bar/spec#trust](https://aria.bar/spec#trust).

| Level | Name | Asserts | TLS analogy | Validity | Status |
|-------|------|---------|-------------|----------|--------|
| **L0** | Anchored | Cryptographic existence of the agent. Nothing more; every declared name is self-declared. E-mail challenge + key possession. Automatic. | Self-signed | 366 days | **Live** |
| **L1** | Identified | A verified natural person answers for the agent (ICAO 9303 document, ISO/IEC 30107-3 liveness, biometric match, human review) and the agent controls its domain (DoH + RDAP). **Not automatic.** | DV | 366 days | [PLANNED] |
| **L2** | Certified | L1, plus the entity exists per its Authoritative Source, the person is linked to it, and neither is sanctioned (OFAC/EU/UN ≤7 d). | OV | 200 days | [PLANNED] |
| **L3** | Sovereign | L2, plus a Binding Officer with power to bind the entity, keys in FIPS 140-3 L2+ / CC EAL4+ hardware (MUST), signed accountability. | EV+ | 180 days | [PLANNED] |

## AID schema highlights

Each AID is a W3C Verifiable Credential signed with the composite cryptosuite
(`mldsa65-ed25519-2026`).

**Schema versions in this repo:**

| Version | File | Status | Adds |
|---|---|---|---|
| **1.2** | [`schema/aid-v1.2.json`](schema/aid-v1.2.json) · [`examples/aid-example-v1.2.json`](examples/aid-example-v1.2.json) | **Preview line — current file shape.** ARIA 1.0 adopts this shape with `legalName` deprecated for natural persons (see DEPRECATIONS.md); the file is re-cut as `aid-1.0.json` at cutover. | `credentialSubject.holderKey` (required) — per-agent Ed25519 keypair for proof-of-possession. Eliminates the bearer-credential vulnerability of v1.x. Private key delivered to registrant once; never stored by the registry. See also [`examples/holder-proof-example.json`](examples/holder-proof-example.json). |
| 1.1 | [`schema/aid-v1.1.json`](schema/aid-v1.1.json) · [`examples/aid-example-v1.1.json`](examples/aid-example-v1.1.json) | Preview line — superseded | `principal.verificationStatus`, top-level `id` as credential-instance URL (per W3C VC 2.0 §4.4), `credentialSubject.previousCredentialId`. |

Notable fields:

| Field | Purpose |
|---|---|
| `id` (top-level) | Unique credential-instance URL — `https://api.aria.bar/v1/credentials/{uuidv7}`. New on every issuance. Equivalent to a TLS certificate serial number. Per W3C VC 2.0 §4.4. |
| `credentialSubject.id` | The agent DID (`did:aria:…`). Stable across reissuances. |
| `credentialSubject.spec_version` | `"1.2"` on preview-line credentials issued today; `"1.0"` on ARIA 1.0 credentials after the [PLANNED] cutover. Verifiers distinguish the regime by issuer DID, not by this number. |
| `credentialSubject.holderKey` | **Required (v1.2).** Ed25519 public key (multibase) bound to this AID. Verifiers MUST check a holder proof signed with the corresponding private key. Read the key from this SIGNED field — never from external sources such as a database — to preserve the PQC integrity guarantee. |
| `credentialSubject.previousCredentialId` | URL of the prior credential instance this one supersedes. Optional — omitted on first issuance. Enables explicit, signed chain-of-issuance traceability. |
| `credentialSubject.principal.verificationStatus` | Machine-readable provenance of `principal.legalName`. Enum: `self-declared` (L0, L1), `registry-confirmed` (L2 — confirmed against the Authoritative Source), `legal-verified` (L3 — primary register + Binding Officer). Verifiers MUST consult this before treating `legalName` as authoritative. `legalName` is an **organization** name: natural-person principals MUST NOT populate it (COM-09, L0-03). |
| `credentialSubject.trustLevel` | `L0`–`L3`. |
| `credentialStatus` | W3C Bitstring Status List v1.0 entry — flipped to revoked atomically on every reissue. |
| `proof.proofValue` | Composite ML-DSA-65 + Ed25519 signature; both must verify. Critically, the signature covers `credentialSubject.holderKey` — preventing key substitution by anyone other than the registry. |

## Agent Trust Protocol (ATP)

ATP is the three-phase handshake between an agent and a receiving system:

1. **Declare** — Agent presents AID + intent declaration
2. **Evaluate** — Receiver checks against DNS policy (`_aria-policy.<domain>`)
3. **Admit** — Pass or reject, returned as an ATP response code. The
   admit/reject decision is queued for the Agent Interaction Log (future
   — see spec §05). Credential lifecycle events are recorded separately
   in the Trust Ledger.

```
_aria-policy.bank.com TXT "v=ATP1; min=L2; enforce=strict; req=commerce:order:*,finance:invoice:read; deny=identity:principal:*; intent=purpose,principal_ref; depth=3; fresh=300s; rua=https://bank.com/atp-reports"
```

Enforcement modes: `monitor` → `warn` → `strict` (graduated adoption, like DMARC). Scopes have three colon-separated segments with a wildcard only in the last; `fresh=` bounds the age of status evidence (default 3600 s, floor 60 s); `principal_ref` is a DID, never a name. Full grammar, parameter classes and result codes: [aria.bar/spec#atp](https://aria.bar/spec#atp).

## Cryptography

- **Primary:** ML-DSA-65 (FIPS 204) — post-quantum, lattice-based
- **Classical:** Ed25519 (RFC 8032) — transition signature
- **Mode:** Composite AND — both signatures must verify
- **Suite:** `mldsa65-ed25519-2026`
- **Sunset:** ECDSA/classical-only credentials expire December 31, 2029

## Standards alignment

| Standard | Mapping |
|----------|---------|
| NIST SP 800-63A-4 | Aligned to. No conformance assessment is claimed. |
| FIPS 204 (ML-DSA) | Primary signature algorithm |
| RFC 8032 (Ed25519) | Classical composite signature |
| W3C DID Core | `did:aria` method |
| W3C VC Data Model 2.0 | AID document format |
| CA/B Forum SC-081v3 | L2 credential validity alignment |
| OWASP Agentic Security | Scope containment, delegation ceiling |
| EU AI Act — Regulation (EU) 2024/1689 | Designed to support risk management (Art. 9), human oversight (Art. 14), transparency (Art. 50), post-market monitoring (Art. 72) |
| Colorado SB 24-205, as replaced by SB 26-189 (effective January 1, 2027) | Designed to support notice and record-keeping duties. No legal conclusion is claimed. |

## Governance

ARIA is owned by **TrustLayer Foundation A.C.** (nonprofit) and operated by **TUNO Labs SAPI de CV** (for-profit, licensed).

Same model as Mozilla Foundation / Mozilla Corporation.

- **Spec + SDK:** Apache License 2.0
- **Documentation:** CC BY 4.0
- **Anti-capture clause:** No single entity can control the protocol

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require DCO sign-off.

Until the Technical Steering Committee (TSC) is constituted (target Q4 2026), Aaron Grego and Ivan Moreno Mendoza act as TSC.

## License

Code and reference implementations: [Apache License 2.0](LICENSE-code)

Specification and documentation: [Creative Commons Attribution 4.0](LICENSE-docs)

---

**TrustLayer Foundation A.C.** · [aria.bar](https://aria.bar) · Open standards. Nonprofit governance. Trustworthy AI.

## Identity of this repository

Commits are authored by the identities of the people and the Foundation behind
them, carry a Developer Certificate of Origin sign-off, and never carry tool
trailers: contributors are people with names. Releases on `main` and every `v*`
tag are signed by the Foundation account. How a change gets approved, and when
that stops being one person, is in [GOVERNANCE.md](GOVERNANCE.md).

The public preview line (April–August 2026) was consolidated into a single
baseline commit; its history is archived off-repository. Commit identifiers from
that line no longer resolve on `main`.
