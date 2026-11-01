# ARIA Protocol

**Agent Registry for Identity & Authorization**

The open protocol for AI agent identity. DNS-anchored. Post-quantum native. Governed by a nonprofit.

ARIA here means Agent Registry for Identity & Authorization. It is unrelated to WAI-ARIA (accessibility).

[![Protocol Version](https://img.shields.io/badge/protocol-1.0.0-00D4AA)](https://aria.bar/spec)
[![ci](https://github.com/trustlayer-foundation/aria-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/trustlayer-foundation/aria-protocol/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE-code)
[![License: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-blue)](LICENSE-docs)
[![NIST Filing](https://img.shields.io/badge/NIST-2025--0035-orange)](https://aria.bar/nist)

---

## Version

**ARIA 1.0 is relaunched in this repository, with its history.** Its delivery is one
set: the protocol and the AID 1.0 credential, the **ARIA SDK 1.0.0** and **ARIA AP
1.0.0**, and the schemas, documentation, examples and conformance that go with them.
Both SDKs are **a local candidate: not published and not an approved release**; ARIA
AP's transport and receipt format are decided; its scope grammar and the rest of its
receipt rules are still open. The canonical text is [aria.bar/spec](https://aria.bar/spec). What 1.0 retires and why:
[DEPRECATIONS.md](DEPRECATIONS.md). Earlier artifacts stay only for compatibility, in
[Historical compatibility](#historical-compatibility) below, outside this path.

**[PLANNED] Issuance cutover.** Credentials under ARIA 1.0 carry `spec_version: "1.0"`
and are issued by TrustLayer Foundation (issuer DID TBD). Credentials issued before the
cutover remain resolvable and are distinguished by their issuer DID, never by version.

## What is ARIA?

ARIA gives AI agents a verifiable, cryptographically signed identity — a passport for the agentic web.

Every agent gets a DID (`did:aria:*`), a trust level (L0 live; L1 to L3 planned), the scopes it declares — what it intends to do, which each receiver decides whether to admit — and a signed credential (AID) that any system can verify offline using post-quantum cryptography.

**ARIA AP** is how an agent uses that credential with a service: the agent authenticates
the receiver, signs each request with its holder key, the receiver admits or refuses it,
runs each operation once and signs a receipt, and either side can recover the outcome
after a lost answer. It replaces an earlier admission protocol, now deprecated (see
[Historical compatibility](#historical-compatibility)).

## Quick links

| Resource | URL |
|----------|-----|
| **Live spec** | [aria.bar/spec](https://aria.bar/spec) |
| **API (public, no auth)** | [api.aria.bar](https://api.aria.bar) |
| **Registry (sign up)** | [registry.aria.bar](https://registry.aria.bar) |
| **SDKs** | [ARIA SDK](sdk/aria-ts/README.md) and [ARIA AP](sdk/aria-ap-ts/README.md), 1.0.0, local candidate, not published |
| **NIST filing** | NIST-2025-0035, March 9, 2026 |
| **NCCoE response** | AI-Identity@nist.gov, April 2, 2026 |

## Repository layout

One repository holds the protocol and its SDKs. This is its long-term structure.

| Path | What it is | Status |
|---|---|---|
| `schema/`, `context/` | JSON Schemas and the JSON-LD context; [`schema/README.md`](schema/README.md) says which are active and which historical | Normative; ARIA AP schemas provisional |
| `spec/` | Where the specification stands; its text is authored with [aria.bar/spec](https://aria.bar/spec) today (`spec/README.md`) | |
| `conformance/` | Vectors and harnesses any implementation runs, in any language | `conformance/ap/` (ARIA AP) is provisional |
| `federation/` | The contract between registration authorities and the issuing authority | |
| `examples/` | Reference credentials and usage examples; [`examples/README.md`](examples/README.md) is the index | |
| `sdk/aria-ts/` | **ARIA SDK** (`@aria-registry/sdk`): credential verification and the status of the exact document | 1.0.0, local candidate, not published |
| `sdk/aria-ap-ts/` | **ARIA AP** (`@aria-registry/ap`): receiver identity, signed requests, admission, operations and receipts, built on the ARIA SDK | 1.0.0, local candidate, not published |

The two SDKs are separate packages. A service that only checks credentials installs the
ARIA SDK; one that admits agent requests or exchanges receipts installs ARIA AP as well,
which uses the ARIA SDK's verifier and has no credential verification of its own. Their
package names are provisional; `sdk/scripts/check-pair.mjs` tests them as packed
artifacts, alone and together.

## Verify a credential

With the ARIA SDK (local candidate; build it from `sdk/aria-ts`):

```typescript
import { createVerifier } from '@aria-registry/sdk';

const verifier = createVerifier({ trust, fetch }); // the issuers you trust, and where status may be fetched
const result = verifier.verifyCredential(credential);
if (result.ok) {
  const standing = verifier.standing(result.credential, await verifier.checkStatus(result.credential));
  console.log(result.credential.did, result.credential.trustLevel, standing.state);
}
```

**Trust is yours to state.** The SDK trusts no issuer by default: you give it each issuer you accept, with its keys, the highest level you accept from it and the status lists it may use. A published key set to obtain those keys from is pending.

**What this establishes, and what it does not.** `verifyCredential` checks the AID 1.0
schema, a trusted issuer, the proof profile, both halves of the composite signature
(ML-DSA-65 and Ed25519), the validity window and the holder key. The status of that
exact document is a separate result, and `standing` judges validity and status freshness
when you ask. None of them is permission to act: deciding whether an agent may do
something is ARIA AP's admission. See the [API contract](sdk/aria-ts/API.md).

**It is a credential verifier, not a DID resolver.** Resolution as the
specification defines it — parse the identifier, follow the DNS pointer, pin the
document against its hash, bind the subject, derive the DID Document — is
`[PLANNED]`; see [spec §3.5.2](https://aria.bar/spec#3-5-2). What the SDK verifies
is a credential you already hold.

### Trust from a published key set

An issuer publishes its keys at `/v1/keyset` (schema [`aria-keyset-1.json`](schema/aria-keyset-1.json)),
each with a fingerprint: `sha256:` and the SHA-256 of the canonical JSON of its
`key_id`, `suite` and two public keys. Being listed grants no trust. Pin the
fingerprint you obtained out of band — from the release manifest or the issuer's
documentation — and take the key it names; the fingerprint is recomputed, never read
from the document. **No issuer publishes a key set yet:** the endpoint and the values a
production issuer would publish (decision D2) are pending.

```javascript
import { canonicalJson, createVerifier } from '@aria-registry/sdk';

/** A verifier trusting the key, in an issuer's published key set, that `pinned` names. */
export async function verifierFromKeyset({ keysetUrl, pinned, profile, fetch = globalThis.fetch }) {
  const keyset = await (await fetch(keysetUrl, { redirect: 'error' })).json();
  const entry = keyset.keys.find((k) => k.fingerprint === pinned && k.active_until === null);
  if (!entry) throw new Error('the key set holds no active key with the pinned fingerprint');
  const identity = canonicalJson({
    key_id: entry.key_id,
    suite: entry.suite,
    public_key_mldsa65: entry.public_key_mldsa65,
    public_key_ed25519: entry.public_key_ed25519,
  });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
  if (`sha256:${Buffer.from(digest).toString('hex')}` !== pinned) throw new Error('the pinned key does not match');
  return createVerifier({
    ...profile.verifier, // clock, fetch policy
    trust: [{
      id: profile.id, // 'demo' or 'production': your statement, not the issuer's
      issuer: keyset.issuer,
      verificationMethod: entry.key_id,
      keys: { mldsa65: Buffer.from(entry.public_key_mldsa65, 'hex'), ed25519: Buffer.from(entry.public_key_ed25519, 'hex') },
      maxLevel: profile.maxLevel,
      statusLists: profile.statusLists,
    }],
  });
}
```

The trust profile's name, highest level and status lists stay your statement: the key
set says which keys signed, not what they are worth. This recipe trusts one pinned key;
following a rotation through `introduced_by` is the publishing authority's check today,
not the SDK's: it serves a set only when its first key is the anchor its operator
configured apart and each later key is introduced by the one before.

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
| **P3 — Present** | ARIA AP over RFC 9421 HTTP Message Signatures (provisional) | How credentials are presented and bound to a request |
| **P4 — Protect** | FIPS 204 + RFC 8032 | ML-DSA-65 + Ed25519 composite signatures |
| **P5 — Revoke** | W3C Bitstring Status List v1.0 | Revocation in a signed status list, as fresh as each verifier requires; append-only Trust Ledger |
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
| **L2** | Certified | L1, plus the entity exists per its Authoritative Source, the person is linked to it, and neither appears on OFAC, EU or UN lists screened no older than 7 days. | OV | 200 days | [PLANNED] |
| **L3** | Sovereign | L2, plus a Binding Officer with power to bind the entity, keys in FIPS 140-3 L2+ / CC EAL4+ hardware (MUST), signed accountability. | EV+ | 180 days | [PLANNED] |

## AID schema highlights

Each AID is a W3C Verifiable Credential signed with the composite cryptosuite
(`mldsa65-ed25519-2026`).

**Schema:** [`schema/aid-1.0.json`](schema/aid-1.0.json) — **a draft until the issuance
cutover**, and the file says so: nothing declares `spec_version: "1.0"` yet, the
Verification Requirements it serves are still a draft, and planned fields have no
place in it. Build against it; it freezes the day the first credential declares 1.0.
Example: [`examples/aid-example.json`](examples/aid-example.json) (illustrative; its proof
value is not verifiable).
`credentialSubject.holderKey` is required: a per-agent Ed25519 keypair for
proof-of-possession that eliminates the bearer-credential vulnerability. The controller
generates the keypair on its own machine and only the public half is submitted; the
registry never holds it (spec §3.5.1).

Credentials issued before the cutover use an earlier schema: see
[Historical compatibility](#historical-compatibility).

Notable fields:

| Field | Purpose |
|---|---|
| `id` (top-level) | Unique credential-instance URL — `https://api.aria.bar/v1/credentials/{uuidv7}`. New on every issuance. Equivalent to a TLS certificate serial number. Per W3C VC 2.0 §4.4. |
| `credentialSubject.id` | The agent DID (`did:aria:…`). Stable across reissuances. |
| `credentialSubject.spec_version` | `"1.0"` under ARIA 1.0 (earlier credentials: [Historical compatibility](#historical-compatibility)). Verifiers distinguish the issuance regime by issuer DID, never by this value. |
| `credentialSubject.holderKey` | **Required.** Ed25519 public key (multibase) bound to this AID. Possession is proved by a request ARIA AP signs with the corresponding private key (local candidate, provisional profile). Read the key from this SIGNED field — never from external sources such as a database — to preserve the PQC integrity guarantee. |
| `credentialSubject.previousCredentialId` | URL of the prior credential instance this one supersedes. Optional — omitted on first issuance. Enables explicit, signed chain-of-issuance traceability. |
| `credentialSubject.principal.type` | `Person` (a natural person) or `Organization` (any legal entity), as schema.org types. Decides the next field: an `Organization` carries `legalName`, a `Person` never does. Absent on credentials issued before the field existed; those carry `legalName` whatever the principal was. |
| `credentialSubject.principal.verificationStatus` | Machine-readable provenance of `principal.legalName`. Enum: `self-declared` (L0, L1), `registry-confirmed` (L2 — confirmed against the Authoritative Source), `legal-verified` (L3 — primary register + Binding Officer). Verifiers MUST consult this before treating `legalName` as authoritative. `legalName` is an **organization** name: natural-person principals MUST NOT populate it (COM-09, L0-03). |
| `credentialSubject.trustLevel` | `L0`–`L3`. |
| `credentialStatus` | W3C Bitstring Status List v1.0 entry. The bit is set on every reissue: the superseded instance is no longer active. Superseded and revoked are different states (spec §7) that share one bit. |
| `proof.proofValue` | Composite ML-DSA-65 + Ed25519 signature; both must verify. Critically, the signature covers `credentialSubject.holderKey` — preventing key substitution by anyone other than the registry. |

## ARIA AP

ARIA AP is the exchange between an agent and a receiving service. Its transport and
receipt format are decided; scopes and the rest of the receipt rules are open. When an
operation's scope requires human approval, a missing or invalid approval refuses the
attempt, for now; holding the operation for approval is not supported, and operations
that need no approval are unaffected:

1. **Who is the receiver.** The agent fetches the receiver's signed identity statement,
   with its AID, and checks it against the DID it expects at that origin.
2. **A signed request.** RFC 9421 over the method, target, body digest, operation id,
   the exact credential and the audience, signed with the agent's holder key and a
   single-use challenge from the receiver.
3. **Admission.** The receiver verifies the credential and its current status with the
   ARIA SDK, then checks audience, level, scope, delegation and human approval, then its
   own resource rule. A refusal is a signed receipt for that attempt only.
4. **Once per operation.** An admitted operation is claimed and settled with a signed
   `aria-ap-receipt/1` in the adopter's storage, in the same transaction as its effect;
   retries of the same operation get the original receipt. An effect outside that
   transaction runs once only with an adapter that guarantees it; an uncertain failure
   otherwise keeps the operation locked rather than allowing a second execution.
5. **Recovery.** After a lost answer, a signed lookup returns the operation's receipts.

Reference: [ARIA AP API contract](sdk/aria-ap-ts/API.md), schemas
[`schema/aria-ap-*.json`](schema/README.md), vectors [`conformance/ap`](conformance/ap/README.md).

## Cryptography

- **Primary:** ML-DSA-65 (FIPS 204) — post-quantum, lattice-based
- **Classical:** Ed25519 (RFC 8032) — transition signature
- **Mode:** Composite AND — both signatures must verify
- **Suite:** `mldsa65-ed25519-2026`
- **Transition:** the specification's plan to end the composite mode on December 31, 2029 is under review by TLF. Until it decides, both halves are required, and no date disables either

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

## Historical compatibility

Kept only so that what was issued or published keeps working. None of it is part of the
ARIA 1.0 path above, and none of it is renumbered or rewritten: these files stay as they
were published. Why each is retired, and what replaces it: [DEPRECATIONS.md](DEPRECATIONS.md).

| Artifact | Why it stays | Until |
|---|---|---|
| [`schema/aid-v1.2.json`](schema/aid-v1.2.json), [`examples/aid-example-v1.2.json`](examples/aid-example-v1.2.json), `conformance/vectors/aid-v1.2-shape.json` | Credentials issued before the cutover declare `spec_version: "1.2"` inside their signed bytes and validate against this schema; its path is cited from the W3C DID Method Registry | The last such credential expires or is revoked |
| [`sdk/verify-ts/`](sdk/verify-ts/README.md) (`@aria-registry/verify` 1.x, published on npm), [`examples/verify-example.ts`](examples/verify-example.ts) | Applications pin published versions | A deprecation on npm, which has not been done |
| [`schema/atp-policy-v1.json`](schema/atp-policy-v1.json), [`schema/intent-declaration-v1.json`](schema/intent-declaration-v1.json), [`examples/atp-policy-example.txt`](examples/atp-policy-example.txt), the `_aria-policy` record `v=ATP1`, the `ATP-…` codes | Their identifiers were published; ATP is deprecated in favour of ARIA AP | A compatibility decision for each identifier |

**The edition of September 7, 2026** (tagged `v1.0.0`) used Verification Requirements
(80 citable requirements) as the normative basis, four levels derived from evidence,
ATP/1 and TrustLayer Foundation as issuer. Development history before it is archived
off-repository and summarized in [CHANGELOG.md](CHANGELOG.md).

**`@aria-registry/verify` 1.x.** `verifyAgent()` verifies the composite signature, the
validity window, the trust level and the provenance of the principal's name. It does
**not** check revocation: `revocationStatus` comes back `'unknown'` and the credential
passes. Read [INVARIANTS.md](INVARIANTS.md#not-an-invariant-but-a-documented-default)
before you gate anything on `valid` alone. The migration to the two SDKs is in
[`sdk/aria-ts/MIGRATION.md`](sdk/aria-ts/MIGRATION.md).

### ATP/1 (deprecated in favour of ARIA AP)

ATP was the three-phase handshake between an agent and a receiving system:

1. **Declare** — Agent presents AID + intent declaration
2. **Evaluate** — the receiver checks against its configured policy: the one it publishes at `_aria-policy.<host>`
3. **Admit** — Pass or reject, returned as an ATP response code. The
   admit/reject decision is queued for the Agent Interaction Log, which is
   `[PLANNED]` — see spec §7. Credential lifecycle events are recorded
   separately in the Trust Ledger.

```
_aria-policy.bank.com TXT "v=ATP1; min=L2; enforce=strict; req=commerce:order:*,finance:invoice:read; deny=identity:principal:*; intent=purpose,principal_ref; depth=3; fresh=300s; rua=https://bank.com/atp-reports"
```

Enforcement modes: `monitor` → `warn` → `strict` (graduated adoption, like DMARC). Scopes have three colon-separated segments with a wildcard only in the last; `fresh=` bounds the age of status evidence (default 3600 s, floor 60 s); `principal_ref` is a DID, never a name. Full grammar, parameter classes and result codes: [aria.bar/spec#atp](https://aria.bar/spec#atp).

## Identity of this repository

Commits are authored by the identities of the people and the Foundation behind
them, carry a Developer Certificate of Origin sign-off, and never carry tool
trailers: contributors are people with names. Releases on `main` and every `v*`
tag are signed by the Foundation account. How a change gets approved, and when
that stops being one person, is in [GOVERNANCE.md](GOVERNANCE.md).

The development history before 1.0 was consolidated into a single signed baseline
commit and is archived off-repository. Earlier commit identifiers do not resolve on
`main`.
