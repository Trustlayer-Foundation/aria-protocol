# ARIA Protocol — Invariants

> **Status:** published, and normative for this repository. Where an invariant and
> the specification at [aria.bar/spec](https://aria.bar/spec) disagree, the
> specification wins on protocol semantics and the invariant is a bug.

This document records the parts of ARIA that **cannot change**, and what breaks if
they do. It exists because ARIA has credentials in the wild: every AID already
issued carries paths, identifiers and formats baked into signed bytes that no
future release can revise.

An invariant here is not a preference. It is a promise that has already been made
to holders of issued credentials, to implementers reading the published spec, and
to the W3C DID Method Registry.

---

## The rule that governs the rest

**The schema is the authority. The prose is description.**

When the schema file for a credential's `spec_version` and any human-readable text disagree, the schema wins
and the text is a bug. This has been load-bearing in practice: a field-by-field
comparison in August 2026 found ~25 divergences between the published prose example
and what production issues, while the schema itself had never drifted.

---

## 1 · The AID credential shape

`schema/aid-1.0.json` defines the shape of an ARIA 1.0 credential: `spec_version: "1.0"`,
a required `credentialSubject.holderKey`, and `principal.legalName` as an organization
name that MUST NOT be populated for a natural-person principal (`COM-09`, `L0-03`).
Every issued credential validates against the schema for the `spec_version` it declares
and is never reissued when a later schema lands. Two schema files are therefore
published, and both are load-bearing:

| File | Validates | Published until |
|---|---|---|
| `schema/aid-1.0.json` | credentials declaring `spec_version: "1.0"` (ARIA 1.0 issuance) | — |
| `schema/aid-v1.2.json` | credentials declaring `spec_version: "1.2"`, issued before the cutover; the path is cited from the W3C DID Method Registry | the last such credential expires or is revoked |

A schema is not history: it is the validation authority for what is in circulation, and
it stays at its path for as long as anything declares it.

Published, registered with INDAUTOR, and referenced from the `did:aria` entry filed
with the W3C DID Method Registry.

**`aid-1.0.json` is a draft until the issuance cutover, and says so in the file.** Nothing
declares `spec_version: "1.0"` yet; the Verification Requirements it serves are still
v1.3-draft with ten decisions open at TrustLayer Foundation; and fields already planned,
a designated successor principal among them, have no place in it. Since
`credentialSubject` declares `additionalProperties: false`, admitting one of them later
means a new file and a new `spec_version`. It is published so implementers can build
against it, and it freezes the day the first credential declares 1.0 — not before.

**Breaks if:** a required field is changed, renamed, or removed.

**Versioning:** additive change is impossible within a version, because
`credentialSubject` and `enrollmentAttestation` both declare
`additionalProperties: false`. A new field therefore means a new schema file and a new
`spec_version`. Credentials issued under an earlier version remain valid against their
own schema and are not reissued.

## 2 · Signature suite `mldsa65-ed25519-2026`

Composite ML-DSA-65 (FIPS 204) + Ed25519 (RFC 8032). Both halves must verify; there
is no degraded mode that accepts one.

**Breaks if:** the algorithm, the encoding, or the suite identifier changes.

## 3 · Canonical JSON — the ARIA canonicalisation

The serialisation used for the identity commitment and for every signature input:
object keys sorted by UTF-16 code unit, `JSON.stringify` escaping, no whitespace,
as `conformance/vectors/canonical-json.json` fixes it.

**This is not JCS.** RFC 8785 additionally specifies number formatting and sorts by
code point; the two agree for every AID issued to date, and diverge on non-ASCII keys
and on floating-point numbers. The invariant is what the vectors say, because
credentials already signed cannot be re-signed against a different rule. JCS is a
candidate for a successor suite, not a description of this one.

Byte-identical output across implementations is the cross-implementation contract, and
the vectors are how a second implementation proves it has it. Today there is one
published SDK; the contract exists so that the second one can be checked against it
rather than negotiated with.

**Breaks if:** any serialisation detail varies — key ordering, number formatting,
string escaping, whitespace.

## 4 · The issuer signing key

**The signing key cannot rotate.** Not "cannot rotate without publishing the old key
set" — cannot rotate, for any already-published version of the verify SDK.

The published SDK carries the registry's public keys as hex literals compiled into
the package. There is no key discovery in the verification path: no endpoint is
consulted, no DID is resolved. Anyone who pins a given version verifies against that
compiled key for as long as they keep the pin.

**Escape hatch:** `setRegistryKeys()` is exported public API, not a test helper. A
pinned consumer can inject new keys at runtime. This turns *impossible* into
*manual*, which is the difference between an incident and a migration note.

**Design requirement for any future release:** the key set must be append-only with
validity windows; rotation must be a signed assertion chained from the compiled key,
making that key an *anchor* rather than *the* key; and key discovery must ship in the
same release as any new package name, not after it.

## 5 · `https://aria.bar/ns/v1`

The JSON-LD context. Declared as a `const` in the schema, so it appears in the
`@context` of every conformant credential.

**Breaks if:** the URL moves, a term definition changes meaning, or the response
stops being served as `application/ld+json`.

## 6 · `https://aria.bar/spec#did-method`

The specification anchor cited from the W3C DID Method Registry entry.

**Breaks if:** the page generator changes the section slug. Anchor stability is a
requirement on the generator, not a cosmetic detail.

## 7 · `api.aria.bar`

The hostname of the public read API.

**Breaks if:** the read API is served from a different host.

## 8 · `https://api.aria.bar/v1/credentials/{credentialId}`

The **path shape**, not just the host. This URL is the top-level `id` of every
issued credential.

**Breaks if:** the route pattern changes — historical instance resolution fails and
the `previousCredentialId` issuance chain cannot be walked.

## 9 · DNS TXT record format

```
v=ARIA1; did=<did>; hash=sha256:<hash>; aid=<url>
```

Deployed in the DNS zones of real customers and described in the W3C registry entry.

**Breaks if:** the parser becomes stricter. Records that resolve today must continue
to resolve; a "better" parser that rejects them is a regression.

## 10 · `https://api.aria.bar/v1/status/1` and `…/status/1#{index}`

The status list credential URL and the entry identifier, present in the
`credentialStatus` block of **every** issued credential.

**Breaks if:** the route shape changes — revocation checking fails for every
existing AID, which is a silent security failure rather than a visible error.

## 11 · The `issuer` string

Every issued credential names its issuer DID together with `#key-1` as the
`verificationMethod`. Today that issuer is `did:aria:registry.aria.bar`.

**Note on what this actually requires.** The reference verify SDK never dereferences
this identifier — it is a label, not a pointer. A third-party verifier implementing DID
resolution per the specification *would* resolve it, so it must resolve; but reference
verification does not depend on it.

**What the issuer is.** The issuer of a conformant credential is the one named in the
accreditation list TrustLayer Foundation signs — not a fixed string. Today that is the
operating registry; from the issuance cutover it is TLF, and once a second Registration
Authority exists the first one's domain must not appear as the issuer of its
credentials. See spec §5.2 (trust bootstrap) and `AUD-02` (withdrawal of an
accreditation is forward-only: it does not invalidate credentials issued while the
accreditation stood).

**The regime is determined by the issuer DID, never by `spec_version`.** Credentials
issued before the cutover carry an earlier `spec_version` than `"1.0"`, so any rule of
the form "version ≥ N" misclassifies them. The only valid rule:

```
issuer did:aria:registry.aria.bar   →  issued before the cutover
issuer the TLF DID                  →  ARIA 1.0 issuance
```

Every issuer that has ever been listed must remain resolvable indefinitely. Key
discovery, which is what would let a verifier check this rather than trust a compiled
constant, is `[PLANNED]` — see invariant 4.

## 12 · `https://api.aria.bar/v1/verify/{did}`

The revocation endpoint, compiled into every published version of the verify SDK as
`DEFAULT_API_URL` plus path.

**This is the revocation mechanism the SDK actually uses.** It does not read
`credentialStatus` from the credential; it asks this endpoint by DID.

**Breaks if:** the route changes or the host stops answering — revocation checking
fails for every pinned SDK version.

**Two revocation mechanisms coexist and both must keep working:**

| Mechanism | Consumer |
|---|---|
| `credentialStatus` → Bitstring Status List at `/v1/status/1` | Third-party verifiers following W3C VC 2.0 |
| `checkRevocation()` → `/v1/verify/{did}` | The reference verify SDK |

**This is a debt, and naming it is part of the invariant.** The per-DID call is a
phone-home: it tells the registry which agent a verifier is asking about, which is
exactly what the aggregate list avoids and what spec §8 warns against. The specification
describes the aggregate Status List as the mechanism; the reference SDK does not use it.
Moving the SDK to the aggregate list is `[PLANNED]`. Until then, both endpoints must
keep answering, because pinned versions depend on the per-DID one.

---

## Procedural: npm package names

`@aria-registry/verify` is cited from the W3C registry entry, and **npm does not
redirect packages**. If the package is republished under a different scope:

```
1. publish the new name
2. npm deprecate the old name, pointing at the new one
3. never npm unpublish — that breaks the cited URL
```

---

## Not an invariant, but a documented default

`verifyAgent()` does not check revocation. It returns `revocationStatus: 'unknown'`
and passes. Revocation checking is opt-in through policy
(`requireRevocationCheck`, `lastRevocationCheck`, `maxOfflineAge`); with a policy
that requires it, verification fails closed.

This is a deliberate design choice — offline verification is a product feature — but
an integrator who calls `verifyAgent()` and reads `passed` without configuring a
policy will accept a revoked credential. It is documented here so the behaviour is
explicit rather than discovered.
