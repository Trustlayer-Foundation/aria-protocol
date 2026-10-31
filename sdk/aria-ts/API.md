# ARIA SDK 1.0 — API contract

Status: S0 contract, corrected after its review (S0-R1 to S0-R4) and amended for the
two-package structure, with S1 implemented: inspection, trust, credential verification,
exact-instance status and the trust interface for ARIA AP work. Package name provisional
(`@aria-registry/sdk`) until its owner is confirmed. Private, not published.

This package verifies credentials and their status. Requests, admission, operations and
receipts are **ARIA AP**, the separate package in [`../aria-ap-ts`](../aria-ap-ts/API.md),
which builds on this one. A service that only checks credentials needs only this package.

## Results, kept apart

| Result | Says | Does not say |
|---|---|---|
| `Inspection` (`inspectCredential`) | The fields a document carries | Anything verified: `verified` is always `false` |
| `VerifiedCredential` (`verifyCredential`) | This exact document conforms to its `spec_version`, is within its signed validity and verifies under a trusted issuer, both signature halves | Who presents it; its status |
| `StatusEvidence` (`checkStatus`) | The status of that exact document, its source, and its times | Anything about another document of the same DID |
| `Standing` (`standing`) | Whether that exact document stands now: valid, with fresh evidence of its status | That anyone presents it, or may do anything with it |

None of them is a decision to run anything. Who presents a credential, and what they may
do, is ARIA AP's: its admission, not a field here, is what lets an operation run.

## Results are the verifier's own: runtime provenance

A result object is a deeply frozen **view**. The verifier that produced it keeps the
authoritative snapshot in private storage keyed by that object's identity, and every
consumer (`checkStatus`, `facts`, `standing`, and through them ARIA AP) reads the
snapshot, never the view's fields. Therefore:

- a spread copy, a copy with every own property and symbol, or a cast object is refused
  (`AriaUsageError`), whatever it contains;
- a view cannot be altered in place: it is frozen, times are RFC 3339 strings and the
  holder key is its multibase string (the 32 bytes stay inside the verifier);
- a result is accepted only by the verifier instance that produced it. A trust profile's
  `id` (`demo`, `production`) is a label, not a trust identity: another verifier, even with
  the same label or keys, refuses it;
- the trusted configuration is copied and frozen when the verifier is created; later
  changes to the caller's key bytes or arrays change nothing;
- time-sensitive evidence is judged when it is used: `standing` judges at each call, so
  a credential verified earlier can be expired at admission, and status evidence fresh
  then can be stale now;
- two installed copies of this package are two separate records: each refuses the
  other's results, so a duplicated install fails closed, never open.

Install one copy and create the verifier once per trust configuration; ARIA AP takes that
instance (`createAp({ credentials })`) instead of creating its own.

Types alone are not the boundary (a spread keeps the type); the runtime record is.

## Building on this package: `facts` and `standing`

ARIA AP, or any package built on this one, must reuse this verifier's work without
trusting a result's fields: a copy, a cast or another verifier's object carries the
same fields. Two methods are the whole interface:

- **`facts(credential)`** returns what the verifier recorded for one of its own
  `VerifiedCredential` results: binding, DID, issuer, level, scopes, `hitlRequired`,
  delegation depth, validity, and the holder key as its 32 raw bytes. Each call returns a
  fresh copy; changing it changes nothing the verifier holds.
- **`standing(credential, status)`** judges, at the call and with the verifier's clock,
  skew and maximum ages, whether that exact credential is inside its signed validity and
  `status` is this verifier's evidence about that same result, available, fresh and
  active. In order: `not_valid_now`; `unknown` (`other_document`, `unavailable`,
  `stale`); `revoked`; `superseded`; `good`. Unknown is never good.

Both throw `AriaUsageError` for anything this verifier did not produce. What they return
is data and a judgment, not evidence: no entry point of this package or of ARIA AP
accepts them in place of a result. They exist so that a package built on this one never
reads a result's fields and never verifies a credential or its status a second time.

A result is evidence only inside the process and the verifier that produced it. Data
that crosses a process boundary is verified again where it arrives.

## Trust boundary

**Trusted configuration** — supplied by the adopter, never read from a message, copied
when the verifier is created: trust profiles (issuer DID, the `verificationMethod` its
proofs name, both public keys, highest level, the status lists it publishes, its online
status endpoint), the fetch policy (exact allowed origins, time and size bounds, the
fetch implementation; redirects are never followed), the clock, maximum status ages and
clock skew. ARIA AP adds its own (receiver identity, operations, stores, approvals).

**Untrusted input** — everything that arrives: credentials, status lists and online
answers. Nothing in them selects a trust anchor or a fetch target outside the allowed
origins.

There is no global configuration and nothing embedded: a verifier trusts exactly its
profiles. The level order is protocol, not configuration: `TRUST_LEVELS` lists the levels
lowest first and is frozen, so no consumer can reorder the ranking this verifier and
ARIA AP apply.

## Credential verification (S1)

`verifyCredential(document)` accepts an object or JSON text up to 100 KB, works on a
private copy, and returns the first failure in this order:

1. not a JSON object (`malformed`), `spec_version` other than `"1.0"` (`unsupported_version`);
2. the AID 1.0 schema (`malformed`, with a JSON pointer);
3. an issuer no profile names (`untrusted_issuer`);
4. proof metadata other than the profile's — `DataIntegrityProof`,
   `mldsa65-ed25519-2026`, `assertionMethod`, the profile's `verificationMethod`
   (`unsupported_proof`). These values are checked, not signed: the suite signs the
   document without its `proof`;
5. both signature halves over the canonical document (`signature_invalid`);
6. strict RFC 3339 validity, ordered, current within the skew (`invalid_validity`,
   `not_yet_valid`, `expired`);
7. the holder key: exactly 32 raw Ed25519 bytes under the ARIA 1.0 compatibility
   encoding, under the subject's DID, and acceptable by the authority's own rule —
   the canonical encoding of a point, not of small order, torsion free
   (`holder_key_invalid`). The identity point and other weak keys cannot establish
   possession, so they are refused here, not only at issuance;
8. rules the schema cannot express: `hitlRequired` within `scope` (`semantic_invalid`);
9. a level above the profile's maximum (`level_not_trusted`);
10. a status list the profile does not publish (`status_list_untrusted`).

The result has no issuance time: `validFrom` and `validUntil` are the signed bounds and
`proof.created` is unsigned. `previousCredentialId` is returned as data and never fetched.

## Status (S1)

`checkStatus(credential, { via })` concerns the exact document:

- **`status-list`** (default) fetches the list the credential names, from an allowed
  origin, and reads it only after it verifies under the same profile: issuer, proof
  profile, both signatures, its signed `id` equal to the list the credential names
  (another genuine list of the same issuer is refused), the supported subject
  (`BitstringStatusList`, purpose `revocation`, one bit per entry), and `encodedList` as
  multibase `u` + base64url GZIP, decompressed within 2 MiB and at least 131,072 entries.
  Its times are then judged at completion, not when the request started: a validity
  window of at most 24 hours that holds now, and an age from its own signed `validFrom`
  within `statusMaxAgeSeconds` (default 3600). `fetchedAt` is that completion time,
  reported apart from the list's signed times.
- **`online`** asks the profile's `onlineStatus` endpoint for the DID. Only a complete
  answer counts — the DID, an exact document reference and a status; anything less is
  `unavailable`. It has no signed time, is stamped when observed, is only as strong as
  TLS to that configured endpoint, and `standing` treats it as fresh for
  `onlineStatusMaxAgeSeconds` (default 60). A complete answer naming another current
  document makes the presented one `superseded`; a revocation bit never does.
- Anything not established is `unavailable` with a reason (`offline`, `origin_not_allowed`,
  `fetch_failed`, `too_large`, `malformed`, `signature_invalid`, `wrong_issuer`,
  `not_valid_now`, `stale`, `no_online_endpoint`); its standing is `unknown`, which ARIA AP's
  admission treats as `indeterminate`.

## Credential profile

`spec_version` `"1.0"` (`schema/aid-1.0.json`, embedded byte for byte and checked by a
test) is the supported profile. Its holder key is 32 raw Ed25519 bytes under
`Ed25519VerificationKey2020` — an ARIA compatibility encoding, not the standard Multikey
one; the SDK decodes exactly 32 bytes and projects `0xed01` only when producing a
Multikey. The proof metadata is outside the signed bytes: the SDK requires the supported
values, which does not make them signed (decision D12 covers a successor suite).

## Package and runtimes

- ESM only, with type declarations; `exports` has the package entry and `package.json`.
  The dependencies are `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `ajv` and
  `ajv-formats`.
- Node.js 20 and 22: everything (declared; the artifact check in
  [`../scripts/check-pair.mjs`](../scripts/check-pair.mjs) runs on the Node.js it is given).
- Browsers and edge runtimes: offline credential checks, with two limits: the schema
  validator compiles code at run time, which a strict Content Security Policy forbids,
  and network status checks there cannot enforce private-network restrictions.

The package has no install scripts and reads no environment file.
