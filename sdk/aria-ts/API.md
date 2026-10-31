# ARIA SDK 1.0 — API contract (draft for review)

Status: S0, the API before its implementation. Types and signatures are in `src/`; every
entry point throws `NotYetImplemented` until S1 (credentials, status, admission) and AP2
(presentation, receipts) implement it. Package name provisional (`@aria-registry/sdk`)
until its owner is confirmed. Not published.

## Six results, kept apart

| Result | Says | Does not say |
|---|---|---|
| `Inspection` (`inspectCredential`) | The fields a document carries | Anything verified: `verified` is always `false` |
| `VerifiedCredential` (`verifyCredential`) | This exact document conforms to its `spec_version`, is within its signed validity and verifies under a trusted issuer, both signature halves | Who presents it; its status |
| `StatusEvidence` (`checkStatus`) | The status of that exact document, its source, and its times | Anything about another document of the same DID |
| `VerifiedPresentation` (`verifyPresentation`) | The caller signed this request with that document's holder key, for this receiver, operation and content | That it may do it |
| `Admission` (`admit`) | `allow`, `deny` or `indeterminate`, with a fixed reason | That the operation ran |
| `ReceiptStatement` (`verifyReceipt`) | The expected receiver signed this statement about this attempt or operation | That the business effect is true outside the receiver; a valid receipt can say `rejected` |

Only `allow` lets an operation be claimed and run. There is no mode in which a failed or
missing check becomes `allow`: a receiver observing a policy (the old `monitor`/`warn`)
logs the `deny`, and whatever it then runs is not admitted.

## Runtime binding

Each result names the exact document it is about (`CredentialBinding`: `credentialId`,
canonical digest, trust profile). `admit` checks at run time that the presentation, its
credential and the status evidence are about the same document; a status of document A
cannot admit document B. Results carry a private mark the package does not export, so
they cannot be typed by hand; the implementation checks the mark again at run time,
because a cast passes any type check.

## Trust boundary

**Trusted configuration** — supplied by the adopter, never read from a message:
trust profiles (issuer DID, both public keys, highest level, status lists), the fetch
policy (allowed origins, time and size bounds, no redirects), the clock, the status
maximum age, the receiver's own identity and signer, its operation descriptors, the
challenge store, the operation storage, the resource authorizer and the approval system.

**Untrusted input** — everything that arrives: the credential, headers, body, identity
statements, receipts and status responses. Nothing in them selects a trust anchor, a
fetch target outside the allowed origins, or an operation not described.

There is no global configuration. Two verifiers with different trust never affect each
other.

## Status

`status-list` (default) reads the issuer's signed list at the document's own index: its
signed `validFrom`/`validUntil` are reported, and evidence older than
`statusMaxAgeSeconds` (default 3600) counted from the list's `validFrom` is `stale`.
`online` asks the issuer's API: its answer has no signed time, and `superseded` appears
only when it names another current document. A revocation bit cannot say why. Without a
fetch policy the verifier is offline and status is `unavailable`, which admission treats
as `indeterminate`.

## Operations, fingerprints and receipts

An `OperationDescriptor` is the closed list of what may vary in an operation: its class,
method, path, the **one** media type a body may have, its query parameters, and any
further header that changes its meaning. Everything listed is signed and part of the
operation's **fingerprint**: SHA-256 over the canonical
`{class, method, path, query, mediaType, semanticHeaders, contentDigest}`, where
`contentDigest` is the digest of empty content for `unsafe-empty` and absent for safe
classes. The challenge, signing times, key and signature are not in it, so a retry with
a fresh signature is the same operation; the same id with another body, query or media
type is a conflict.

The receiver's sequence: authenticate (unsigned failures), admit (a refusal is a signed
`rejected/attempt` and claims nothing), then `OperationLedger.begin`:

- no record: claim it atomically and run;
- same fingerprint, outcome recorded: return the governing receipt, no second effect;
- other fingerprint, or still claimed by another attempt: a signed `rejected/attempt`
  (`aria.idempotency_conflict`, `aria.operation_in_progress`) that changes nothing.

Receipts have exactly two sources:

- an **operation outcome**, recorded by `OperationLedger.settle` at the business
  effect's commit point, in its transaction (`accepted`, `completed`, or `rejected` with a
  business code, final for that operation id);
- an **attempt refusal**, from a denied admission or a refused claim
  (`buildAttemptRefusal`), which neither claims nor changes the operation.

An admission cannot make either. Errors before authentication are unsigned.

The client's `OperationTracker` moves only on operation receipts, never backwards; an
attempt refusal is kept as evidence and leaves the operation where it was.

## Human approval

When the credential lists the operation's scope in `hitlRequired`, admission needs
`ApprovalEvidence` from the receiver's approval system, bound to the sender, the exact
credential, the operation id, its fingerprint and an expiry. Without it:

- `onMissingApproval: 'refuse'` (recommended for profile 1): `deny` with
  `approval_required`; a later attempt carrying an approval can proceed;
- `onMissingApproval: 'hold'` (only if decision D8 selects it): the receiver's workflow
  records the operation as `accepted` without running it, re-admits it with the approval
  when granted, and settles it then. Not implemented unless chosen.

Neither path runs a business effect or signs an acceptance from admission alone.
Enrollment consent and the agent's own signature are not approvals.

## Credential profile

`spec_version` `"1.0"` (`schema/aid-1.0.json`) is the supported profile. Its holder key
is 32 raw Ed25519 bytes under `Ed25519VerificationKey2020` — an ARIA compatibility
encoding, not the standard Multikey one; the SDK decodes exactly 32 bytes and projects
`0xed01` only when producing a Multikey. The proof metadata (`cryptosuite`,
`verificationMethod`, `proofPurpose`, `created`) is outside the signed bytes: the SDK
requires the supported values, which does not make them signed, and exposes no issuance
time — `validFrom` and `validUntil` are the signed bounds.

## Runtimes

- Node.js 20 and 22: everything.
- Browsers and edge runtimes: offline credential and receipt verification. Network
  status checks there cannot enforce private-network restrictions and are documented
  as such.

The package has no install scripts and reads no environment file.
