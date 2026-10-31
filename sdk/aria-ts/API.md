# ARIA SDK 1.0 — API contract

Status: S0 contract, corrected after its review (S0-R1 to S0-R4), with S1 implemented:
inspection, trust, credential verification and exact-instance status work; presentation,
admission, operations, receipts and the agent side throw `NotYetImplemented` until AP2.
Package name provisional (`@aria-registry/sdk`) until its owner is confirmed. Private,
not published.

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
logs the `deny`, and whatever it then runs is not admitted. The public `admit` always
needs a verified presentation; the admission rules exist internally and are tested, but
nothing reaches them without one.

## Results are the verifier's own: runtime provenance

A result object is a deeply frozen **view**. The verifier that produced it keeps the
authoritative snapshot in private storage keyed by that object's identity, and every
consumer (`checkStatus`, `admit`, the ledger) reads the snapshot, never the view's
fields. Therefore:

- a spread copy, a copy with every own property and symbol, or a cast object is refused
  (`AriaUsageError`), whatever it contains;
- a view cannot be altered in place: it is frozen, times are RFC 3339 strings and the
  holder key is its multibase string (the 32 bytes stay inside the verifier);
- a result is accepted only by the verifier instance that produced it. A trust profile's
  `id` (`demo`, `production`) is a label, not a trust identity: another verifier, even with
  the same label or keys, refuses it;
- the trusted configuration is copied and frozen when the verifier is created; later
  changes to the caller's key bytes or arrays change nothing;
- time-sensitive evidence is judged when it is used: a credential verified earlier can
  be expired at admission, and status evidence fresh then can be stale now.

Types alone are not the boundary (a spread keeps the type); the runtime record is.

## Trust boundary

**Trusted configuration** — supplied by the adopter, never read from a message, copied
when the verifier is created: trust profiles (issuer DID, the `verificationMethod` its
proofs name, both public keys, highest level, the status lists it publishes, its online
status endpoint), the fetch policy (exact allowed origins, time and size bounds, the
fetch implementation; redirects are never followed), the clock, maximum status ages and
clock skew; on the receiver side, its own identity and signer, operation descriptors, the
challenge store, the operation storage, the resource authorizer and the approval system.

**Untrusted input** — everything that arrives: the credential, headers, body, identity
statements, receipts, status lists and online answers. Nothing in them selects a trust
anchor, a fetch target outside the allowed origins, or an operation not described.

There is no global configuration and nothing embedded: a verifier trusts exactly its
profiles.

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
   encoding, a point on the curve, under the subject's DID (`holder_key_invalid`);
8. rules the schema cannot express: `hitlRequired` within `scope` (`semantic_invalid`);
9. a level above the profile's maximum (`level_not_trusted`);
10. a status list the profile does not publish (`status_list_untrusted`).

The result has no issuance time: `validFrom` and `validUntil` are the signed bounds and
`proof.created` is unsigned. `previousCredentialId` is returned as data and never fetched.

## Status (S1)

`checkStatus(credential, { via })` concerns the exact document:

- **`status-list`** (default) fetches the list the credential names, from an allowed
  origin, and reads it only after it verifies under the same profile: issuer, proof
  profile, both signatures, a validity window of at most 24 hours that holds now, and an
  age from its own signed `validFrom` within `statusMaxAgeSeconds` (default 3600);
  `encodedList` is multibase `u` + base64url GZIP, decompressed within 2 MiB and at least
  131,072 entries. Its signed times are reported apart from `fetchedAt`.
- **`online`** asks the profile's `onlineStatus` endpoint for the DID. The answer has no
  signed time and is only as strong as TLS to that configured endpoint; it is reusable at
  admission for `onlineStatusMaxAgeSeconds` (default 60). An answer naming another
  current document makes the presented one `superseded`; a revocation bit never does.
- Anything not established is `unavailable` with a reason (`offline`, `origin_not_allowed`,
  `fetch_failed`, `too_large`, `malformed`, `signature_invalid`, `wrong_issuer`,
  `not_valid_now`, `stale`, `no_online_endpoint`), which admission treats as `indeterminate`.

## Operations, fingerprints and receipts (contract; AP2)

An `OperationDescriptor` is the closed list of what may vary in an operation: its class,
method, path, the **one** media type a body may have, its query parameters, and any
further header that changes its meaning. Everything listed is signed and part of the
operation's **fingerprint**: SHA-256 over the canonical
`{class, method, path, query, mediaType, semanticHeaders, contentDigest}`, where
`contentDigest` is the digest of empty content for `unsafe-empty` and absent for safe
classes. The challenge, signing times, key and signature are not in it, so a retry with
a fresh signature is the same operation; the same id with another body, query or media
type is a conflict.

The receiver: authenticate (unsigned failures), admit (a refusal is a signed
`rejected/attempt` and claims nothing), then `OperationLedger.begin`:

- no record: create it as `claimed` with a fresh claim id, and run;
- same fingerprint with an outcome: return the governing receipt, no second effect;
- another fingerprint, or claimed by another worker: a signed `rejected/attempt`
  (`aria.idempotency_conflict`, `aria.operation_in_progress`) that changes nothing.

**Storage is compare-and-set.** Every stored operation has a `revision`; a claim has an
id. `create` inserts only if absent; `replace`, `reclaim` and `remove` write only if the
revision and claim they read are still there. So two workers cannot both settle an
operation, a stale worker cannot replace a final outcome, and a late failure cannot
release another worker's claim.

**When a handler throws**, `ledger.fail(claim, 'rolled-back')` releases the claim only
when the adopter knows its transaction did not commit; `'uncertain'` keeps it, retries
get `operation_in_progress`, and `ledger.reconcile` later settles or releases it from the
adopter's own record of the effect (a claim older than `claimTimeoutSeconds` can also be
reconciled).

**`accepted` continues after a restart** through `ledger.resume(key, admission)`: a fresh
admission of the same operation and fingerprint (current status, policy and approval),
then a new claim at the stored revision; one worker gets it, the others are refused. The
final receipt is new; the `accepted` one stays in the immutable history.

Receipts have exactly two sources: an **operation outcome**, recorded by `ledger.settle`
in the business effect's transaction, and an **attempt refusal**, from a denied admission
or a refused claim (`buildAttemptRefusal`). An admission cannot make either. Errors before
authentication are unsigned.

**The client keeps every attempt.** `OperationTracker` holds the operation's binding
(operation id, sender, receiver) and every `SentAttempt`. A receipt's request digest only
selects the kept attempt; signature, receiver, sender and every binding are then checked
against it, so the original receipt returned to a retry with a fresh challenge is
recognised. It moves only on a verified operation receipt of this operation; an attempt
refusal is kept as evidence and leaves the state; an unverifiable binding or another
sender or receiver changes nothing. Failing to send a retry is that retry's error: once
an attempt was sent (`everSent`) the operation is not «not sent».

**Historical verification** (`mode: 'historical'`) works offline from retained evidence:
the exact receiver credential the receipt names (its URL is in the receipt; the DID's
current document may be another one) and, optionally, the retained signed status list.
It reports separately whether that credential verifies under the trusted issuer now,
whether the receiver's claimed `issuedAt` falls in its signed validity, and the retained
status; it never establishes the signing time, which is the receiver's own claim. Without
the exact credential it fails with `evidence_missing`. It neither fetches the DID's
current document nor moves the verifier's clock.

## Human approval

When the credential lists the operation's scope in `hitlRequired`, admission needs
`ApprovalEvidence` from the receiver's approval system, bound to the sender, the exact
credential, the operation id, its fingerprint and an expiry. Without it the attempt is
refused (`approval_required`) and a later attempt carrying an approval can proceed.

Holding an operation for an approval workflow (`accepted` without running it) is
**deferred, not decided**: it needs decision D8 and is not offered by this API until then.
Enrollment consent and the agent's own signature are not approvals.

## Credential profile

`spec_version` `"1.0"` (`schema/aid-1.0.json`, embedded byte for byte and checked by a
test) is the supported profile. Its holder key is 32 raw Ed25519 bytes under
`Ed25519VerificationKey2020` — an ARIA compatibility encoding, not the standard Multikey
one; the SDK decodes exactly 32 bytes and projects `0xed01` only when producing a
Multikey. The proof metadata is outside the signed bytes: the SDK requires the supported
values, which does not make them signed (decision D12 covers a successor suite).

## Runtimes

- Node.js 20 and 22: everything.
- Browsers and edge runtimes: offline credential checks, with two limits: the schema
  validator compiles code at run time, which a strict Content Security Policy forbids,
  and network status checks there cannot enforce private-network restrictions.

The package has no install scripts and reads no environment file.
