# ARIA AP 1.0 — API contract

Status: implemented against a **provisional** wire profile. The vectors in
[`conformance/ap`](../../conformance/ap/README.md) encode the options recommended for
decisions D3 (transport), D4 (receipt), D5 (scopes) and D8 (human approval), none of
which is taken; the identity statement below is provisional under D3 as well. Expect the
wire format to change when they are decided. Package name provisional
(`@aria-registry/ap`) until its owner is confirmed. Version 1.0.0 is a local candidate:
private, not published, not an approved release.

## What it builds on

ARIA AP has no credential or status verification of its own. It builds on the credential
verifier of the ARIA SDK ([`../aria-ts`](../aria-ts/API.md)), which the application
creates with its trust configuration and hands over:

```ts
import { createVerifier } from '@aria-registry/sdk';
import { createAp } from '@aria-registry/ap';

const verifier = createVerifier({ trust, fetch });
const ap = createAp({ credentials: verifier });
```

- **One verifier, the application's.** `@aria-registry/sdk` is a peer dependency: the
  application installs it, and ARIA AP uses that copy. ARIA AP imports only its public
  entry point and contains none of its code. Its own dependencies are `@noble/curves`
  and `@noble/hashes`.
- **Credentials are verified by the verifier, and read through it.** A presented
  credential document goes to `verifier.verifyCredential`; the result is read with
  `verifier.facts` (holder key, level, scopes) and judged with `verifier.standing`
  (validity, status, freshness, now). Both refuse anything that verifier did not produce,
  so a copied, hand-made or foreign result or status cannot become evidence.
- **ARIA AP's own results** (presentations, admissions, lookups, refusals, claims,
  outcomes, verified receivers, receipt statements) are recorded by the `Ap` instance
  that produced them and accepted only by it.
- **A duplicated install fails closed**, and **nothing is portable evidence**: results
  live in one process, and what crosses a process boundary is verified again.

## The exchange

| Step | Agent | Receiver |
|---|---|---|
| 1. Who is the receiver | `GET /.well-known/aria/identity?nonce&audience`, then `verifyReceiverIdentity(response, pin, { nonce, audience })` → `VerifiedReceiver` with a challenge | `identify(self, { nonce, audience }, challenges)` |
| 2. A signed attempt | `signRequest({ request, class, operationId, receiver, credential, signer })` → `{ request, sent, receiver }` | `verifyPresentation(request, context)` → `VerifiedPresentation`, or an unsigned 400/401 |
| 3. Admission | — | `admit({ presentation, status, approval?, authorize })`; a refusal is signed with `buildAttemptRefusal` |
| 4. Once per operation | — | `OperationLedger.begin` → `settle` in the effect's transaction, or `fail` |
| 5. The answer | `OperationTracker.record(signed)` before sending, `observe(ap, receipt, { mode: 'decision', transportStatus })` | — |
| 6. Recovery | a signed `retrieval`, then `observeLookup(ap, { history })` | `admitLookup`, `ledger.lookup` |

Every request, a lookup included, uses a new challenge from a fresh step 1: a challenge
is consumed by the request that uses it.

## Results, kept apart

| Result | Says | Does not say |
|---|---|---|
| `VerifiedReceiver` | The pinned DID at the pinned origin signed a fresh statement for this client, with a credential that stood when verified; `signRequest` judges it again | Anything about the operation; that it still stands later |
| `VerifiedPresentation` | The caller signed this request with the holder key of an exact verified credential, for this receiver, operation and content | That it may do it |
| `Admission` | `allow`, `deny` or `indeterminate`, with a fixed reason | That the operation ran |
| `ReceiptStatement` | The receiver previously verified by this instance signed this statement about one kept attempt | That the receiver stands now; that the effect is true outside the receiver; a valid receipt can say `rejected` |
| `HistoricalStatement` | The receiver credential the receipt names, retained and authentic, signed this statement about one kept attempt | That the credential stands now, or that anything is authorized now |

Only `allow` lets an operation be claimed. There is no mode in which a failed check
becomes `allow`; a receiver observing a policy logs the `deny`, and what it then runs is
not admitted.

## Request profile (provisional, D3)

RFC 9421 with one signature labelled `aria`, tag `aria-ap/1`, Ed25519, `keyid` the
credential's holder key. Each class fixes its covered components exactly:

| Class | Methods | Covered | Receipt |
|---|---|---|---|
| `unsafe-body` | POST, PUT, PATCH | `@method`, `@target-uri`, `content-type`, `content-digest`, `aria-operation`, `aria-credential`, `aria-audience` | yes |
| `unsafe-empty` | DELETE, POST, PATCH | as above without `content-type`; digest of empty content | yes |
| `safe-receiptable` | GET | `@method`, `@target-uri`, `aria-operation`, `aria-credential`, `aria-audience` | yes |
| `retrieval` | GET `?operation=<id>` | `@method`, `@target-uri`, `aria-credential`, `aria-audience` | no |

plus every semantic header the operation declares and the request carries.
`ARIA-Operation` is the operation id (a UUID, the same on every retry and the idempotency
key); `ARIA-Credential` names the exact credential by URL with its digest
(`"<url>";digest=:<sha-256>:`); `ARIA-Audience` is the receiver DID.

`verifyPresentation` checks in a fixed order and stops at the first failure: method and
one described operation, body and media type, query, `ARIA-Operation` (400
`aria.request_invalid`); then one `aria` signature, the covered components, the
parameters and window (at most 60 s, 5 s skew), `Content-Digest`, a live challenge, the
exact credential (resolved by `context.resolveCredential(url)`, verified, URL and digest
equal, `keyid` its holder key), and strict Ed25519 over the base rebuilt from the
receiver's configured origin (401 `aria.authentication_failed` with that subtype). Only
then is the challenge consumed. Strict Ed25519 means the key and `R` canonical, not small
order and torsion free, and `S < L`. The fingerprint is SHA-256 over the canonical
`{class, method, path, query, semanticHeaders, mediaType, contentDigest}`; the challenge,
times, key and signature are not in it.

An expired or not-yet-valid credential does not authenticate (401 `credential`): the
credential verifier produces no result for it. `aria.credential_expired` is the admission
answer when validity ends between authentication and admission.

## Receiver identity (provisional, D3)

`identify` answers `{ credential, statement }`: the receiver's AID document and a
statement `aria-ap-identity/1` with `subject`, `credential`, `origin`, `audience`,
`nonce`, a fresh `challenge` (single use, 60 s) and `created`, signed with the
receiver's holder key over its canonical JSON without `proof.value`.
`verifyReceiverIdentity` checks, in order: the form (`malformed`); the document verifies
and is the one named (`credential`); the pinned DID (`unexpected_receiver`), origin
(`origin`), audience (`audience`), nonce (`nonce`); `created` within 60 s (`stale`); the
signature by that credential's holder key (`signature`); and the credential's standing is
`good` now (`status`). The client pins origin and DID; nothing is learnt from the answer.
The verified receiver keeps that credential and status evidence: `signRequest` judges the
statement's freshness and the credential's standing when it starts and again after the
`Signer` returns, and refuses a request whose own signature window ended while signing.
After that, identify the receiver again; nothing extends the old statement. Receipts
already recorded are not judged again this way.
The identity endpoint is anonymous and every call signs and stores a challenge:
rate-limit it. `MemoryChallengeStore` refuses to hold more than `maxLive` (default 10 000).

## Admission

Order: audience; the credential's standing (`not_valid_now` → `credential_expired`,
`unknown` → `indeterminate`, `revoked`, `superseded`); level against the operation's
minimum; scope (exact: the credential's scopes are never patterns); the receiver's scope
policy, when `admit` is given one (`aria.scope_denied`); delegation (unsupported); human
approval, judged at the standing's instant; then the application's `authorize`, called
only when all of these pass. A refusal by `authorize` carries the receiver's own code (`bank.account_not_granted`)
and is a 403 attempt refusal. Refusals are signed `rejected/attempt` receipts and claim
nothing; `indeterminate` is a signed 503 `aria.status_unavailable`.

**An admission is a short-lived capability, judged when it is made and again when it is
used.** `admit` judges standing and approval again after `authorize` returns, since the
authorizer may take time. The admission keeps the status evidence and approval it was
judged on and its request's deadline (the signature's `expires` plus the 5 s skew);
`begin` and `resume` judge it again on entry and after every storage wait, on every path:
before granting a claim, after the write (releasing the claim just made if it no longer
holds), and before returning a stored receipt to a retry, including after losing the
`create` race. The recorded outcome is never changed by these refusals. An approval or status
that lapsed refuses the attempt (signed, as at admission); a deadline that passed throws
`AdmissionExpired`: admit a fresh attempt. Every admission is used once. The application's
own resource decision is valid for that same lifetime; revalidating it longer is the
adopter's. Operation descriptors are checked: a minimum level outside `TRUST_LEVELS` or an
approval policy other than `refuse` is a usage error.

The scope policy (provisional, D5) is a list of `{ effect: 'allow' | 'deny', pattern }`
rules over the operation's scope. A pattern is a three-segment scope or two segments
followed by `:*`, which matches any third segment and nothing longer or shorter. A matching
deny wins whatever the order; otherwise a matching allow is needed, so an empty policy
admits nothing. Any other pattern (`payments:*:create`, `*`, `payments:transfer:cre*`) is a
usage error. The admission keeps a copy, so `begin` judges it with the same rules.

```ts
await ap.admit({
  presentation,
  status,
  scopePolicy: [
    { effect: 'allow', pattern: 'payments:transfer:*' },
    { effect: 'deny', pattern: 'payments:transfer:delete' },
  ],
  authorize,
});
```

A retrieval is admitted by `admitLookup` (provisional, D4): a credential of the
operation's sender DID whose standing is `good` reads that operation's receipts; a
revoked, superseded or expired credential reads nothing. Its refusals are unsigned
problems, since a retrieval gets no receipt of its own. A lookup admission is judged again
before the receipts are released, after the storage read: `ledger.lookup` throws
`AdmissionExpired` once its request is past its deadline, or with the status and code to
answer once the credential no longer stands.

## Operations and receipts

`OperationLedger` keys an operation by receiver, sender DID and operation id, over the
adopter's `OperationStorage` (each method one atomic compare-and-set;
`MemoryOperationStorage` is the reference). `begin` claims a new operation, returns the
governing receipt of a finished one with its original status, or refuses this attempt:
`aria.idempotency_conflict` for other content, `aria.operation_in_progress` while
claimed. `settle` records the outcome and signs its receipt inside the effect's
transaction; `fail('rolled-back')` releases a claim; `resume` continues an `accepted`
operation after a fresh admission of the same operation and content. A stale worker gets
`StaleClaim`; a record that contradicts the adopter's effect, `InvariantViolation`.

**Running each operation once.** The simple contract is an effect that commits in the
same transaction as `settle`: `settle`'s compare-and-set then fences any older worker,
whose transaction rolls back. An effect outside that transaction (a remote call) needs its
adapter to guarantee that a released claim cannot apply it later: durable idempotency at
the destination keyed by this operation, or cancellation that is known to be final.
Otherwise the operation stays locked:

- `fail(claim, 'uncertain')` marks the claim, by compare-and-set; it stays locked and
  retries get `aria.operation_in_progress`. The worker that holds it can still `settle`
  it once it learns the outcome. `markUncertain(key, { claimId, revision })` marks the
  claim of a worker that stopped without calling `fail`.
- `reconcile(key, observation)` releases a claim only when it is marked uncertain, the
  observation names its exact `claimId` and `revision`, `committed` is `false`, and the
  `assurance` is `transactional` or `fenced` (`Assurance`). An unmarked claim is `kept`
  (`active`); a marked one without assurance is `kept` (`unassured`); an observation of an
  earlier generation throws `StaleClaim` and releases nothing. A timeout, a row absent at
  one instant or a stopped local handler is not an assurance.
- A committed effect already has its stored outcome: `reconcile` returns that receipt,
  never a new one; an open claim reported committed throws `InvariantViolation`.

Receipts (`aria-ap-receipt/1`, provisional D4) have two sources only: a settled outcome
and an attempt refusal. The governing receipt is the final one if any, else the latest
`accepted`; history is never rewritten.

## The client

`OperationTracker` keeps every signed attempt with the receiver it was signed for, and
takes statements only from the `Ap` instance it is given. `observe` selects the kept attempt by the receipt's request digest and checks the exact
receiver credential and key, the signature, then operation, sender and receiver against
that attempt (`binding`), then the transport status (`status_mismatch` in `decision`
mode; `not_operation` for an attempt refusal in `retrieval` mode). With no attempt kept it
refuses (`binding_unverifiable`). Only a verified operation receipt moves the state; an
attempt refusal is kept as evidence; it never moves back, and two different final
receipts make it `inconsistent`. A receipt is identified by the digest of its signed
content, not by its `id`, which the receiver chooses: the same `id` with other content is
also `inconsistent`, and every statement is kept as evidence. Once an attempt was
recorded, `everSent` stays true.

## Historical receipts

`verifyHistoricalReceipt(receipt, { attempts, evidence })` checks a receipt long after the
exchange, against what the client kept: its attempts, the receiver's credential document
and, optionally, a status list. The credential verifier establishes the evidence, without
the current time: `verifyAuthenticity` over the retained document and `readRetainedStatus`
over the retained list (see the ARIA SDK's «Historical authenticity»).

- **Validity is authenticity and binding.** The evidence must be the exact receiver
  credential the receipt names; without it, or with another document of the same DID,
  the answer is `evidence_missing`. Then the same checks as a live receipt: receiver and
  key (`receiver_mismatch`), signature, and the kept attempt the digest selects
  (`binding`, `binding_unverifiable`). There is no transport status to compare.
- **The findings are reported, not folded into validity:** whether `issuedAt` falls in
  the credential's signed validity (`validFrom` inclusive, `validUntil` exclusive), what
  the retained list said and for which period (`active`, `revoked` or `not_retained`),
  and `signingTime: 'receiver_claim'`: `issuedAt` is the receiver's assertion, not an
  independent timestamp. A receipt can be valid and its credential revoked later.
- **It authorizes nothing now.** A `HistoricalStatement` is its own kind of result: no
  tracker, admission or signing accepts it, and an `AuthenticCredential` is refused
  wherever a verified credential is required. Evidence the verifier did not produce, or a
  retained status about another document, is a usage error.

```ts
const authentic = verifier.verifyAuthenticity(kept.receiverDocument);
const read = authentic.ok ? await verifier.readRetainedStatus(authentic.credential, kept.statusList) : null;
const r = await ap.verifyHistoricalReceipt(kept.receipt, {
  attempts: kept.attempts,
  evidence: authentic.ok ? { credential: authentic.credential, ...(read?.ok ? { status: read.status } : {}) } : {},
});
if (r.ok) console.log(r.statement.state, r.findings);
```

What is kept is plain JSON (the receipt, the attempts, the documents); a new process, with
a new verifier, checks it again.

## Schemas (provisional)

One JSON Schema (draft 2020-12) per wire document, in the protocol's
[`schema/`](../../schema/README.md) and shipped byte for byte in `schemas/` (a test and
`check-pair` compare them):

| Schema | Document |
|---|---|
| `aria-ap-receipt-1.json` | A receipt, `aria-ap-receipt/1`, including which state, `applies`, status and code go together |
| `aria-ap-identity-1.json` | The identity response: the receiver's AID 1.0 document (by reference to `aid-1.0.json`) and its `aria-ap-identity/1` statement |
| `aria-ap-lookup-1.json` | A retrieval's answer: `current` and `history`, operation receipts only |

`aria-ap-identity-1.json` refers to `https://aria.bar/schema/aid-1.0.json`, and
`aria-ap-lookup-1.json` to the receipt schema. Outside this repository, load the AID
schema from `@aria-registry/sdk/schemas/aid-1.0.json`, which the ARIA SDK exports byte
for byte, register its two annotation keywords, and assert formats, since the instants
rely on `date-time`. This is
[`../scripts/pair/schema-consumer.mjs`](../scripts/pair/schema-consumer.mjs), which
`check-pair` runs against the installed packages:

```js
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import aid from '@aria-registry/sdk/schemas/aid-1.0.json' with { type: 'json' };
import receipt from '@aria-registry/ap/schemas/aria-ap-receipt-1.json' with { type: 'json' };
import identity from '@aria-registry/ap/schemas/aria-ap-identity-1.json' with { type: 'json' };
import lookup from '@aria-registry/ap/schemas/aria-ap-lookup-1.json' with { type: 'json' };

const ajv = new Ajv2020();
ajv.addKeyword('_comment'); // annotations in aid-1.0.json, not validation keywords
ajv.addKeyword('_status');
addFormats(ajv); // the instants are date-time: formats must be asserted
ajv.addSchema([aid, receipt]);

export const validReceipt = ajv.getSchema(receipt.$id);
export const validIdentity = ajv.compile(identity);
export const validLookup = ajv.compile(lookup);
```

The origin's host expression is syntax only. The SDK also requires an origin to parse as
a URL whose serialization is the value itself, which includes valid IDNA:
`https://xn--a.example` matches the schema's pattern but is refused by the SDK, both when
emitting and when receiving.

They are provisional with D3 and D4. Conforming to a schema is neither a valid signature
nor an authorization: the SDK also parses receipts strictly (no duplicate keys, integers
only, at most 4096 bytes, which JSON Schema cannot express), verifies signatures, pins the
receiver's exact credential and binds each receipt to a kept attempt. Against the AP1
receipt vectors the schema and the SDK agree on every document but the three that only
the strict parsing refuses.

## Not offered yet

- **Holding an operation for approval** (`hold`, D8), **delegation**, a credential **by
  value**, and the WIMSE binding.

## Package and runtimes

- ESM only, with type declarations. Peer dependency: `@aria-registry/sdk` `^1.0.0`;
  the compatible pair is the one the release manifest records after
  [`../scripts/check-pair.mjs`](../scripts/check-pair.mjs) passed.
- Node.js 20 and 22 (declared). Uses the Web Crypto `getRandomValues` and `randomUUID`.
  No install scripts; reads no environment file.
