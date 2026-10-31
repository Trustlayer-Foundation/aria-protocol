# ARIA AP 1.0 — API contract

Status: S0 contract, amended for the two-package structure. Every entry point throws
`NotYetImplemented('AP2')` until AP2; the admission rules exist internally and are tested.
Package name provisional (`@aria-registry/ap`) until its owner is confirmed. Private, not
published. The wire profile it will implement is provisional: its vectors
([`conformance/ap`](../../conformance/ap/README.md)) encode the options recommended for
decisions D3, D4, D5 and D8, none of which is taken.

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
  entry point and contains none of its code.
- **Credential and status results are read through the verifier, never from their
  fields.** Wherever ARIA AP receives a `VerifiedCredential` or `StatusEvidence` (a
  receiver's own credential, the status given to `admit`, the credential behind a
  presentation), it calls `verifier.facts(credential)` for the verified data and the
  holder key, and `verifier.standing(credential, status)` for validity, status and
  freshness judged now. Both throw for anything that verifier did not produce: a copy, a
  cast, a hand-made object, another verifier's result. So a fabricated result cannot
  become evidence because ARIA AP accepts its type.
- **What the verifier judges, ARIA AP does not judge again.** Validity, status and
  freshness come from `standing`; ARIA AP adds what is its own: possession bound to the
  request, the receiver, audience, level and scope against the operation, delegation,
  human approval, the application's resource decision, operations and receipts.
- **ARIA AP's own results** (presentations, admissions, claims, outcomes, refusals,
  receipt statements, verified receivers) are recorded by the `Ap` instance that produced
  them and accepted only by it, the same way the verifier treats its own.
- **A duplicated install fails closed.** A second copy of `@aria-registry/sdk` keeps its
  own records: its verifier refuses the first copy's results and the reverse. Nothing
  passes because two copies exist; it just stops working until there is one.
- **Nothing is portable evidence.** Results live in one process. A credential, a request
  or a receipt that crosses a process boundary is verified again where it arrives.

## Results, kept apart

| Result | Says | Does not say |
|---|---|---|
| `VerifiedPresentation` (`verifyPresentation`) | The caller signed this request with the holder key of an exact verified credential, for this receiver, operation and content | That it may do it |
| `Admission` (`admit`) | `allow`, `deny` or `indeterminate`, with a fixed reason | That the operation ran |
| `ReceiptStatement` (`verifyReceipt`) | The expected receiver signed this statement about this attempt or operation | That the business effect is true outside the receiver; a valid receipt can say `rejected` |

Only `allow` lets an operation be claimed and run. There is no mode in which a failed or
missing check becomes `allow`: a receiver observing a policy (the old `monitor`/`warn`)
logs the `deny`, and whatever it then runs is not admitted. The public `admit` always
needs a presentation this instance produced; nothing reaches the rules without one.

**Admission order.** Audience; the credential's standing (`not_valid_now` →
`credential_expired`, `unknown` → `indeterminate`, `revoked`, `superseded`); level; scope;
delegation; human approval, judged at the standing's time; then the application's
resource decision.

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
when the adopter knows its transaction did not commit; `'uncertain'` keeps it, and retries
get `operation_in_progress`. `ledger.reconcile` later decides it from the adopter's own
record of the effect. Since the effect and its signed outcome commit together, a
committed effect already has its stored receipt, which is returned and never regenerated;
an open claim reported as committed breaks that invariant and fails; only an explicit
«not committed» releases the claim, never a timeout alone. The claimed record keeps the
authenticated attempt that claimed it, because a fingerprint cannot rebuild a signature
base.

**`accepted` continues after a restart** through `ledger.resume(key, admission)`: a fresh
admission of the same operation and fingerprint (current status, policy and approval),
then a new claim at the stored revision; one worker gets it, the others are refused. The
final receipt is new; the `accepted` one stays in the immutable history.

Receipts have exactly two sources: an **operation outcome**, recorded by `ledger.settle`
in the business effect's transaction, and an **attempt refusal**, from a denied admission
or a refused claim (`ap.buildAttemptRefusal`). An admission cannot make either. Errors before
authentication are unsigned.

**The client keeps every attempt.** `OperationTracker` holds the operation's binding
(operation id, sender, receiver) and every `SentAttempt`. A receipt's request digest only
selects the kept attempt; signature, receiver, sender and every binding are then checked
against it, so the original receipt returned to a retry with a fresh challenge is
recognised. Every request, a lookup included, uses a new challenge from a fresh receiver
authentication: a lookup consumes its challenge, so the mutation after it needs another.
It moves only on a verified operation receipt of this operation; an attempt
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

## Package and runtimes

- ESM only, with type declarations. Peer dependency: `@aria-registry/sdk` `^1.0.0-alpha.0`;
  each package keeps its own version, and the compatible pair is the one the release
  manifest records after [`../scripts/check-pair.mjs`](../scripts/check-pair.mjs) passed.
- Node.js 20 and 22 (declared). The package has no install scripts and reads no
  environment file.
