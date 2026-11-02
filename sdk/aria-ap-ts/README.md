# ARIA AP

`@trustlayer-foundation/aria-ap` is the exchange between an AI agent and a service it
calls. It authenticates the agent's signed request, decides whether to admit it, runs each
operation once and answers with a signed receipt. On the agent's side, it checks who the
service is, signs requests and verifies receipts. It is the TypeScript implementation of
ARIA AP for [ARIA 1.0](https://aria.bar/spec), for Node.js 20 or later, published by
TrustLayer Foundation under Apache-2.0.

## Which package do I need?

| You want to | Install |
|---|---|
| Show or record whether an agent's credential is genuine, current and not revoked | [`@trustlayer-foundation/aria-sdk`](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ts#readme) only |
| Decide whether an agent's request may run, or call such a service as an agent | `@trustlayer-foundation/aria-sdk` and `@trustlayer-foundation/aria-ap` |

```bash
npm install @trustlayer-foundation/aria-sdk @trustlayer-foundation/aria-ap
```

ARIA AP has no credential verification of its own. It reads every credential and status
result through the verifier of the ARIA SDK, which your application creates with its trust
configuration and hands over (`createAp({ credentials: verifier })`). The ARIA SDK is a peer
dependency: your application installs it, and ARIA AP uses that copy.

## How an exchange works

1. **Who is the receiver.** The agent fetches the receiver's signed identity statement,
   with its credential, and checks it against the DID it expects at that origin.
2. **A signed request.** RFC 9421 over the method, target, body digest, operation id, the
   exact credential and the audience, signed with the agent's holder key and a
   single-use challenge from the receiver.
3. **Admission.** The receiver verifies the credential and its current status with the
   ARIA SDK, then checks audience, level, scope, delegation and human approval, then its
   own rule.
4. **Once per operation.** An admitted operation is claimed and settled with a signed
   receipt, `aria-ap-receipt/1`, in the receiver's storage. A retry of the same operation
   gets the original receipt.
5. **Recovery.** After a lost answer, a signed lookup returns the operation's receipts.

## Quick start: a receiver

A receiver with one protected operation, a transfer. `trust` and `fetch` are your trust
configuration, as for the [ARIA SDK](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ts#readme).
The rest is yours as well:
- this receiver's `did` and `origin`;
- its own credential document (`ownDocument`) and the `signer` of its holder key;
- `resolveCredential`, which returns the document of a credential a request names by URL;
- `authorize`, your own resource rule.

```javascript
import { createVerifier } from '@trustlayer-foundation/aria-sdk';
import { createAp, MemoryChallengeStore, MemoryOperationStorage, OperationLedger } from '@trustlayer-foundation/aria-ap';

const verifier = createVerifier({ trust, fetch });
const ap = createAp({ credentials: verifier });
const self = { did, origin, document: ownDocument, credential: verifier.verifyCredential(ownDocument).credential, signer };

// In memory, to try it: a production receiver keeps challenges and operations in durable storage.
const challenges = new MemoryChallengeStore();
const ledger = new OperationLedger(ap, new MemoryOperationStorage(), self);
const transfer = { name: 'transfer', class: 'unsafe-body', method: 'POST', path: '/v1/transfers', mediaType: 'application/json', scope: 'payments:transfer:create', minLevel: 'L1' };
const context = { receiver: { did, origin }, operations: [transfer], challenges, resolveCredential };

/** GET /.well-known/aria/identity?nonce=…&audience=…: who this receiver is, with a fresh challenge. */
export const identity = (nonce, audience) => ap.identify(self, { nonce, audience }, challenges);

/** POST /v1/transfers: authenticate, admit, run once, answer with a signed receipt. */
export async function handle(request) {
  const presented = await ap.verifyPresentation(request, context);
  if (!presented.ok) return { status: presented.status }; // unsigned 400 or 401: the caller proved nothing
  const { presentation } = presented;
  const status = await verifier.checkStatus(presentation.credential);
  const admission = await ap.admit({ presentation, status, authorize });
  if (admission.decision !== 'allow') return { status: admission.refusal.status, receipt: await ap.buildAttemptRefusal(admission.refusal, self) };
  const begun = await ledger.begin(admission);
  if (begun.kind === 'existing') return { status: begun.status, receipt: begun.governing }; // a retry: the original receipt
  if (begun.kind === 'refused') return { status: begun.refusal.status, receipt: await ap.buildAttemptRefusal(begun.refusal, self) };
  // Run the effect here, in the same transaction as `settle` when storage is durable.
  const outcome = await ledger.settle(begun.claim, { state: 'completed', status: 201 });
  return { status: outcome.status, receipt: outcome.receipt };
}
```

An agent calling it uses the same packages:
1. `verifyReceiverIdentity` on the identity statement, against the DID it pinned;
2. `signRequest` with its credential and holder-key signer;
3. `OperationTracker` to verify the receipt it gets back.

See the [agent's client example](https://github.com/trustlayer-foundation/aria-protocol/blob/main/sdk/aria-ap-ts/examples/agent-client.ts).

## What each result tells you

| Result | Says | Does not say |
|---|---|---|
| `VerifiedReceiver` (`verifyReceiverIdentity`) | The pinned DID at the pinned origin signed a fresh statement for this client, with a credential that stood when verified | Anything about the operation |
| `VerifiedPresentation` (`verifyPresentation`) | The caller signed this request with the holder key of an exact verified credential, for this receiver, operation and content | That it may do it |
| `Admission` (`admit`) | `allow`, `deny` or `indeterminate`, with a fixed reason | That the operation ran |
| `ReceiptStatement` (`verifyReceipt`, `OperationTracker.observe`) | The receiver verified earlier signed this statement about one kept attempt | That the receiver stands now; a valid receipt can say `rejected` |

Only `allow` lets an operation run; no failed check becomes `allow`. Each operation's
outcome is a signed receipt, and so is each attempt refused at admission. Two answers are
not signed:
- a request that fails authentication gets an unsigned 400 or 401;
- a lookup returns the stored receipts and gets no receipt of its own; its refusals are
  unsigned.

When an operation's scope requires human approval, a missing or invalid approval refuses
the attempt. Holding an operation for approval is not offered in 1.0.

## Configuration is yours

The ARIA SDK's verifier carries the issuers you trust. ARIA AP adds what the receiver
states:
- its own identity (`self`);
- the operations it serves, each with its class, method, path, scope and minimum level;
- a challenge store and an operation store;
- an optional scope policy (`{ effect: 'allow' | 'deny', pattern }` rules, a matching deny
  winning);
- the `authorize` rule.

Nothing in a request selects any of them.

## Documentation

- [API contract](https://github.com/trustlayer-foundation/aria-protocol/blob/main/sdk/aria-ap-ts/API.md):
  the exchange step by step, the request profile, admission, scopes, operations,
  receipts, retrieval and historical receipts.
- [Examples](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ap-ts/examples):
  a receiver's identity endpoint and protected operation, an agent's client with
  recovery, and the replacement for `if (result.valid) execute()`.
- [ARIA AP schemas](https://github.com/trustlayer-foundation/aria-protocol/tree/main/schema),
  also exported as `@trustlayer-foundation/aria-ap/schemas/<name>.json`, and
  [conformance vectors](https://github.com/trustlayer-foundation/aria-protocol/tree/main/conformance/ap).
- [ARIA SDK](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ts#readme),
  [developer guide](https://aria.bar/developers),
  [ARIA AP step by step](https://aria.bar/protocol) and
  [specification](https://aria.bar/spec).

## Support

- Questions and bugs:
  [GitHub issues](https://github.com/trustlayer-foundation/aria-protocol/issues).
- Security vulnerabilities: security@trustlayer.foundation, never a public issue
  ([security policy](https://github.com/trustlayer-foundation/aria-protocol/blob/main/SECURITY.md)).

## Development

In the [repository](https://github.com/trustlayer-foundation/aria-protocol):
- `pnpm typecheck` compiles the sources, examples, tests and boundary checks against the
  ARIA SDK's sources.
- `pnpm test` runs:
  - the conformance vectors: requests through the real challenge store, fingerprints,
    receipts, historical receipts, receiver identity, scopes, and the sequences against
    the real ledger and tracker;
  - the exchange end to end over a real verifier, and over local HTTP.
- `pnpm build` writes `dist/` against the ARIA SDK's built types; build that first.

The README that npm shows for a version is the one packed in it; this file is newer than
1.0.0's.
