// The agent's side: authenticate the receiver, sign each attempt, keep every
// attempt, and recover the operation's original receipt after a lost answer,
// without a second effect and without calling an already-sent operation unsent.
import { createAp, OperationTracker, type HttpRequestLike, type Receipt, type ReceiverPin, type Signer, type VerifiedReceiver } from '@trustlayer-foundation/aria-ap';
import type { Did, Verifier, VerifiedCredential } from '@trustlayer-foundation/aria-sdk';

declare const verifier: Verifier; // the credential verifier, with the agent's trust profiles
const ap = createAp({ credentials: verifier });
declare const signer: Signer; // the holder key, outside the language model
declare const credential: VerifiedCredential; // the agent's own credential, verified by `verifier`
declare const me: Did;
declare function newOperationId(): string;
declare function newNonce(): string; // 32 random bytes, base64url
declare function fetchIdentity(origin: string, nonce: string, audience: Did): Promise<unknown>;
declare function send(request: HttpRequestLike): Promise<{ status: number; receipt?: Receipt } | 'lost'>;
declare function lookup(request: HttpRequestLike): Promise<{ status: number; history?: readonly unknown[] } | 'lost'>;

const bank: ReceiverPin = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' };

/** A freshly authenticated receiver with a new single-use challenge: one per request, never reused. */
async function freshReceiver(): Promise<VerifiedReceiver | string> {
  const nonce = newNonce();
  const identity = await ap.verifyReceiverIdentity(await fetchIdentity(bank.origin, nonce, me), bank, { nonce, audience: me });
  return identity.ok ? identity.receiver : `receiver ${identity.reason}`;
}

export async function transfer(body: Uint8Array): Promise<{ state: string; lastAttemptError?: string }> {
  // One id per logical operation, reused by every retry; the tracker keeps every attempt.
  const tracker = new OperationTracker({ operationId: newOperationId(), sender: me, receiver: bank });
  let lastAttemptError: string | undefined;

  for (let attempt = 0; attempt < 3 && (tracker.state === 'unknown' || tracker.state === 'accepted'); attempt++) {
    // Once an attempt has been sent, ask for the operation's stored outcome first, under its own challenge.
    if (tracker.everSent) {
      const receiver = await freshReceiver();
      if (typeof receiver === 'string') {
        // This lookup could not be sent; an earlier attempt may have run. Not "not sent".
        lastAttemptError = receiver;
        continue;
      }
      const { request: signedLookup } = await ap.signRequest({
        request: { method: 'GET', target: `/v1/operations?operation=${tracker.operation.operationId}`, headers: {} },
        class: 'retrieval',
        receiver,
        credential,
        signer,
      });
      const stored = await lookup(signedLookup);
      if (stored !== 'lost' && stored.status === 200 && stored.history) {
        if ((await tracker.observeLookup(ap, { history: stored.history })) !== 'unknown') break;
      }
    }

    // The mutation gets a new challenge: the lookup consumed the previous one.
    const receiver = await freshReceiver();
    if (typeof receiver === 'string') {
      lastAttemptError = receiver;
      continue;
    }
    const signed = await ap.signRequest({
      request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body },
      class: 'unsafe-body',
      operationId: tracker.operation.operationId,
      receiver,
      credential,
      signer,
    });
    tracker.record(signed); // kept before sending: the receipt may name this attempt or an earlier one

    const answer = await send(signed.request);
    if (answer === 'lost' || !answer.receipt) continue; // no conclusive receipt: still unknown, same operation id

    // The receipt names its attempt by digest; the tracker checks it against that kept attempt.
    const seen = await tracker.observe(ap, answer.receipt, { mode: 'decision', transportStatus: answer.status });
    if (seen.applied === 'none') lastAttemptError = seen.reason;
  }

  // `rejected` means the operation itself was refused, not merely an attempt.
  return lastAttemptError === undefined ? { state: tracker.state } : { state: tracker.state, lastAttemptError };
}
