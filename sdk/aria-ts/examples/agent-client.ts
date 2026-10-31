// The agent's side: authenticate the receiver, sign each attempt, keep every
// attempt, and recover the operation's original receipt after a lost answer,
// without a second effect and without calling an already-sent operation unsent.
import {
  OperationTracker,
  signRequest,
  type CredentialPresentation,
  type Did,
  type HttpRequestLike,
  type Receipt,
  type ReceiverPin,
  type Signer,
  type Verifier,
} from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const signer: Signer; // the holder key, outside the language model
declare const credential: CredentialPresentation;
declare const me: { did: Did; credential: string };
declare function newOperationId(): string;
declare function newNonce(): string;
declare function fetchIdentity(origin: string, nonce: string): Promise<unknown>;
declare function send(request: HttpRequestLike): Promise<{ status: number; receipt?: Receipt } | 'lost'>;
declare function lookup(request: HttpRequestLike): Promise<{ current?: Receipt } | 'lost'>;

const bank: ReceiverPin = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' };

export async function transfer(body: Uint8Array): Promise<{ state: string; lastAttemptError?: string }> {
  // One id per logical operation, reused by every retry; the tracker keeps every attempt.
  const tracker = new OperationTracker({ operationId: newOperationId(), sender: me, receiver: bank });
  let lastAttemptError: string | undefined;

  for (let attempt = 0; attempt < 3 && (tracker.state === 'unknown' || tracker.state === 'accepted'); attempt++) {
    const nonce = newNonce();
    const identity = await verifier.verifyReceiverIdentity(await fetchIdentity(bank.origin, nonce), bank, nonce);
    if (!identity.ok) {
      // This attempt could not be sent; an earlier one may have run. Not "not sent".
      lastAttemptError = `receiver ${identity.reason}`;
      continue;
    }

    // Once an attempt has been sent, ask for the operation's stored outcome first.
    if (tracker.everSent) {
      const { request: signedLookup } = await signRequest({
        request: { method: 'GET', target: `/v1/transfers?operation=${tracker.operation.operationId}`, headers: {} },
        class: 'retrieval',
        receiver: identity.receiver,
        credential,
        signer,
      });
      const stored = await lookup(signedLookup);
      if (stored !== 'lost' && stored.current) {
        await tracker.observe(verifier, stored.current, { mode: 'retrieval' });
        if (tracker.state !== 'unknown') break;
      }
    }

    const { request: signed, sent } = await signRequest({
      request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body },
      class: 'unsafe-body',
      operationId: tracker.operation.operationId,
      receiver: identity.receiver,
      credential,
      signer,
    });
    tracker.record(sent); // kept before sending: the receipt may name this attempt or an earlier one

    const answer = await send(signed);
    if (answer === 'lost' || !answer.receipt) continue; // no conclusive receipt: still unknown, same operation id

    // The receipt names its attempt by digest; the tracker checks it against that kept attempt.
    const seen = await tracker.observe(verifier, answer.receipt, { mode: 'decision', transportStatus: answer.status });
    if (seen.applied === 'none') lastAttemptError = seen.reason;
  }

  // `rejected` means the operation itself was refused, not merely an attempt.
  return lastAttemptError === undefined ? { state: tracker.state } : { state: tracker.state, lastAttemptError };
}
