// The agent's side: authenticate the receiver, sign the attempt, check the receipt,
// and retry the same operation without a second effect.
import {
  OperationTracker,
  signRequest,
  type CredentialPresentation,
  type HttpRequestLike,
  type Receipt,
  type ReceiverPin,
  type SentAttempt,
  type Signer,
  type Verifier,
} from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const signer: Signer; // the holder key, outside the language model
declare const credential: CredentialPresentation;
declare function newOperationId(): string;
declare function newNonce(): string;
declare function fetchIdentity(origin: string, nonce: string): Promise<unknown>;
declare function send(request: HttpRequestLike): Promise<{ status: number; receipt?: Receipt } | 'lost'>;
declare function keep(sent: SentAttempt): void; // the evidence the client retains

const bank: ReceiverPin = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' };

export async function transfer(body: Uint8Array): Promise<string> {
  const operationId = newOperationId(); // one per logical operation, reused by every retry
  const tracker = new OperationTracker(operationId);

  for (let attempt = 0; attempt < 3 && (tracker.state === 'unknown' || tracker.state === 'accepted'); attempt++) {
    const nonce = newNonce();
    const identity = await verifier.verifyReceiverIdentity(await fetchIdentity(bank.origin, nonce), bank, nonce);
    if (!identity.ok) return `not sent: receiver ${identity.reason}`;

    const request: HttpRequestLike = {
      method: 'POST',
      target: '/v1/transfers',
      headers: { 'content-type': 'application/json' },
      body,
    };
    const { request: signed, sent } = await signRequest({
      request,
      class: 'unsafe-body',
      operationId,
      receiver: identity.receiver,
      credential,
      signer,
    });
    keep(sent);

    const answer = await send(signed);
    if (answer === 'lost' || !answer.receipt) continue; // no conclusive receipt: still unknown, same operation id

    const checked = await verifier.verifyReceipt(answer.receipt, { receiver: bank, sent, mode: 'decision', transportStatus: answer.status });
    if (checked.ok) tracker.apply(checked); // an attempt refusal leaves the operation's state as it was
  }

  // `rejected` here means the operation itself was refused, not merely an attempt.
  return tracker.state;
}
