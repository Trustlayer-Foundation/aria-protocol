// Compile-time boundaries of the ARIA AP API. Each `@ts-expect-error` must stay an
// error: `tsc` fails if one of these lines starts to compile. The same boundaries
// are checked again at run time, since a cast gets past any type.
import { OperationLedger, OperationTracker, type Admission, type Ap, type HistoricalStatement, type OperationClaim, type Receipt, type ReceiptStatement, type ReceiverSelf, type SentAttempt, type Signer, type VerifiedPresentation, type VerifiedReceiver } from '@aria-registry/ap';
import type { AuthenticCredential, CredentialFacts, RetainedStatus, Standing, StatusEvidence, VerifiedCredential } from '@aria-registry/sdk';

declare const ap: Ap;
declare const ledger: OperationLedger;
declare const self: ReceiverSelf;
declare const presentation: VerifiedPresentation;
declare const status: StatusEvidence;
declare const admission: Admission;
declare const claim: OperationClaim;
declare const receipt: Receipt;
declare const credential: VerifiedCredential;
declare const facts: CredentialFacts;
declare const standing: Standing;
declare const receiver: VerifiedReceiver;
declare const attempts: readonly SentAttempt[];
declare const signer: Signer;
declare const tracker: OperationTracker;
declare const authentic: AuthenticCredential;
declare const retained: RetainedStatus;
declare const historical: HistoricalStatement;

export async function boundaries(): Promise<void> {
  // No admission without proof of the holder key.
  // @ts-expect-error `presentation` is required
  await ap.admit({ status, authorize: async () => ({ allowed: true }) });

  // Admission takes the credential verifier's results, never what its trust interface returns.
  // @ts-expect-error a standing is a judgment, not status evidence
  await ap.admit({ presentation, status: standing, authorize: async () => ({ allowed: true }) });
  // @ts-expect-error facts are data, not a presentation
  await ap.admit({ presentation: facts, status, authorize: async () => ({ allowed: true }) });
  // @ts-expect-error a verified credential is not a presentation: the document says nothing about who presents it
  await ap.admit({ presentation: credential, status, authorize: async () => ({ allowed: true }) });

  // Only an `allow` can claim an operation.
  // @ts-expect-error a deny or indeterminate admission is not `Admitted`
  await ledger.begin(admission);
  if (admission.decision === 'allow') await ledger.begin(admission);

  // An admission cannot make a receipt: not as a settlement, not as a refusal.
  // @ts-expect-error settle needs the claim, not the admission
  await ledger.settle(admission, { state: 'completed', status: 201 });
  // @ts-expect-error a refusal comes from a denied admission or a refused claim
  await ap.buildAttemptRefusal(admission, self);
  if (admission.decision !== 'allow') await ap.buildAttemptRefusal(admission.refusal, self);

  // A completion needs a success status; a refusal of the operation is a 422 with a code.
  // @ts-expect-error `completed` is 200 or 201
  await ledger.settle(claim, { state: 'completed', status: 403 });
  // @ts-expect-error a rejected operation carries its code
  await ledger.settle(claim, { state: 'rejected', status: 422 });

  // A receipt is checked against the receiver the client verified, never against a pin it typed.
  const pin = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' } as const;
  // @ts-expect-error a pin is not a verified receiver
  await ap.verifyReceipt(receipt, { receiver: pin, attempts, mode: 'retrieval' });
  // A fresh answer is checked against its transport status; a retrieval is not.
  // @ts-expect-error `decision` needs the transport status
  await ap.verifyReceipt(receipt, { receiver, attempts, mode: 'decision' });
  await ap.verifyReceipt(receipt, { receiver, attempts, mode: 'decision', transportStatus: 201 });
  await ap.verifyReceipt(receipt, { receiver, attempts, mode: 'retrieval' });
  // Historical verification is a separate API (verifyHistoricalReceipt), not a mode of verifyReceipt.
  // @ts-expect-error verifyReceipt has no historical mode
  await ap.verifyReceipt(receipt, { receiver, attempts, mode: 'historical' });

  // A valid receipt is not a success: callers read its state.
  const checked = await ap.verifyReceipt(receipt, { receiver, attempts, mode: 'retrieval' });
  if (checked.ok && checked.statement.state === 'rejected' && checked.statement.applies === 'attempt') {
    // This attempt was refused; the operation's own outcome is not known from it.
  }

  // A lookup reads receipts only once admitted, and only as allowed.
  const lookup = await ap.admitLookup({ presentation, status });
  // @ts-expect-error a denied lookup reads nothing
  await ledger.lookup(lookup);
  // @ts-expect-error an operation key is not an admitted lookup
  await ledger.lookup({ receiver: pin.did, sender: credential.did, operationId: 'x' });
  if (lookup.decision === 'allow') await ledger.lookup(lookup);

  // The agent signs with its verified credential; the trust interface's data is not one.
  // @ts-expect-error facts are not a verified credential
  await ap.signRequest({ request: { method: 'POST', target: '/', headers: {} }, class: 'unsafe-body', receiver, credential: facts, signer });

  // The tracker keeps signed attempts, with the receiver they were signed for.
  // @ts-expect-error a bare sent attempt does not say which receiver to check against
  tracker.record(attempts[0]!);

  // Historical authenticity authorizes nothing now, and is not a live result.
  // @ts-expect-error an authentic credential is not a verified one
  await ap.signRequest({ request: { method: 'POST', target: '/', headers: {} }, class: 'unsafe-body', receiver, credential: authentic, signer });
  // @ts-expect-error a retained status is not status evidence
  await ap.admit({ presentation, status: retained, authorize: async () => ({ allowed: true }) });
  // @ts-expect-error a historical statement is not a live receipt statement
  const live: ReceiptStatement = historical;
  // @ts-expect-error historical evidence takes an authentic credential, not a verified one
  await ap.verifyHistoricalReceipt(receipt, { attempts, evidence: { credential } });
  await ap.verifyHistoricalReceipt(receipt, { attempts, evidence: { credential: authentic, status: retained } });
  void live;
  void presentation;
}
