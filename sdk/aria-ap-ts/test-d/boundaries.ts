// Compile-time boundaries of the ARIA AP API. Each `@ts-expect-error` must stay an
// error: `tsc` fails if one of these lines starts to compile. The same boundaries
// are checked again at run time (AP2), since a cast gets past any type.
import { OperationLedger, type Admission, type Ap, type OperationClaim, type Receipt, type ReceiverSelf, type VerifiedPresentation } from '@aria-registry/ap';
import type { CredentialFacts, Standing, StatusEvidence, VerifiedCredential } from '@aria-registry/sdk';

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

  // A fresh answer is checked against its transport status; a retrieval is not.
  const receiver = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' } as const;
  // @ts-expect-error `decision` needs the transport status
  await ap.verifyReceipt(receipt, { receiver, mode: 'decision' });
  await ap.verifyReceipt(receipt, { receiver, mode: 'retrieval' });
  // @ts-expect-error historical verification needs the retained receiver credential
  await ap.verifyReceipt(receipt, { receiver, mode: 'historical' });
  await ap.verifyReceipt(receipt, { receiver, mode: 'historical', evidence: { receiverCredential: {} } });

  // A valid receipt is not a success: callers read its state.
  const checked = await ap.verifyReceipt(receipt, { receiver, mode: 'retrieval' });
  if (checked.ok && checked.statement.state === 'rejected' && checked.statement.applies === 'attempt') {
    // This attempt was refused; the operation's own outcome is not known from it.
  }
  void presentation;
}
