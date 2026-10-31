// Compile-time boundaries of the API. Each `@ts-expect-error` must stay an error:
// `tsc` fails if one of these lines starts to compile. The same boundaries are
// checked again at run time (S1, AP2), since a cast gets past any type.
import {
  buildAttemptRefusal,
  inspectCredential,
  OperationLedger,
  type Admission,
  type OperationClaim,
  type Receipt,
  type ReceiverSelf,
  type StatusEvidence,
  type VerifiedCredential,
  type VerifiedPresentation,
  type Verifier,
} from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const ledger: OperationLedger;
declare const self: ReceiverSelf;
declare const presentation: VerifiedPresentation;
declare const status: StatusEvidence;
declare const admission: Admission;
declare const claim: OperationClaim;
declare const receipt: Receipt;

export async function boundaries(): Promise<void> {
  // Inspection is not verification.
  const seen = inspectCredential({});
  // @ts-expect-error an inspection is not a verified credential
  await verifier.checkStatus(seen);

  // A verified credential cannot be typed by hand.
  // @ts-expect-error missing the SDK's private mark
  const forged: VerifiedCredential = { did: 'did:aria:x:y' };
  void forged;

  // No admission without proof of the holder key.
  // @ts-expect-error `presentation` is required
  await verifier.admit({ status, authorize: async () => ({ allowed: true }) });

  // Only an `allow` can claim an operation.
  // @ts-expect-error a deny or indeterminate admission is not `Admitted`
  await ledger.begin(admission);
  if (admission.decision === 'allow') await ledger.begin(admission);

  // An admission cannot make a receipt: not as a settlement, not as a refusal.
  // @ts-expect-error settle needs the claim, not the admission
  await ledger.settle(admission, { state: 'completed', status: 201 });
  // @ts-expect-error a refusal comes from a denied admission or a refused claim
  await buildAttemptRefusal(admission, self);
  if (admission.decision !== 'allow') await buildAttemptRefusal(admission.refusal, self);

  // A completion needs a success status; a refusal of the operation is a 422 with a code.
  // @ts-expect-error `completed` is 200 or 201
  await ledger.settle(claim, { state: 'completed', status: 403 });
  // @ts-expect-error a rejected operation carries its code
  await ledger.settle(claim, { state: 'rejected', status: 422 });

  // A fresh answer is checked against its transport status; a retrieval is not.
  const receiver = { origin: 'https://bank.example', did: 'did:aria:bank.example:transfers' } as const;
  // @ts-expect-error `decision` needs the transport status
  await verifier.verifyReceipt(receipt, { receiver, mode: 'decision' });
  await verifier.verifyReceipt(receipt, { receiver, mode: 'retrieval' });
  // @ts-expect-error historical verification needs the retained receiver credential
  await verifier.verifyReceipt(receipt, { receiver, mode: 'historical' });
  await verifier.verifyReceipt(receipt, { receiver, mode: 'historical', evidence: { receiverCredential: {} } });

  // A copy keeps the type, which is not the boundary: the verifier refuses it at run time (test/provenance.test.ts).
  const credential = (verifier.verifyCredential({}) as Extract<ReturnType<Verifier['verifyCredential']>, { ok: true }>).credential;
  const copy: VerifiedCredential = { ...credential, scopes: ['payments:transfer:create'] };
  void copy;

  // A valid receipt is not a success: callers read its state.
  const checked = await verifier.verifyReceipt(receipt, { receiver, mode: 'retrieval' });
  if (checked.ok && checked.statement.state === 'rejected' && checked.statement.applies === 'attempt') {
    // This attempt was refused; the operation's own outcome is not known from it.
  }
  void presentation;
}
