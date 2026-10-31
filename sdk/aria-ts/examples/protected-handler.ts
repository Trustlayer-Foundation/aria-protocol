// A receiver's protected operation: authenticate, admit, claim, run once, sign.
import {
  buildAttemptRefusal,
  OperationLedger,
  type ChallengeStore,
  type HttpRequestLike,
  type OperationDescriptor,
  type OperationStorage,
  type Receipt,
  type ReceiverSelf,
  type Verifier,
} from '@aria-registry/sdk';

declare const verifier: Verifier;
declare const self: ReceiverSelf; // the bank's own identity and signer
declare const challenges: ChallengeStore;
declare const storage: OperationStorage; // the bank's database
declare function inTransaction<T>(work: () => Promise<T>): Promise<T>;
declare function moveMoney(body: Uint8Array): Promise<{ ok: true } | { ok: false; code: string }>;
declare function rolledBack(error: unknown): boolean; // true only when the bank knows its transaction did not commit
declare function accountGranted(sender: string, body: Uint8Array | undefined): Promise<boolean>;

const transfer: OperationDescriptor = {
  name: 'transfer',
  class: 'unsafe-body',
  method: 'POST',
  path: '/v1/transfers',
  mediaType: 'application/json',
  scope: 'payments:transfer:create',
  minLevel: 'L1',
  onMissingApproval: 'refuse',
};

const ledger = new OperationLedger(storage, self);

type Answer = { status: number; receipt?: Receipt; problem?: string; challenge?: string };

export async function handle(request: HttpRequestLike): Promise<Answer> {
  // 1. Who is asking. Failures here are unsigned: nothing is attributed to a DID that proved no key.
  const presented = await verifier.verifyPresentation(request, { receiver: self, operations: [transfer], challenges });
  if (!presented.ok) {
    return presented.challenge === undefined
      ? { status: presented.status, problem: presented.reason }
      : { status: presented.status, problem: presented.reason, challenge: presented.challenge };
  }
  const { presentation } = presented;

  // 2. Admission: the exact document's status, level, scope, human approval and the bank's own rule.
  const status = await verifier.checkStatus(presentation.credential);
  const admission = await verifier.admit({
    presentation,
    status,
    authorize: async ({ presentation: p }) =>
      (await accountGranted(p.credential.did, request.body)) ? { allowed: true } : { allowed: false, code: 'bank.account_not_granted' },
  });
  if (admission.decision !== 'allow') {
    // An authenticated refusal of this attempt only: the operation is not claimed.
    return { status: admission.refusal.status, receipt: await buildAttemptRefusal(admission.refusal, self) };
  }

  // 3. The operation: once per operation id, whatever the number of attempts.
  const begun = await ledger.begin(admission);
  if (begun.kind === 'existing') return { status: begun.status, receipt: begun.governing };
  if (begun.kind === 'refused') return { status: begun.refusal.status, receipt: await buildAttemptRefusal(begun.refusal, self) };

  // 4. The effect and its outcome commit together; the receipt comes from the recorded outcome.
  try {
    const outcome = await inTransaction(async () => {
      const moved = await moveMoney(request.body ?? new Uint8Array());
      return ledger.settle(begun.claim, moved.ok ? { state: 'completed', status: 201 } : { state: 'rejected', status: 422, code: moved.code });
    });
    return { status: outcome.status, receipt: outcome.receipt };
  } catch (error) {
    // No receipt either way; the client stays unknown and retries the same operation.
    // Release only a proven rollback. If the commit is uncertain the claim stays,
    // retries get `operation_in_progress`, and `ledger.reconcile` decides later from the bank's records.
    await ledger.fail(begun.claim, rolledBack(error) ? 'rolled-back' : 'uncertain');
    return { status: 500, problem: 'internal' };
  }
}
