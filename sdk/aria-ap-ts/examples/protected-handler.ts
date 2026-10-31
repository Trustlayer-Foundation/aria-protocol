// A receiver's side: its identity statement, then each protected request:
// authenticate, admit, claim, run once, sign; and the signed lookup that recovers
// an operation's receipts after a lost answer.
import { createAp, OperationLedger, type ChallengeStore, type HttpRequestLike, type IdentityResponse, type OperationDescriptor, type OperationStorage, type Receipt, type ReceiverSelf } from '@aria-registry/ap';
import type { Verifier } from '@aria-registry/sdk';

declare const verifier: Verifier; // the credential verifier, with the bank's trust profiles
declare const self: ReceiverSelf; // the bank's own identity, credential document and signer
declare const challenges: ChallengeStore; // shared by the bank's instances; consume is atomic
declare const storage: OperationStorage; // the bank's database
declare function credentialDocument(url: string): Promise<unknown>; // bounded fetch or cache of AID documents
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
const lookup: OperationDescriptor = { name: 'lookup', class: 'retrieval', method: 'GET', path: '/v1/operations', query: ['operation'] };

// ARIA AP builds on that verifier: credential and status results are read through it.
const ap = createAp({ credentials: verifier });
const ledger = new OperationLedger(ap, storage, self);
const context = { receiver: { did: self.did, origin: self.origin }, operations: [transfer, lookup], challenges, resolveCredential: credentialDocument };

/** `GET /.well-known/aria/identity?nonce=…&audience=…`: who the bank is, and a challenge for the client's next request. */
export function identity(nonce: string, audience: string): Promise<IdentityResponse> {
  return ap.identify(self, { nonce, audience }, challenges);
}

type Answer = { status: number; receipt?: Receipt; problem?: string; current?: Receipt | null; history?: readonly Receipt[] };

export async function handle(request: HttpRequestLike): Promise<Answer> {
  // 1. Who is asking. Failures here are unsigned: nothing is attributed to a DID that proved no key.
  const presented = await ap.verifyPresentation(request, context);
  if (!presented.ok) return { status: presented.status, problem: `${presented.code} (${presented.reason})` };
  const { presentation } = presented;
  const status = await verifier.checkStatus(presentation.credential);

  // A lookup: a current credential of the operation's sender reads its stored receipts, and gets none of its own.
  if (presentation.operation.class === 'retrieval') {
    const allowed = await ap.admitLookup({ presentation, status });
    if (allowed.decision !== 'allow') return { status: allowed.status, problem: allowed.code };
    const found = await ledger.lookup(allowed);
    return found ? { status: 200, current: found.current, history: found.history } : { status: 404, problem: 'aria.operation_unknown' };
  }

  // 2. Admission: the exact document's status, level, scope, human approval and the bank's own rule.
  const admission = await ap.admit({
    presentation,
    status,
    authorize: async ({ presentation: p }) =>
      (await accountGranted(p.credential.did, request.body)) ? { allowed: true } : { allowed: false, code: 'bank.account_not_granted' },
  });
  if (admission.decision !== 'allow') {
    // An authenticated refusal of this attempt only: the operation is not claimed.
    return { status: admission.refusal.status, receipt: await ap.buildAttemptRefusal(admission.refusal, self) };
  }

  // 3. The operation: once per operation id, whatever the number of attempts.
  const begun = await ledger.begin(admission);
  if (begun.kind === 'existing') return { status: begun.status, receipt: begun.governing };
  if (begun.kind === 'refused') return { status: begun.refusal.status, receipt: await ap.buildAttemptRefusal(begun.refusal, self) };

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
