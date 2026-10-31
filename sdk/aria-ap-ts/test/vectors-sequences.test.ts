// AP1 sequences (conformance/ap/vectors/sequences.json) against the real ledger,
// tracker and admission, over both packages. Each label becomes a real value:
// operations are UUIDs, fingerprints are bodies, challenges come from verified
// identity statements, admissions are decided by real credentials and status.
import { describe, expect, it } from 'vitest';
import { AriaUsageError } from '@aria-registry/sdk';
import { InvariantViolation, OperationTracker, StaleClaim, type ApprovalEvidence, type OperationClaim, type Receipt, type VerifiedReceiver } from '../src';
import { newReceiptId } from '../src/internal/instance';
import { RECEIPT_TYPE, signReceipt } from '../src/internal/receipt';
import { load } from './conformance';
import { AGENT, BANK, world, type Holder } from './world';

const sequences = load('vectors/sequences.json');
const OPERATIONS: Record<string, string> = { X: '55ee2e26-ffcc-40ca-b388-d12966453e48', Y: 'e8f70dd3-bc7b-433f-9518-b08e7c662d2d' };
const AMOUNTS: Record<string, string> = { F1: '10.00', F2: '99.00' };

function runner(issued: readonly string[]) {
  const w = world();
  let index = 30;
  const make = (over?: { hitl?: string[]; scopes?: string[] }) => w.holder(AGENT, index++, over);
  let good = make();
  const pool: Record<string, Holder> = {};
  const hitl = () => (pool.hitl ??= make({ hitl: ['payments:transfer:create'] }));
  const revoked = () => {
    if (!pool.revoked) {
      pool.revoked = make();
      w.revoke(index - 1);
    }
    return pool.revoked;
  };
  const noScope = () => (pool.noScope ??= make({ scopes: ['payments:balance:read'] }));

  const receivers = new Map<string, Promise<VerifiedReceiver>>();
  const challenge = (label: string) => {
    if (!issued.includes(label)) throw new Error(`challenge ${label} not issued`);
    if (!receivers.has(label)) receivers.set(label, w.receiver());
    return receivers.get(label)!;
  };
  // Challenges are issued up front, as the sequence declares.
  for (const label of issued) challenge(label);

  const trackers = new Map<string, OperationTracker>();
  const tracker = (op: string) => {
    if (!trackers.has(op)) trackers.set(op, new OperationTracker({ operationId: OPERATIONS[op]!, sender: AGENT, receiver: BANK }));
    return trackers.get(op)!;
  };
  const claims = new Map<string, OperationClaim>();
  const attemptsOf = new Map<string, string>();
  const labels = new Map<string, string>();
  const receiptsByLabel = new Map<string, Receipt>();
  const effects = new Map<string, number>();
  const label = (r: Receipt) => labels.get(r.id) ?? `unlabelled:${r.id}`;
  const keyOf = (op: string) => ({ receiver: BANK.did, sender: AGENT, operationId: OPERATIONS[op]! });

  /** Signs and presents one transfer attempt with the credential and approval the admission label calls for. */
  async function present(op: string, fingerprint: string, receiver: VerifiedReceiver, admission: any) {
    const deny = typeof admission === 'object' ? admission.deny : null;
    let holder = good;
    let approval: ApprovalEvidence | undefined;
    if (deny === 'aria.approval_required' || deny === 'aria.approval_invalid') holder = hitl();
    if (deny === 'aria.credential_revoked') holder = revoked();
    if (deny === 'aria.scope_missing') holder = noScope();
    w.useCredential(holder);
    const attempt = await w.signTransfer(OPERATIONS[op]!, AMOUNTS[fingerprint], receiver);
    w.statusAvailable(deny !== 'aria.status_unavailable');
    const presented = await w.bankAp.verifyPresentation(attempt.request, w.context);
    if (deny === 'aria.approval_invalid' && presented.ok) {
      const valid = { approvalId: 'approval-1', sender: AGENT, credentialId: w.agentCredential.binding.credentialId, operationId: OPERATIONS[op]!, fingerprint: presented.presentation.fingerprint!, expiresAt: '2026-11-01T12:10:00Z' };
      approval = admission.approval === 'expired' ? { ...valid, expiresAt: '2026-11-01T11:59:00Z' } : { ...valid, operationId: OPERATIONS.Y! };
    }
    return { attempt, presented, approval };
  }

  async function admitted(op: string, fingerprint: string, receiver: VerifiedReceiver, admission: any) {
    const { attempt, presented, approval } = await present(op, fingerprint, receiver, admission);
    tracker(op).record(attempt);
    if (!presented.ok) return { attempt, unauthenticated: presented } as const;
    const status = await w.bankVerifier.checkStatus(presented.presentation.credential);
    w.statusAvailable(true);
    const decided = await w.bankAp.admit({ presentation: presented.presentation, status, ...(approval ? { approval } : {}), authorize: async () => ({ allowed: true }) });
    return { attempt, decided } as const;
  }

  async function deliver(op: string, receipt: Receipt, status: number) {
    await tracker(op).observe(w.agentAp, JSON.stringify(receipt), { mode: 'decision', transportStatus: status });
  }

  const steps: Record<string, (s: any) => Promise<unknown>> = {
    async attempt(s) {
      attemptsOf.set(s.attempt, s.operation);
      if (s.arrived === false) {
        w.useCredential(good);
        tracker(s.operation).record(await w.signTransfer(OPERATIONS[s.operation]!, AMOUNTS[s.fingerprint], await challenge(s.challenge)));
        return { lost: true };
      }
      const r = await admitted(s.operation, s.fingerprint, await challenge(s.challenge), s.admission);
      if ('unauthenticated' in r) return { http: r.unauthenticated.status, code: r.unauthenticated.code, subtype: r.unauthenticated.reason };
      const d = r.decided!;
      if (d.decision !== 'allow') {
        const receipt = await w.bankAp.buildAttemptRefusal(d.refusal, w.self);
        if (s.delivered !== false) await deliver(s.operation, receipt, d.refusal.status);
        return { http: d.refusal.status, receipt: { state: receipt.outcome.state, applies: receipt.outcome.applies, code: receipt.outcome.code } };
      }
      const begun = await w.ledger.begin(d);
      if (begun.kind === 'claimed') {
        claims.set(s.attempt, begun.claim);
        return { claimed: true };
      }
      if (begun.kind === 'existing') {
        if (s.delivered !== false) await deliver(s.operation, begun.governing, begun.status);
        return { http: begun.status, receipt: label(begun.governing) };
      }
      const receipt = await w.bankAp.buildAttemptRefusal(begun.refusal, w.self);
      if (s.delivered !== false) await deliver(s.operation, receipt, begun.refusal.status);
      return { http: begun.refusal.status, receipt: { state: 'rejected', applies: 'attempt', code: begun.refusal.code } };
    },

    async settle(s) {
      const claim = claims.get(s.attempt);
      // Without a claim object a worker cannot call settle at all; the model tells
      // "no record" from "a record another worker holds or closed".
      if (!claim) return { error: (await w.storage.get(keyOf(attemptsOf.get(s.attempt)!))) ? 'stale_claim' : 'no_claim' };
      const settlement = s.outcome === 'completed' ? { state: 'completed', status: 201 } : s.outcome === 'accepted' ? { state: 'accepted', status: 202 } : { state: 'rejected', status: 422, code: s.outcome.rejected };
      try {
        const outcome = await w.ledger.settle(claim, settlement as never);
        labels.set(outcome.receipt.id, s.receipt);
        receiptsByLabel.set(s.receipt, outcome.receipt);
        const op = attemptsOf.get(s.attempt)!;
        if (s.outcome === 'completed') effects.set(op, (effects.get(op) ?? 0) + 1);
        if (s.delivered !== false) await deliver(op, outcome.receipt, outcome.status);
        return { http: outcome.status, receipt: s.receipt };
      } catch (error) {
        if (error instanceof StaleClaim) return { error: 'stale_claim' };
        throw error;
      }
    },

    async fail(s) {
      const claim = claims.get(s.attempt);
      if (!claim) return { error: 'stale_claim' };
      try {
        await w.ledger.fail(claim, s.how);
        return s.how === 'uncertain' ? { kept: true } : { released: true };
      } catch (error) {
        if (error instanceof StaleClaim) return { error: 'stale_claim' };
        throw error;
      }
    },

    async reconcile(s) {
      try {
        const r = await w.ledger.reconcile(keyOf(s.operation), { committed: s.committed });
        return r.kind === 'committed' ? { receipt: label(r.current) } : { [r.kind]: true };
      } catch (error) {
        if (error instanceof InvariantViolation) return { error: 'invariant_violation' };
        throw error;
      }
    },

    async resume(s) {
      attemptsOf.set(s.attempt, s.operation);
      const r = await admitted(s.operation, s.fingerprint, await w.receiver(), s.admission);
      if ('unauthenticated' in r) throw new Error('resume could not authenticate');
      const d = r.decided!;
      if (d.decision !== 'allow') return { denied: d.refusal.code };
      try {
        const begun = await w.ledger.resume(keyOf(s.operation), d);
        if (begun.kind === 'claimed') {
          claims.set(s.attempt, begun.claim);
          return { claimed: true };
        }
        if (begun.kind === 'refused') return { refused: begun.refusal.code };
        return { error: 'not_accepted' };
      } catch (error) {
        if (error instanceof AriaUsageError) return { error: 'not_accepted' };
        throw error;
      }
    },

    async lookup(s) {
      const receiver = await challenge(s.challenge);
      w.useCredential(s.credential === 'revoked' ? revoked() : good);
      const signed = await w.agentAp.signRequest({ request: { method: 'GET', target: `/v1/operations?operation=${OPERATIONS[s.operation]}`, headers: {} }, class: 'retrieval', receiver, credential: w.agentCredential, signer: (s.credential === 'revoked' ? revoked() : good).signer });
      const answer = await w.handle(signed.request);
      if (answer.status === 401) return { http: 401, code: 'aria.authentication_failed', subtype: answer.problem!.split('/')[1] };
      if (answer.status !== 200) return { http: answer.status, code: answer.problem, signed: false };
      if (s.delivered !== false) await tracker(s.operation).observeLookup(w.agentAp, { history: answer.history!.map((r) => JSON.stringify(r)) });
      return { http: 200, current: answer.current ? label(answer.current) : null, history: answer.history!.map(label) };
    },

    async 'client-observe'(s) {
      let receipt = receiptsByLabel.get(s.receipt.label);
      if (!receipt) {
        // A receiver that signs a second, different outcome for the same operation.
        const kept = tracker(s.operation).attempts[0]!;
        receipt = await signReceipt(
          {
            type: RECEIPT_TYPE,
            id: newReceiptId(),
            request: { id: kept.operationId, sender: kept.sender, digest: kept.requestDigest },
            receiver: kept.receiver,
            issuedAt: '2026-11-01T12:00:30Z',
            outcome: { state: s.receipt.state, applies: s.receipt.applies, status: s.receipt.http, code: s.receipt.code },
          },
          w.self.signer,
        );
        labels.set(receipt.id, s.receipt.label);
      }
      await deliver(s.operation, receipt, s.receipt.http);
      return { observed: s.receipt.label };
    },

    async check(s) {
      const record = await w.storage.get(keyOf(s.operation));
      return { effects: effects.get(s.operation) ?? 0, record: record?.state ?? 'absent', receipts: record ? record.receipts.map(label) : [], everSent: tracker(s.operation).everSent };
    },
  };

  return {
    async step(s: any) {
      const handler = steps[s.do];
      if (!handler) throw new Error(`unknown step ${s.do}`);
      const result = await handler(s);
      const op = s.operation ?? attemptsOf.get(s.attempt);
      return { result, client: op ? tracker(op).state : undefined };
    },
  };
}

describe('AP1 sequences against the implementation', () => {
  for (const sequence of sequences.sequences) {
    it(`${sequence.id}: ${sequence.title}`, async () => {
      const run = runner(sequence.issued ?? []);
      for (const [i, s] of sequence.steps.entries()) {
        const { result, client } = await run.step(s);
        if (s.expect !== undefined) expect(result, `step ${i + 1} (${s.do})`).toEqual(s.expect);
        if (s.client !== undefined) expect(client, `step ${i + 1} (${s.do}) client`).toBe(s.client);
      }
    });
  }
});
