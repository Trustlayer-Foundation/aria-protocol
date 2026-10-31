// The exchange end to end over both packages: a real admission, the refusals that
// must not reach the application's authorizer or the effect, and the recovery of
// the original operation receipt after a lost answer.
import { describe, expect, it } from 'vitest';
import { AriaUsageError } from '@aria-registry/sdk';
import { createAp, OperationTracker } from '../src';
import { AGENT, BANK, NOW, world } from './world';

const OP = '55ee2e26-ffcc-40ca-b388-d12966453e48';
const OP2 = 'e8f70dd3-bc7b-433f-9518-b08e7c662d2d';

describe('a legitimate operation', () => {
  it('is authenticated, admitted, run once and answered with a completed receipt the client verifies', async () => {
    const w = world();
    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const attempt = await w.signTransfer(OP);
    tracker.record(attempt);
    const answer = await w.handle(attempt.request);
    expect(answer.status).toBe(201);
    expect(answer.receipt?.outcome).toMatchObject({ state: 'completed', applies: 'operation', code: 'aria.completed' });
    expect(await tracker.observe(w.agentAp, JSON.stringify(answer.receipt), { mode: 'decision', transportStatus: 201 })).toEqual({ applied: 'operation', state: 'completed' });
    expect(w.effects).toBe(1);
  });

  it('after a lost answer, a retry with a fresh challenge gets the original receipt and no second effect', async () => {
    const w = world();
    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const first = await w.signTransfer(OP);
    tracker.record(first);
    const lost = await w.handle(first.request);
    expect(tracker.state).toBe('unknown');

    const retry = await w.signTransfer(OP);
    tracker.record(retry);
    expect(retry.sent!.requestDigest).not.toBe(first.sent!.requestDigest);
    const answer = await w.handle(retry.request);
    expect(answer).toEqual({ status: 201, receipt: lost.receipt });
    // The receipt names the first attempt; the tracker kept it, so the binding holds.
    expect(answer.receipt!.request.digest).toBe(first.sent!.requestDigest);
    expect(await tracker.observe(w.agentAp, answer.receipt, { mode: 'decision', transportStatus: 201 })).toEqual({ applied: 'operation', state: 'completed' });
    expect(w.effects).toBe(1);
  });

  it('is recovered by a signed lookup, which gets no receipt of its own', async () => {
    const w = world();
    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const attempt = await w.signTransfer(OP);
    tracker.record(attempt);
    await w.handle(attempt.request); // lost
    const lookup = await w.signLookup(OP);
    expect(lookup.sent).toBeNull();
    const found = await w.handle(lookup.request);
    expect(found.status).toBe(200);
    expect(found.history).toHaveLength(1);
    expect(await tracker.observeLookup(w.agentAp, { history: found.history!.map((r) => JSON.stringify(r)) })).toBe('completed');
    expect(w.effects).toBe(1);
  });

  it('a lookup of an operation the receiver never recorded answers 404 and leaves the client unknown', async () => {
    const w = world();
    const found = await w.handle((await w.signLookup(OP)).request);
    expect(found).toEqual({ status: 404, problem: 'aria.operation_unknown' });
  });
});

describe('cross-package substitutions are refused before the authorizer or the effect', () => {
  it('status evidence from another credential verifier', async () => {
    const w = world();
    const presented = await w.bankAp.verifyPresentation((await w.signTransfer(OP)).request, w.context);
    if (!presented.ok) throw new Error(presented.reason);
    // The agent's verifier checked the same document: its evidence is not the bank verifier's.
    const foreign = await w.agentVerifier.checkStatus(w.agentCredential);
    await expect(w.bankAp.admit({ presentation: presented.presentation, status: foreign, authorize: async () => ({ allowed: true }) })).rejects.toThrow(AriaUsageError);
    expect([w.authorizations, w.effects]).toEqual([0, 0]);
  });

  it('status evidence about another document of the same verifier: indeterminate, signed 503, nothing claimed', async () => {
    const w = world();
    const presented = await w.bankAp.verifyPresentation((await w.signTransfer(OP)).request, w.context);
    if (!presented.ok) throw new Error(presented.reason);
    const otherStatus = await w.bankVerifier.checkStatus(w.self.credential);
    let called = false;
    const admission = await w.bankAp.admit({ presentation: presented.presentation, status: otherStatus, authorize: async () => ((called = true), { allowed: true }) });
    expect(admission).toMatchObject({ decision: 'indeterminate', reason: 'status_unavailable', refusal: { status: 503, code: 'aria.status_unavailable' } });
    expect(called).toBe(false);
    expect(await w.storage.get({ receiver: BANK.did, sender: AGENT, operationId: OP })).toBeNull();
  });

  it("another ARIA AP instance's presentation, and copies of a presentation", async () => {
    const w = world();
    const request = (await w.signTransfer(OP)).request;
    const presented = await w.bankAp.verifyPresentation(request, w.context);
    if (!presented.ok) throw new Error(presented.reason);
    const status = await w.bankVerifier.checkStatus(presented.presentation.credential);
    const otherAp = createAp({ credentials: w.bankVerifier, clock: () => new Date(w.now) });
    const authorize = async () => ({ allowed: true as const });
    await expect(otherAp.admit({ presentation: presented.presentation, status, authorize })).rejects.toThrow(AriaUsageError);
    await expect(w.bankAp.admit({ presentation: { ...presented.presentation }, status, authorize })).rejects.toThrow(AriaUsageError);
    await expect(w.bankAp.admit({ presentation: w.agentCredential as never, status, authorize })).rejects.toThrow(AriaUsageError);
    expect(w.effects).toBe(0);
  });

  it('an admission, claim or refusal of another instance cannot drive this ledger or sign', async () => {
    const w = world();
    const other = world();
    const admitted = async (x: ReturnType<typeof world>) => {
      const p = await x.bankAp.verifyPresentation((await x.signTransfer(OP)).request, x.context);
      if (!p.ok) throw new Error(p.reason);
      return x.bankAp.admit({ presentation: p.presentation, status: await x.bankVerifier.checkStatus(p.presentation.credential), authorize: async () => ({ allowed: true }) });
    };
    const foreign = await admitted(other);
    if (foreign.decision !== 'allow') throw new Error('expected allow');
    await expect(w.ledger.begin(foreign)).rejects.toThrow(AriaUsageError);
    await expect(w.ledger.begin({ ...foreign })).rejects.toThrow(AriaUsageError);
    const begun = await other.ledger.begin(foreign);
    if (begun.kind !== 'claimed') throw new Error('expected a claim');
    await expect(w.ledger.settle(begun.claim, { state: 'completed', status: 201 })).rejects.toThrow(AriaUsageError);
  });
});

describe('an admission is not an execution', () => {
  it('a denied or indeterminate admission cannot claim, whatever its type says', async () => {
    const w = world({ level: 'L0' });
    const presented = await w.bankAp.verifyPresentation((await w.signTransfer(OP)).request, w.context);
    if (!presented.ok) throw new Error(presented.reason);
    const denied = await w.bankAp.admit({ presentation: presented.presentation, status: await w.bankVerifier.checkStatus(presented.presentation.credential), authorize: async () => ({ allowed: true }) });
    expect(denied.decision).toBe('deny');
    await expect(w.ledger.begin(denied as never)).rejects.toThrow(AriaUsageError);
    await expect(w.ledger.begin({ ...denied, decision: 'allow' } as never)).rejects.toThrow(AriaUsageError);
    expect(await w.storage.get({ receiver: BANK.did, sender: AGENT, operationId: OP })).toBeNull();
  });
});

describe('the operation minimum level through public admission', () => {
  it('refuses a lower level with a signed attempt refusal and admits the same level', async () => {
    const w = world({ level: 'L0' });
    const low = await w.handle((await w.signTransfer(OP)).request);
    expect(low.status).toBe(403);
    expect(low.receipt?.outcome).toEqual({ state: 'rejected', applies: 'attempt', status: 403, code: 'aria.level_insufficient' });
    expect(w.authorizations).toBe(0);

    w.useCredential(w.holder(AGENT, 21, { level: 'L1' }));
    expect((await w.handle((await w.signTransfer(OP2)).request)).status).toBe(201);
  });
});

describe('the revocation path (R2a, provisional D4)', () => {
  it('a revoked credential is refused per attempt and reads nothing; the renewed one of the same DID retrieves the original', async () => {
    const w = world();
    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const first = await w.signTransfer(OP);
    tracker.record(first);
    const original = await w.handle(first.request); // completed, answer lost

    w.revoke(11);
    const retry = await w.signTransfer(OP);
    tracker.record(retry);
    const refused = await w.handle(retry.request);
    expect(refused.receipt?.outcome).toEqual({ state: 'rejected', applies: 'attempt', status: 403, code: 'aria.credential_revoked' });
    expect(await tracker.observe(w.agentAp, refused.receipt, { mode: 'decision', transportStatus: 403 })).toEqual({ applied: 'attempt', state: 'unknown' });
    expect(await w.handle((await w.signLookup(OP)).request)).toEqual({ status: 403, problem: 'aria.credential_revoked' });

    w.useCredential(w.holder(AGENT, 22));
    const found = await w.handle((await w.signLookup(OP)).request);
    expect(found).toMatchObject({ status: 200, current: original.receipt });
    expect(await tracker.observeLookup(w.agentAp, { history: found.history! })).toBe('completed');
    expect(w.effects).toBe(1);
  });
});

describe('one operation, one effect', () => {
  it('other content under the same operation id is a conflict that changes nothing', async () => {
    const w = world();
    const original = await w.handle((await w.signTransfer(OP, '10.00')).request);
    const conflict = await w.handle((await w.signTransfer(OP, '99.00')).request);
    expect(conflict.receipt?.outcome).toEqual({ state: 'rejected', applies: 'attempt', status: 409, code: 'aria.idempotency_conflict' });
    const found = await w.handle((await w.signLookup(OP)).request);
    expect(found.current).toEqual(original.receipt);
    expect(w.effects).toBe(1);
  });

  it('two simultaneous attempts: one claim, one 409, one effect', async () => {
    const w = world();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const [a, b] = await Promise.all([w.signTransfer(OP), w.signTransfer(OP)]);
    const slow = w.handle(a.request, undefined, async () => (await gate, 'ok'));
    const fast = await w.handle(b.request);
    expect(fast.receipt?.outcome).toMatchObject({ state: 'rejected', applies: 'attempt', status: 409, code: 'aria.operation_in_progress' });
    release();
    expect((await slow).status).toBe(201);
    expect(w.effects).toBe(1);
  });

  it('a business rejection is final for the operation id', async () => {
    const w = world();
    const rejected = await w.handle((await w.signTransfer(OP)).request, undefined, async () => 'bank.insufficient_funds');
    expect(rejected.receipt?.outcome).toEqual({ state: 'rejected', applies: 'operation', status: 422, code: 'bank.insufficient_funds' });
    const again = await w.handle((await w.signTransfer(OP)).request);
    expect(again).toEqual({ status: 422, receipt: rejected.receipt });
  });
});

describe('challenges', () => {
  it('a challenge serves one request: a replay, and a second request with it, are refused', async () => {
    const w = world();
    const receiver = await w.receiver();
    const a = await w.signTransfer(OP, '10.00', receiver);
    expect((await w.handle(a.request)).status).toBe(201);
    expect(await w.handle(a.request)).toEqual({ status: 401, problem: 'aria.authentication_failed/challenge' });
    const b = await w.signTransfer(OP2, '10.00', receiver);
    expect(await w.handle(b.request)).toEqual({ status: 401, problem: 'aria.authentication_failed/challenge' });
  });

  it('two requests racing on one challenge: one is authenticated', async () => {
    const w = world();
    const receiver = await w.receiver();
    const [a, b] = await Promise.all([w.signTransfer(OP, '10.00', receiver), w.signTransfer(OP2, '10.00', receiver)]);
    const results = await Promise.all([w.bankAp.verifyPresentation(a.request, w.context), w.bankAp.verifyPresentation(b.request, w.context)]);
    expect(results.map((r) => r.ok).sort()).toEqual([false, true]);
  });

  it('an expired challenge is refused, even in a request signed just now', async () => {
    const w = world();
    const receiver = await w.receiver();
    w.at(NOW + 61_000);
    const a = await w.signTransfer(OP, '10.00', receiver);
    expect(await w.handle(a.request)).toEqual({ status: 401, problem: 'aria.authentication_failed/challenge' });
  });
});

describe('the audience the signature covers', () => {
  it('a request signed for another receiver is refused at admission, before the authorizer; a lookup, unsigned', async () => {
    const w = world();
    // Another receiver DID at the same origin, whose store accepts the bank's challenges: only the signed audience differs.
    const challenges = { issue: w.challenges.issue.bind(w.challenges), live: (c: string) => w.challenges.live(c, BANK.did), consume: (c: string) => w.challenges.consume(c, BANK.did) };
    const context = { ...w.context, receiver: { did: 'did:aria:bank.example.test:other' as const, origin: BANK.origin }, challenges };
    const presented = await w.bankAp.verifyPresentation((await w.signTransfer(OP)).request, context);
    if (!presented.ok) throw new Error(presented.reason);
    expect(presented.presentation.audience).toBe(BANK.did);
    const status = await w.bankVerifier.checkStatus(presented.presentation.credential);
    let called = false;
    const admission = await w.bankAp.admit({ presentation: presented.presentation, status, authorize: async () => ((called = true), { allowed: true }) });
    expect(admission).toMatchObject({ decision: 'deny', reason: 'audience_mismatch', refusal: { status: 403, code: 'aria.audience_mismatch' } });
    expect(called).toBe(false);

    const lookup = await w.bankAp.verifyPresentation((await w.signLookup(OP)).request, context);
    if (!lookup.ok) throw new Error(lookup.reason);
    expect(await w.bankAp.admitLookup({ presentation: lookup.presentation, status: await w.bankVerifier.checkStatus(lookup.presentation.credential) })).toEqual({ decision: 'deny', status: 403, code: 'aria.audience_mismatch' });
  });
});

describe('authentication order', () => {
  it('a dead challenge is refused before the credential is resolved', async () => {
    const w = world();
    const receiver = await w.receiver();
    const used = await w.signTransfer(OP, '10.00', receiver);
    expect((await w.handle(used.request)).status).toBe(201);
    let resolved = 0;
    const context = { ...w.context, resolveCredential: async (url: string) => (resolved++, w.documents.get(url) ?? null) };
    const replay = await w.signTransfer(OP2, '10.00', receiver);
    expect(await w.bankAp.verifyPresentation(replay.request, context)).toEqual({ ok: false, status: 401, code: 'aria.authentication_failed', reason: 'challenge' });
    expect(resolved).toBe(0);
  });
});

describe('human approval (refuse, provisional D8)', () => {
  it('without an approval the attempt is refused and claims nothing; a bound approval admits', async () => {
    const w = world({ hitl: ['payments:transfer:create'] });
    const first = await w.handle((await w.signTransfer(OP)).request);
    expect(first.receipt?.outcome.code).toBe('aria.approval_required');
    expect(await w.storage.get({ receiver: BANK.did, sender: AGENT, operationId: OP })).toBeNull();

    const attempt = await w.signTransfer(OP);
    const presented = await w.bankAp.verifyPresentation(attempt.request, w.context);
    if (!presented.ok) throw new Error(presented.reason);
    const fingerprint = presented.presentation.fingerprint!;
    // The verification consumed this attempt's challenge; sign the next one with the approval bound to the same content.
    const approval = { approvalId: 'ap-1', sender: AGENT, credentialId: w.agentCredential.binding.credentialId, operationId: OP, fingerprint, expiresAt: '2026-11-01T12:10:00Z' };
    expect((await w.handle((await w.signTransfer(OP)).request, { ...approval, operationId: OP2 })).receipt?.outcome.code).toBe('aria.approval_invalid');
    expect((await w.handle((await w.signTransfer(OP)).request, approval)).status).toBe(201);
  });
});

describe('the receiver, authenticated before anything is sent', () => {
  async function statement(w: ReturnType<typeof world>, nonce = 'n'.repeat(22)) {
    return JSON.parse(JSON.stringify(await w.bankAp.identify(w.self, { nonce, audience: AGENT }, w.challenges)));
  }

  it('refuses another DID, another origin, another audience, another nonce, a stale or altered statement', async () => {
    const w = world();
    const nonce = 'n'.repeat(22);
    const check = async (s: unknown, pin = BANK, expected = { nonce, audience: AGENT }) => {
      const r = await w.agentAp.verifyReceiverIdentity(s, pin, expected);
      return r.ok ? 'ok' : r.reason;
    };
    expect(await check(await statement(w))).toBe('ok');
    expect(await check(await statement(w), { ...BANK, did: 'did:aria:bank.example.test:other' })).toBe('unexpected_receiver');
    expect(await check(await statement(w), { ...BANK, origin: 'https://evil.example.test' })).toBe('origin');
    expect(await check(await statement(w), BANK, { nonce, audience: 'did:aria:someone.example.test:else' })).toBe('audience');
    expect(await check(await statement(w), BANK, { nonce: 'm'.repeat(22), audience: AGENT })).toBe('nonce');
    const altered = await statement(w);
    altered.statement.challenge = 'another-challenge';
    expect(await check(altered)).toBe('signature');
    const old = await statement(w);
    w.at(NOW + 61_000);
    expect(await check(old)).toBe('stale');
  });

  it('refuses a receiver whose credential is revoked', async () => {
    const w = world();
    w.revoke(12);
    const nonce = 'n'.repeat(22);
    expect(await w.agentAp.verifyReceiverIdentity(await statement(w), BANK, { nonce, audience: AGENT })).toEqual({ ok: false, reason: 'status' });
  });
});

describe('signing', () => {
  it('only the credential\'s holder key signs for it, and only for a receiver this instance verified', async () => {
    const w = world();
    const receiver = await w.receiver();
    const request = { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode('{}') };
    const input = { request, class: 'unsafe-body' as const, operationId: OP, receiver, credential: w.agentCredential, signer: w.agentSigner };
    await expect(w.agentAp.signRequest({ ...input, signer: w.self.signer })).rejects.toThrow(AriaUsageError);
    await expect(w.agentAp.signRequest({ ...input, receiver: { ...receiver } })).rejects.toThrow(AriaUsageError);
    await expect(w.bankAp.signRequest(input)).rejects.toThrow(AriaUsageError);
    await expect(w.agentAp.signRequest({ ...input, operationId: 'not-a-uuid' })).rejects.toThrow(AriaUsageError);
    expect((await w.agentAp.signRequest(input)).sent?.operationId).toBe(OP);
  });
});

describe('receipts the client refuses', () => {
  it('a decision whose transport status differs, an altered receipt, one for an attempt never sent', async () => {
    const w = world();
    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const attempt = await w.signTransfer(OP);
    const answer = await w.handle(attempt.request);
    // Not recorded: the receipt names an attempt this client did not keep.
    expect(await tracker.observe(w.agentAp, answer.receipt, { mode: 'decision', transportStatus: 201 })).toMatchObject({ applied: 'none' });
    tracker.record(attempt);
    expect(await tracker.observe(w.agentAp, answer.receipt, { mode: 'decision', transportStatus: 200 })).toEqual({ applied: 'none', state: 'unknown', reason: 'status_mismatch' });
    const altered = { ...answer.receipt!, outcome: { ...answer.receipt!.outcome, status: 200 } };
    expect(await tracker.observe(w.agentAp, altered, { mode: 'decision', transportStatus: 200 })).toEqual({ applied: 'none', state: 'unknown', reason: 'signature_invalid' });
    expect(tracker.state).toBe('unknown');
  });
});
