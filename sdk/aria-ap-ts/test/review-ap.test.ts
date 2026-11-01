// Corrections from the independent AP1/AP2 review: reconciliation never enables a
// second execution (F1), freshness is judged after every asynchronous step (F2), and
// an admission is judged again when it is used (F3).
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier } from '@aria-registry/sdk';
import { AdmissionExpired, createAp, StaleClaim, type ApprovalEvidence, type OperationStorage } from '../src';
import { profile, statusList } from './fixtures';
import { AGENT, BANK, NOW, world } from './world';

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((r) => (open = r));
  return { opened, open };
}

async function presented(w: ReturnType<typeof world>, id = randomUUID()) {
  const p = await w.bankAp.verifyPresentation((await w.signTransfer(id)).request, w.context);
  if (!p.ok) throw new Error(p.reason);
  return { p: p.presentation, status: await w.bankVerifier.checkStatus(p.presentation.credential), id };
}

const approvalFor = (x: Awaited<ReturnType<typeof presented>>, expiresAt: number): ApprovalEvidence => ({
  approvalId: 'approval-1',
  sender: AGENT,
  credentialId: x.p.credential.binding.credentialId,
  operationId: x.id,
  fingerprint: x.p.fingerprint!,
  expiresAt: new Date(expiresAt).toISOString().replace('.000Z', 'Z'),
});

const keyOf = (id: string) => ({ receiver: BANK.did, sender: AGENT, operationId: id });

describe('F1: reconciliation never enables a second execution', () => {
  it('a running worker is kept: reconciliation of its unmarked claim changes nothing, a retry is refused, the effect lands once', async () => {
    const w = world();
    const id = randomUUID();
    const entered = gate();
    const proceed = gate();
    let external = 0;
    const first = w.handle((await w.signTransfer(id)).request, undefined, async () => (entered.open(), await proceed.opened, external++, 'ok'));
    await entered.opened;
    const record = await w.storage.get(keyOf(id));
    if (record?.state !== 'claimed') throw new Error('expected a claim');
    expect(await w.ledger.reconcile(keyOf(id), { committed: false, claimId: record.claim.id, revision: record.revision, assurance: 'transactional' })).toEqual({ kind: 'kept', reason: 'active' });
    expect((await w.handle((await w.signTransfer(id)).request, undefined, async () => (external++, 'ok'))).status).toBe(409);
    proceed.open();
    expect((await first).status).toBe(201);
    expect(external).toBe(1);
  });

  it('after a local uncertain failure with a remote request still pending, no assurance means the operation stays locked', async () => {
    const w = world();
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    const b = await w.ledger.begin(a);
    if (b.kind !== 'claimed') throw new Error('expected a claim');
    const remote = gate();
    let external = 0;
    const pending = remote.opened.then(() => external++);
    await w.ledger.fail(b.claim, 'uncertain');
    const record = await w.storage.get(b.claim.key);
    if (record?.state !== 'claimed') throw new Error('expected a claim');
    expect(record.uncertain).toBeDefined();
    expect(await w.ledger.reconcile(b.claim.key, { committed: false, claimId: record.claim.id, revision: record.revision })).toEqual({ kind: 'kept', reason: 'unassured' });
    expect((await w.handle((await w.signTransfer(x.id)).request, undefined, async () => (external++, 'ok'))).status).toBe(409);
    remote.open();
    await pending;
    // The worker learns the remote outcome and records it once.
    expect((await w.ledger.settle(b.claim, { state: 'completed', status: 201 })).state).toBe('completed');
    expect(external).toBe(1);
  });

  it('a worker that stopped without calling fail is marked by its supervisor, then released with an assurance; the old worker is fenced', async () => {
    const w = world();
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    const b = await w.ledger.begin(a);
    if (b.kind !== 'claimed') throw new Error('expected a claim');
    const seen = await w.storage.get(b.claim.key);
    if (seen?.state !== 'claimed') throw new Error('expected a claim');
    await w.ledger.markUncertain(b.claim.key, { claimId: seen.claim.id, revision: seen.revision });
    const marked = await w.storage.get(b.claim.key);
    if (marked?.state !== 'claimed') throw new Error('expected a claim');
    // An observation of the revision before the mark is stale.
    await expect(w.ledger.reconcile(b.claim.key, { committed: false, claimId: seen.claim.id, revision: seen.revision, assurance: 'transactional' })).rejects.toThrow(StaleClaim);
    expect(await w.ledger.reconcile(b.claim.key, { committed: false, claimId: marked.claim.id, revision: marked.revision, assurance: 'transactional' })).toEqual({ kind: 'released' });
    expect((await w.handle((await w.signTransfer(x.id)).request)).status).toBe(201);
    // The old worker's settle fails its compare-and-set, so its transaction rolls back.
    await expect(w.ledger.settle(b.claim, { state: 'completed', status: 201 })).rejects.toThrow(StaleClaim);
    expect(w.effects).toBe(1);
  });

  it('an observation of an older claim never releases its successor', async () => {
    const w = world();
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    const b = await w.ledger.begin(a);
    if (b.kind !== 'claimed') throw new Error('expected a claim');
    await w.ledger.fail(b.claim, 'uncertain');
    const old = await w.storage.get(b.claim.key);
    if (old?.state !== 'claimed') throw new Error('expected a claim');
    expect(await w.ledger.reconcile(b.claim.key, { committed: false, claimId: old.claim.id, revision: old.revision, assurance: 'fenced' })).toEqual({ kind: 'released' });
    const entered = gate();
    const proceed = gate();
    const second = w.handle((await w.signTransfer(x.id)).request, undefined, async () => (entered.open(), await proceed.opened, 'ok'));
    await entered.opened;
    await expect(w.ledger.reconcile(b.claim.key, { committed: false, claimId: old.claim.id, revision: old.revision, assurance: 'transactional' })).rejects.toThrow(StaleClaim);
    proceed.open();
    expect((await second).status).toBe(201);
    expect(w.effects).toBe(1);
  });
});

describe('F2: freshness after every asynchronous step', () => {
  it('a signature window is judged again after the credential is resolved: inside it at the boundary, refused just after', async () => {
    for (const [elapsed, ok] of [[34_000, true], [35_000, true], [35_001, false], [36_000, false]] as const) {
      const w = world();
      const signed = await w.signTransfer(randomUUID()); // created NOW, expires NOW + 30 s; skew 5 s
      const r = await w.bankAp.verifyPresentation(signed.request, { ...w.context, resolveCredential: async (url) => (w.at(NOW + elapsed), w.context.resolveCredential(url)) });
      expect([elapsed, r.ok], `${elapsed}`).toEqual([elapsed, ok]);
      if (!r.ok) expect(r.reason).toBe('window');
    }
  });

  it('and again after an asynchronous challenge store consumes the challenge', async () => {
    const w = world();
    const signed = await w.signTransfer(randomUUID());
    const slow = { ...w.challenges, live: w.challenges.live.bind(w.challenges), issue: w.challenges.issue.bind(w.challenges), consume: async (c: string, aud: never) => { const ok = await w.challenges.consume(c, aud); w.at(NOW + 36_000); return ok; } };
    expect(await w.bankAp.verifyPresentation(signed.request, { ...w.context, challenges: slow })).toEqual({ ok: false, status: 401, code: 'aria.authentication_failed', reason: 'window' });
  });

  it('a receiver statement is judged again after its status is fetched', async () => {
    for (const [elapsed, ok] of [[59_000, true], [60_000, true], [61_000, false]] as const) {
      const w = world();
      const expected = { nonce: 'n'.repeat(22), audience: AGENT };
      const response = await w.bankAp.identify(w.self, expected, w.challenges);
      const v = createVerifier({
        trust: [profile(w.issuer, { maxLevel: 'L3' })],
        clock: () => new Date(w.now),
        fetch: { allowedOrigins: ['https://status.example.test'], fetch: async () => (w.at(NOW + elapsed), new Response(JSON.stringify(statusList(w.issuer, [], { ageMs: 60_000 })), { status: 200 })) },
      });
      const r = await createAp({ credentials: v, clock: () => new Date(w.now) }).verifyReceiverIdentity(response, BANK, expected);
      expect([elapsed, r.ok ? 'ok' : r.reason]).toEqual([elapsed, ok ? 'ok' : 'stale']);
    }
  });

  it('a verified receiver is not used to sign once its statement and challenge are stale', async () => {
    const w = world();
    const receiver = await w.receiver();
    w.at(NOW + 60_001);
    await expect(w.signTransfer(randomUUID(), '10.00', receiver)).rejects.toThrow(AriaUsageError);
  });
});

describe('F3: an admission is judged again when it is used', () => {
  it('a human approval that expires while the authorizer runs denies the admission', async () => {
    const w = world({ hitl: ['payments:transfer:create'] });
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, approval: approvalFor(x, NOW + 1_000), authorize: async () => (w.at(NOW + 2_000), { allowed: true }) });
    expect(a).toMatchObject({ decision: 'deny', reason: 'approval_invalid', refusal: { status: 403, code: 'aria.approval_invalid' } });
  });

  it('an admission whose approval expired before begin is refused, signed, and claims nothing', async () => {
    const w = world({ hitl: ['payments:transfer:create'] });
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, approval: approvalFor(x, NOW + 1_000), authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    w.at(NOW + 2_000);
    const b = await w.ledger.begin(a);
    expect(b).toMatchObject({ kind: 'refused', refusal: { status: 403, code: 'aria.approval_invalid' } });
    expect(await w.storage.get(keyOf(x.id))).toBeNull();
  });

  it('an admission used after its request\'s signature window throws AdmissionExpired', async () => {
    const w = world();
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    w.at(NOW + 36_000);
    await expect(w.ledger.begin(a)).rejects.toThrow(AdmissionExpired);
    expect(await w.storage.get(keyOf(x.id))).toBeNull();
  });

  it('status evidence that turns stale between admission and begin, inside the request\'s window, is refused as unavailable', async () => {
    // The list is 60 s old when fetched; at most 70 s are accepted.
    const w = world({ statusMaxAgeSeconds: 70 });
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    w.at(NOW + 20_000);
    expect(await w.ledger.begin(a)).toMatchObject({ kind: 'refused', refusal: { status: 503, code: 'aria.status_unavailable' } });
    expect(await w.storage.get(keyOf(x.id))).toBeNull();
  });

  it('a storage wait across the approval\'s expiry: the claim just made is released and the attempt refused', async () => {
    const w = world({ hitl: ['payments:transfer:create'] });
    const x = await presented(w);
    const slow: OperationStorage = {
      get: (k) => w.storage.get(k),
      create: async (k, r) => { const out = await w.storage.create(k, r); w.at(NOW + 2_000); return out; },
      replace: (k, e, n) => w.storage.replace(k, e, n),
      reclaim: (k, rv, n) => w.storage.reclaim(k, rv, n),
      remove: (k, e) => w.storage.remove(k, e),
    };
    const { OperationLedger } = await import('../src');
    const ledger = new OperationLedger(w.bankAp, slow, w.self);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, approval: approvalFor(x, NOW + 1_000), authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    expect(await ledger.begin(a)).toMatchObject({ kind: 'refused', refusal: { code: 'aria.approval_invalid' } });
    expect(await w.storage.get(keyOf(x.id))).toBeNull();
  });

  it('control: a bound approval still valid at use is admitted, claimed and completed', async () => {
    const w = world({ hitl: ['payments:transfer:create'] });
    const x = await presented(w);
    const a = await w.bankAp.admit({ presentation: x.p, status: x.status, approval: approvalFor(x, NOW + 60_000), authorize: async () => ({ allowed: true }) });
    if (a.decision !== 'allow') throw new Error('expected allow');
    const b = await w.ledger.begin(a);
    if (b.kind !== 'claimed') throw new Error('expected a claim');
    expect((await w.ledger.settle(b.claim, { state: 'completed', status: 201 })).state).toBe('completed');
  });

  it('a retained lookup admission reads nothing once its request is old, nor once its credential no longer stands', async () => {
    const w = world();
    const id = randomUUID();
    await w.handle((await w.signTransfer(id)).request);
    const admitted = async () => {
      const p = await w.bankAp.verifyPresentation((await w.signLookup(id)).request, w.context);
      if (!p.ok) throw new Error(p.reason);
      const a = await w.bankAp.admitLookup({ presentation: p.presentation, status: await w.bankVerifier.checkStatus(p.presentation.credential) });
      if (a.decision !== 'allow') throw new Error('expected allow');
      return a;
    };
    const old = await admitted();
    w.at(NOW + 25 * 3_600_000);
    await expect(w.ledger.lookup(old)).rejects.toThrow(AdmissionExpired);

    const w2 = world();
    const id2 = randomUUID();
    await w2.handle((await w2.signTransfer(id2)).request);
    const p = await w2.bankAp.verifyPresentation((await w2.signLookup(id2)).request, w2.context);
    if (!p.ok) throw new Error(p.reason);
    const status = await w2.bankVerifier.checkStatus(p.presentation.credential);
    const a = await w2.bankAp.admitLookup({ presentation: p.presentation, status });
    if (a.decision !== 'allow') throw new Error('expected allow');
    const blocked = { ...w2.storage, get: async (k: never) => (w2.at(NOW + 40_000), w2.storage.get(k)) } as unknown as OperationStorage;
    const { OperationLedger } = await import('../src');
    await expect(new OperationLedger(w2.bankAp, blocked, w2.self).lookup(a)).rejects.toThrow(AdmissionExpired);
  });
});
