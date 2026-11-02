// AP1 request and fingerprint vectors against ARIA AP's request rules.
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '@trustlayer-foundation/aria-sdk';
import { digestField, utf8 } from '../src/internal/bytes';
import { MemoryChallengeStore } from '../src';
import { authenticate, fieldsOf, signatureBase } from '../src/internal/request';
import { holderOf, load, requestOf, type View } from './conformance';

const requests = load('vectors/requests.json');
const fingerprints = load('vectors/fingerprints.json');
const ctx = requests.context;

/** What the receiver answers, in the vectors' terms, with the real challenge store and the vector's timeline. */
async function answer(vector: any): Promise<Record<string, unknown>> {
  const start = Date.parse(ctx.now);
  let t = start;
  const pending: string[] = [];
  const store = new MemoryChallengeStore(() => new Date(t), { token: () => pending.shift()! });
  const did = ctx.receiver.did;
  // Each vector challenge is issued for 60 s so that it expires when the vector says.
  for (const c of ctx.challenges) {
    t = Date.parse(c.expires) - 60_000;
    pending.push(c.value);
    await store.issue(did, 60);
  }
  t = start;
  for (const c of vector.context?.consumed ?? []) await store.consume(c, did);
  const timeline = vector.timeline ?? {};
  const result = await authenticate(requestOf(vector.request), {
    origin: ctx.receiver.origin,
    operations: ctx.descriptors,
    now: () => t,
    challengeLive: (nonce) => store.live(nonce, did),
    consume: async (nonce) => {
      const ok = await store.consume(nonce, did);
      if (timeline.consumedAfter !== undefined) t = start + timeline.consumedAfter * 1000;
      return ok;
    },
    resolve: async (url, digest) => {
      if (timeline.resolvedAfter !== undefined) t = start + timeline.resolvedAfter * 1000;
      const view = (ctx.credentials as View[]).find((c) => c.url === url);
      return view && view.digest === digest ? holderOf(view) : null;
    },
  });
  if (!result.ok) {
    const { status, reason } = result.failure;
    return status === 400
      ? { result: 'refused', http: 400, code: 'aria.request_invalid', signed: false }
      : { result: 'refused', http: 401, code: 'aria.authentication_failed', subtype: reason, signed: false };
  }
  const a = result.value;
  // Admission's first check, the audience the signature covers.
  if (a.audience !== ctx.receiver.did) {
    return a.descriptor.class === 'retrieval'
      ? { result: 'refused', http: 403, code: 'aria.audience_mismatch', signed: false }
      : { result: 'refused', http: 403, code: 'aria.audience_mismatch', signed: true, applies: 'attempt' };
  }
  const out = {
    result: 'authenticated',
    descriptor: a.descriptor.name,
    class: a.descriptor.class,
    sender: { did: a.holder.did, credential: a.holder.credentialId },
    requestDigest: a.requestDigest,
  };
  return a.descriptor.class === 'retrieval' ? { ...out, retrieves: a.lookupOf } : { ...out, operation: a.operationId, fingerprint: a.fingerprint };
}

describe('AP1 request vectors', () => {
  for (const vector of requests.vectors) {
    it(`${vector.id}: ${vector.title}`, async () => {
      expect(await answer(vector)).toEqual(vector.expect);
    });
  }
});

describe('AP1 fingerprint vectors', () => {
  it('computes each case', () => {
    for (const c of fingerprints.cases) expect(digestField(utf8(canonicalJson(c.input))), c.id).toBe(c.fingerprint);
  });

  it('keeps the declared relations between cases', () => {
    const byCase = new Map(fingerprints.cases.map((c: any) => [c.id, c.fingerprint]));
    for (const rel of fingerprints.relations) expect(byCase.get(rel.a) === byCase.get(rel.b), `${rel.a} ~ ${rel.b}`).toBe(rel.same);
  });

  it('matches the fingerprints of the request vectors', async () => {
    const byId = new Map(requests.vectors.map((v: any) => [v.id, v]));
    const byCase = new Map(fingerprints.cases.map((c: any) => [c.id, c.fingerprint]));
    for (const rel of fingerprints.requestRelations) {
      const [a, b] = await Promise.all([answer(byId.get(rel.a)), answer(byId.get(rel.b))]);
      expect(a.fingerprint === b.fingerprint, `${rel.a} ~ ${rel.b}`).toBe(rel.same);
    }
    for (const rc of fingerprints.requestCases) expect((await answer(byId.get(rc.request))).fingerprint, rc.request).toBe(byCase.get(rc.case));
  });
});

describe('the signature base', () => {
  it('refuses a covered value that would add a line to the base', async () => {
    const vector = requests.vectors.find((v: any) => v.id === 'REQ-001');
    const injected = structuredClone(vector);
    for (const h of injected.request.headers) if (h[0] === 'aria-audience') h[1] = `${h[1]}\n"@method": GET`;
    expect(await answer(injected)).toMatchObject({ http: 401, subtype: 'signature' });
    expect(signatureBase('POST', 'https://x.test/', fieldsOf({ a: 'v\r' }), ['a'], [[], new Map()])).toBeNull();
  });
});
