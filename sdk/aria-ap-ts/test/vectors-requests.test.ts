// AP1 request and fingerprint vectors against ARIA AP's request rules.
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '@aria-registry/sdk';
import { digestField, utf8 } from '../src/internal/bytes';
import { authenticate, fieldsOf, signatureBase } from '../src/internal/request';
import { holderOf, load, requestOf, type View } from './conformance';

const requests = load('vectors/requests.json');
const fingerprints = load('vectors/fingerprints.json');
const ctx = requests.context;

/** What the receiver answers, in the vectors' terms. */
async function answer(vector: any): Promise<Record<string, unknown>> {
  const consumed = new Set<string>(vector.context?.consumed ?? []);
  const live = (nonce: string) => {
    const issued = ctx.challenges.find((c: { value: string }) => c.value === nonce);
    return !!issued && Date.parse(issued.expires) >= Date.parse(ctx.now) && !consumed.has(nonce);
  };
  const result = await authenticate(requestOf(vector.request), {
    origin: ctx.receiver.origin,
    operations: ctx.descriptors,
    now: () => Date.parse(ctx.now),
    challengeLive: async (nonce) => live(nonce),
    consume: async (nonce) => live(nonce) && consumed.add(nonce) !== undefined,
    resolve: async (url, digest) => {
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
