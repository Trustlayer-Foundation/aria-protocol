// AP1 receiver identity vectors against ARIA AP's identity rules, the same core
// `verifyReceiverIdentity` runs over the credential verifier.
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '@aria-registry/sdk';
import { checkIdentity, type IdentityHolder } from '../src/internal/identity';
import { load, multibaseKey } from './conformance';

const identity = load('vectors/identity.json');
const ctx = identity.context;

interface IdentityView {
  readonly url: string;
  readonly did: string;
  readonly holderKey: { readonly id: string; readonly publicKeyMultibase: string };
  readonly validFrom: string;
  readonly validUntil: string;
  readonly status: 'good' | 'revoked';
  readonly document: unknown;
}

/** What the client concludes, in the vectors' terms; the clock moves while status is established. */
async function answer(vector: any): Promise<Record<string, unknown>> {
  const start = Date.parse(ctx.now);
  let t = start;
  const result = await checkIdentity<IdentityView>(vector.response, { ...ctx.pin, ...vector.pin }, ctx.expected, {
    now: () => t,
    verify: (document) => {
      // The credential verifier's part, from the views: the document verifies and is valid now.
      const view = (ctx.credentials as IdentityView[]).find((c) => canonicalJson(c.document) === canonicalJson(document));
      if (!view || Date.parse(view.validFrom) > t + ctx.skewSeconds * 1000 || Date.parse(view.validUntil) <= t) return null;
      const holder: IdentityHolder = { credentialId: view.url, did: view.did, keyId: view.holderKey.id, publicKey: multibaseKey(view.holderKey.publicKeyMultibase) };
      return { holder, handle: view };
    },
    stands: async (view) => {
      if (vector.timeline?.statusAfter !== undefined) t = start + vector.timeline.statusAfter * 1000;
      return view.status === 'good';
    },
  });
  return result.ok
    ? { result: 'authenticated', credential: result.holder.credentialId, keyid: result.holder.keyId, challenge: result.challenge }
    : { result: 'refused', reason: result.reason };
}

describe('AP1 receiver identity vectors', () => {
  it('covers every vector', () => {
    expect(identity.vectors.length).toBeGreaterThanOrEqual(34);
  });

  for (const v of identity.vectors) {
    it(`${v.id}: ${v.title}`, async () => {
      expect(await answer(v)).toEqual(v.expect);
    });
  }
});
