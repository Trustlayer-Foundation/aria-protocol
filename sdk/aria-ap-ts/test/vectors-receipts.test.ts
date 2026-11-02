// AP1 receipt vectors against ARIA AP's receipt rules. Historical receipts have their
// own vectors (vectors-historical.test.ts).
import { describe, expect, it } from 'vitest';
import { checkReceipt } from '../src/internal/receipt';
import { holderOf, load, type View } from './conformance';

const receipts = load('vectors/receipts.json');

function answer(vector: any): Record<string, unknown> {
  const view: View = vector.client.receiver;
  const h = holderOf(view);
  const labels = new Map<string, string>();
  const attempts = vector.client.attempts.map((a: any) => {
    labels.set(a.requestDigest, a.request);
    return { operationId: a.operation, requestDigest: a.requestDigest, sender: a.sender, receiver: a.receiver };
  });
  const mode = vector.mode === 'decision' ? { mode: 'decision' as const, transportStatus: vector.transportStatus } : { mode: 'retrieval' as const, transportStatus: vector.transportStatus };
  const r = checkReceipt(vector.receipt, { did: h.did, credentialId: h.credentialId, keyId: h.keyId, publicKey: h.publicKey }, attempts, mode);
  if (!r.ok) return { result: 'invalid', reason: r.reason };
  const o = r.receipt.outcome;
  return { result: 'valid', state: o.state, applies: o.applies, status: o.status, code: o.code, attempt: labels.get(r.attempt.requestDigest) };
}

describe('AP1 receipt vectors', () => {
  for (const vector of receipts.vectors) {
    it(`${vector.id}: ${vector.title}`, () => {
      expect(answer(vector)).toEqual(vector.expect);
    });
  }

  it('holds no historical vectors', () => {
    expect(receipts.vectors.filter((v: any) => v.mode === 'historical')).toEqual([]);
  });
});
