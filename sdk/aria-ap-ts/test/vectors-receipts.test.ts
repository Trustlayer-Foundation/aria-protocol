// AP1 receipt vectors against ARIA AP's receipt rules. Historical mode (RCP-12a–d)
// is not run: it needs the credential package to establish a retained credential's
// authenticity without its current validity, which it does not offer yet.
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
    const run = vector.mode === 'historical' ? it.skip : it;
    run(`${vector.id}: ${vector.title}`, () => {
      expect(answer(vector)).toEqual(vector.expect);
    });
  }

  it('leaves out only the historical vectors', () => {
    expect(receipts.vectors.filter((v: any) => v.mode === 'historical').map((v: any) => v.id)).toEqual(['RCP-12a', 'RCP-12b', 'RCP-12c', 'RCP-12d']);
  });
});
