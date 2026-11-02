// AP1 historical receipt vectors through the public APIs: the credential verifier
// establishes the retained documents' authenticity and what retained lists said,
// at a time when the named receiver credential has expired; ARIA AP checks the
// receipts against that evidence.
import { describe, expect, it } from 'vitest';
import { createVerifier, type AuthenticCredential, type RetainedStatus } from '@trustlayer-foundation/aria-sdk';
import { createAp, type SentAttempt } from '../src';
import { load } from './conformance';

const historical = load('vectors/historical.json');
const ctx = historical.context;
const clock = () => new Date(ctx.at);
const verifier = createVerifier({
  trust: [
    {
      id: 'vectors',
      issuer: ctx.issuer.did,
      verificationMethod: ctx.issuer.verificationMethod,
      keys: { mldsa65: new Uint8Array(Buffer.from(ctx.issuer.keys.mldsa65, 'base64')), ed25519: new Uint8Array(Buffer.from(ctx.issuer.keys.ed25519, 'base64')) },
      maxLevel: ctx.issuer.maxLevel,
      statusLists: ctx.issuer.statusLists,
    },
  ],
  clock,
});
const ap = createAp({ credentials: verifier, clock });

const authentic = (name: string): AuthenticCredential | undefined => {
  const r = verifier.verifyAuthenticity(ctx.documents[name].document);
  return r.ok ? r.credential : undefined;
};

async function answer(vector: any): Promise<Record<string, unknown>> {
  const credential = vector.evidence.document ? authentic(vector.evidence.document) : undefined;
  let status: RetainedStatus | undefined;
  if (credential && vector.evidence.statusList) {
    const read = await verifier.readRetainedStatus(credential, ctx.statusLists[vector.evidence.statusList].document);
    if (read.ok) status = read.status;
  }
  const labels = new Map<string, string>();
  const attempts: SentAttempt[] = vector.attempts.map((a: any) => {
    labels.set(a.requestDigest, a.request);
    return { operationId: a.operation, requestDigest: a.requestDigest, sender: a.sender, receiver: a.receiver };
  });
  const r = await ap.verifyHistoricalReceipt(vector.receipt, { attempts, evidence: { ...(credential ? { credential } : {}), ...(status ? { status } : {}) } });
  if (!r.ok) return { result: 'invalid', reason: r.reason };
  const s = r.statement;
  return { result: 'valid', state: s.state, applies: s.applies, status: s.status, code: s.code, attempt: labels.get(r.attempt.requestDigest), findings: r.findings };
}

describe('AP1 historical evidence through the credential verifier', () => {
  for (const [name, d] of Object.entries<any>(ctx.documents)) {
    it(`document ${name}: ${d.authentic ? 'authentic' : d.reason}`, () => {
      const r = verifier.verifyAuthenticity(d.document);
      expect(r.ok ? 'authentic' : r.reason).toBe(d.authentic ? 'authentic' : d.reason);
    });
  }

  it('the retained receiver credential has expired at the check: verifyCredential refuses what verifyAuthenticity establishes', () => {
    expect(verifier.verifyCredential(ctx.documents.r1.document)).toMatchObject({ ok: false, reason: 'expired' });
    expect(authentic('r1')?.kind).toBe('authentic-credential');
  });

  for (const [name, l] of Object.entries<any>(ctx.statusLists)) {
    it(`status list ${name} for r1: ${l.read.state ?? l.read.reason}`, async () => {
      const r = await verifier.readRetainedStatus(authentic('r1')!, l.document);
      expect(r.ok ? { state: r.status.state } : { reason: r.reason }).toEqual(l.read);
    });
  }
});

describe('AP1 historical receipt vectors', () => {
  for (const vector of historical.vectors) {
    it(`${vector.id}: ${vector.title}`, async () => {
      expect(await answer(vector)).toEqual(vector.expect);
    });
  }
});
