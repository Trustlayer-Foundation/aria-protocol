// Historical receipts through the public API: authenticity of the retained evidence,
// checked long after the exchange, kept apart from anything that authorizes now.
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AriaUsageError } from '@trustlayer-foundation/aria-sdk';
import { HOUR, statusList } from './fixtures';
import { NOW, world } from './world';

const MONTH = 30 * 24 * HOUR;

/** A completed operation; then, a month later, what the client kept. */
async function completedThenLater() {
  const w = world();
  const id = randomUUID();
  const signed = await w.signTransfer(id);
  const answer = await w.handle(signed.request);
  if (answer.status !== 201 || !answer.receipt) throw new Error('expected a completed operation');
  w.at(NOW + MONTH);
  const authentic = w.agentVerifier.verifyAuthenticity(w.self.document);
  if (!authentic.ok) throw new Error(authentic.reason);
  return { w, signed, receipt: JSON.stringify(answer.receipt), credential: authentic.credential };
}

describe('verifyHistoricalReceipt', () => {
  it('a month later, with the receiver credential expired, the receipt verifies against the retained document', async () => {
    const { w, signed, receipt, credential } = await completedThenLater();
    expect(w.agentVerifier.verifyCredential(w.self.document)).toMatchObject({ ok: false, reason: 'expired' });
    const read = await w.agentVerifier.readRetainedStatus(credential, statusList(w.issuer, [12]));
    if (!read.ok) throw new Error(read.reason);
    const r = await w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [signed.sent!], evidence: { credential, status: read.status } });
    if (!r.ok) throw new Error(r.reason);
    expect(r.statement).toMatchObject({ state: 'completed', applies: 'operation', status: 201 });
    expect(r.findings).toEqual({
      issuedAtWithinValidity: true,
      retainedStatus: 'revoked',
      retainedStatusPeriod: { validFrom: read.status.list.validFrom, validUntil: read.status.list.validUntil },
      signingTime: 'receiver_claim',
    });
  });

  it('without the exact named credential there is no evidence; another document of the same DID is not it', async () => {
    const { w, signed, receipt } = await completedThenLater();
    expect(await w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [signed.sent!], evidence: {} })).toEqual({ ok: false, reason: 'evidence_missing' });
    const renewed = w.holder(w.self.did, 40, { scopes: ['payments:transfer:receive'] });
    const other = w.agentVerifier.verifyAuthenticity(renewed.document);
    if (!other.ok) throw new Error(other.reason);
    expect(await w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [signed.sent!], evidence: { credential: other.credential } })).toEqual({ ok: false, reason: 'evidence_missing' });
  });

  it('evidence the verifier did not produce is refused: a copy, a current credential in its place, a retained status of another document', async () => {
    const { w, signed, receipt, credential } = await completedThenLater();
    const check = (evidence: object) => w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [signed.sent!], evidence: evidence as never });
    await expect(check({ credential: { ...credential } })).rejects.toThrow(AriaUsageError);
    w.at(NOW);
    await expect(check({ credential: w.agentCredential })).rejects.toThrow(AriaUsageError);
    const renewed = w.holder(w.self.did, 41, { scopes: ['payments:transfer:receive'] });
    const other = w.agentVerifier.verifyAuthenticity(renewed.document);
    if (!other.ok) throw new Error(other.reason);
    const read = await w.agentVerifier.readRetainedStatus(other.credential, statusList(w.issuer, []));
    if (!read.ok) throw new Error(read.reason);
    await expect(check({ credential, status: read.status })).rejects.toThrow(AriaUsageError);
  });

  it('binding still decides: a receipt for an attempt the client did not keep is refused', async () => {
    const { w, receipt, credential } = await completedThenLater();
    const unrelated = await (async () => {
      w.at(NOW);
      const s = await w.signTransfer(randomUUID());
      return s.sent!;
    })();
    expect(await w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [unrelated], evidence: { credential } })).toEqual({ ok: false, reason: 'binding' });
  });
});

describe('an authentic credential authorizes nothing now', () => {
  it('signing a request with it is refused, with a live receiver', async () => {
    const w = world();
    const authentic = w.agentVerifier.verifyAuthenticity(w.documents.values().next().value);
    if (!authentic.ok) throw new Error(authentic.reason);
    const receiver = await w.receiver();
    await expect(
      w.agentAp.signRequest({
        request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode('{}') },
        class: 'unsafe-body',
        operationId: randomUUID(),
        receiver,
        credential: authentic.credential as never,
        signer: w.agentSigner,
      }),
    ).rejects.toThrow(AriaUsageError);
  });

  it('a request whose credential expired is refused at authentication, while its old receipts still verify historically', async () => {
    const { w, signed, receipt, credential } = await completedThenLater();
    const late = await w.bankAp.verifyPresentation(signed.request, w.context);
    expect(late.ok).toBe(false);
    expect((await w.agentAp.verifyHistoricalReceipt(receipt, { attempts: [signed.sent!], evidence: { credential } })).ok).toBe(true);
  });
});
