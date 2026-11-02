// A retained document's authenticity and a retained list's statement, judged without
// the current time and kept apart from everything that judges a credential now.
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier, type AuthenticCredential } from '../src';
import { credential, fakeFetch, HOUR, iso, LIST_URL, newIssuer, NOW, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const signed = sign(credential(), issuer);
// Two days later: the document (valid for 24 h) has expired, its retained list too.
const LATER = NOW + 48 * HOUR;
const verifier = (at = LATER, i = issuer) => createVerifier({ trust: [profile(i)], clock: () => new Date(at), fetch: { allowedOrigins: ['https://status.example.test'], fetch: fakeFetch({}) } });

function authentic(v = verifier(), doc: unknown = signed): AuthenticCredential {
  const r = v.verifyAuthenticity(doc);
  if (!r.ok) throw new Error(r.reason);
  return r.credential;
}

describe('verifyAuthenticity', () => {
  it('establishes an expired document that verifyCredential refuses, with its signed validity reported', () => {
    const v = verifier();
    expect(v.verifyCredential(signed)).toEqual({ ok: false, reason: 'expired', path: '/validUntil' });
    const c = authentic(v);
    expect(c).toMatchObject({ kind: 'authentic-credential', did: credential().credentialSubject.id, validFrom: iso(-HOUR), validUntil: iso(24 * HOUR), statusEntry: { list: LIST_URL, index: 7 } });
    expect(c.binding.credentialId).toBe(credential().id);
  });

  it('establishes a document not yet valid', () => {
    expect(authentic(verifier(NOW - 10 * HOUR)).kind).toBe('authentic-credential');
  });

  it('refuses everything else verifyCredential refuses: either signature half, another issuer, altered content, bounds that are not an interval', () => {
    const v = verifier();
    expect(v.verifyAuthenticity(sign(credential(), issuer, 'pq'))).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(v.verifyAuthenticity(sign(credential(), issuer, 'classical'))).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(v.verifyAuthenticity(sign(credential(), newIssuer()))).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(v.verifyAuthenticity({ ...signed, issuer: 'did:aria:other.example.test' })).toMatchObject({ ok: false, reason: 'untrusted_issuer' });
    expect(v.verifyAuthenticity({ ...signed, credentialSubject: { ...signed.credentialSubject, agentName: 'altered' } })).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(v.verifyAuthenticity(sign({ ...credential(), validUntil: iso(-2 * HOUR) }, issuer))).toMatchObject({ ok: false, reason: 'invalid_validity' });
    expect(v.verifyAuthenticity('not json')).toMatchObject({ ok: false, reason: 'malformed' });
  });
});

describe('an authentic credential never stands in for a verified one', () => {
  it('facts, standing and checkStatus refuse it; historicalFacts refuses a verified credential', async () => {
    const v = verifier(NOW);
    const c = authentic(v);
    const verified = v.verifyCredential(signed);
    if (!verified.ok) throw new Error(verified.reason);
    const status = await v.checkStatus(verified.credential);
    expect(() => v.facts(c as never)).toThrow(AriaUsageError);
    expect(() => v.standing(c as never, status)).toThrow(AriaUsageError);
    await expect(v.checkStatus(c as never)).rejects.toThrow(AriaUsageError);
    expect(() => v.historicalFacts(verified.credential as never)).toThrow(AriaUsageError);
  });

  it('a copy, an altered view or another verifier’s result is refused', () => {
    const v = verifier();
    const c = authentic(v);
    expect(() => v.historicalFacts({ ...c })).toThrow(AriaUsageError);
    expect(() => verifier().historicalFacts(c)).toThrow(AriaUsageError);
    expect(Object.isFrozen(c.holderKey)).toBe(true);
  });

  it('historicalFacts returns the holder key bytes and validity from the record, not the view', () => {
    const v = verifier();
    const f = v.historicalFacts(authentic(v));
    expect(f.holderKey.publicKey).toHaveLength(32);
    expect(f).toMatchObject({ validFrom: iso(-HOUR), validUntil: iso(24 * HOUR), retainedStatus: null });
  });
});

describe('readRetainedStatus', () => {
  it('reads a retained list long after it expired, reporting its validity, never judging it now', async () => {
    const v = verifier();
    const c = authentic(v);
    const revoked = await v.readRetainedStatus(c, statusList(issuer, [7]));
    if (!revoked.ok) throw new Error(revoked.reason);
    expect(revoked.status).toMatchObject({ kind: 'retained-status', state: 'revoked', list: { url: LIST_URL, index: 7, validFrom: iso(-10 * 60_000), validUntil: iso(-10 * 60_000 + 24 * HOUR) } });
    const active = await v.readRetainedStatus(c, JSON.stringify(statusList(issuer, [3])));
    expect(active.ok && active.status.state).toBe('active');
    expect(v.historicalFacts(c, revoked.status).retainedStatus).toEqual({ state: 'revoked', validFrom: iso(-10 * 60_000), validUntil: iso(-10 * 60_000 + 24 * HOUR) });
  });

  it('refuses a list of another issuer, a broken signature, another list of the same issuer, and bounds longer than 24 h', async () => {
    const v = verifier();
    const c = authentic(v);
    const other = newIssuer();
    expect(await v.readRetainedStatus(c, { ...statusList(other, [7]), issuer: 'did:aria:other.example.test' })).toEqual({ ok: false, reason: 'wrong_issuer' });
    expect(await v.readRetainedStatus(c, statusList(other, [7]))).toEqual({ ok: false, reason: 'signature_invalid' });
    expect(await v.readRetainedStatus(c, statusList(issuer, [7], { id: 'https://status.example.test/v1/status/2' }))).toEqual({ ok: false, reason: 'malformed' });
    expect(await v.readRetainedStatus(c, statusList(issuer, [7], { validityMs: 25 * HOUR }))).toEqual({ ok: false, reason: 'invalid_validity' });
    expect(await v.readRetainedStatus(c, 'not json')).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a retained status is not status evidence, and one about another document is refused', async () => {
    const v = verifier(NOW);
    const c = authentic(v);
    const read = await v.readRetainedStatus(c, statusList(issuer, [3]));
    if (!read.ok) throw new Error(read.reason);
    const verified = v.verifyCredential(signed);
    if (!verified.ok) throw new Error(verified.reason);
    expect(() => v.standing(verified.credential, read.status as never)).toThrow(AriaUsageError);
    const doc = credential();
    doc.id = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-000000000002';
    const another = authentic(v, sign(doc, issuer));
    expect(() => v.historicalFacts(another, read.status)).toThrow(AriaUsageError);
    await expect(v.readRetainedStatus(verified.credential as never, statusList(issuer, []))).rejects.toThrow(AriaUsageError);
  });
});
