// The trust interface packages built on this SDK use (ARIA AP): `facts` and
// `standing` read the verifier's own record, refuse anything it did not
// produce, and judge time-sensitive evidence when they are called.
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier, inspectCredential, type StatusEvidence, type VerifiedCredential } from '../src';
import { credential, DID, fakeFetch, HOUR, LIST_URL, newIssuer, NOW, ONLINE, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const signed = sign(credential(), issuer);
const ORIGIN = 'https://status.example.test';

function setup(routes: Parameters<typeof fakeFetch>[0] = {}, online = false) {
  let t = NOW;
  const v = createVerifier({
    trust: [profile(issuer)],
    clock: () => new Date(t),
    ...(online || Object.keys(routes).length > 0 ? { fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch(routes) } } : {}),
  });
  const verify = (): VerifiedCredential => {
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    return r.credential;
  };
  return { v, verify, at: (ms: number) => (t = ms) };
}

describe('facts: what the verifier established, from its own record', () => {
  const { v, verify } = setup();
  const genuine = verify();

  it('returns the verified data, with the holder key as its 32 raw bytes', () => {
    const f = v.facts(genuine);
    expect(f).toMatchObject({ did: DID, trustLevel: 'L0', delegationDepth: 0, binding: genuine.binding, scopes: genuine.scopes, hitlRequired: genuine.hitlRequired });
    expect(f.holderKey.id).toBe(`${DID}#holder-key-1`);
    expect(f.holderKey.publicKey).toBeInstanceOf(Uint8Array);
    expect(f.holderKey.publicKey).toHaveLength(32);
    expect(f.validUntil).toBe(genuine.validUntil);
  });

  it('is a fresh copy: changing what it returned changes nothing the verifier holds', () => {
    const first = v.facts(genuine);
    first.holderKey.publicKey.fill(0);
    expect(() => (first.scopes as string[]).push('admin:all:write')).toThrow(TypeError);
    const second = v.facts(genuine);
    expect(second.holderKey.publicKey.some((b) => b !== 0)).toBe(true);
    expect(second.scopes).not.toContain('admin:all:write');
  });

  it('refuses copies, hand-made objects, inspections and another verifier’s results', () => {
    const mirror = Object.create(Object.getPrototypeOf(genuine), Object.getOwnPropertyDescriptors(genuine)) as VerifiedCredential;
    const forged = [
      { ...genuine, scopes: ['admin:all:write'] },
      mirror,
      { kind: 'verified-credential', did: genuine.did } as unknown as VerifiedCredential,
      inspectCredential(signed) as unknown as VerifiedCredential,
      setup().verify(),
    ];
    for (const value of forged) expect(() => v.facts(value as VerifiedCredential)).toThrow(AriaUsageError);
  });
});

describe('standing: the exact credential, judged when asked', () => {
  it('is good with fresh evidence that it is active, and says from which source', async () => {
    const { v, verify } = setup({ [LIST_URL]: statusList(issuer, []) });
    const c = verify();
    expect(v.standing(c, await v.checkStatus(c))).toEqual({ kind: 'standing', state: 'good', source: 'status-list', judgedAt: '2026-11-01T12:00:00Z' });
  });

  it('is revoked or superseded only as the evidence says', async () => {
    const revoked = setup({ [LIST_URL]: statusList(issuer, [7]) });
    const r = revoked.verify();
    expect(revoked.v.standing(r, await revoked.v.checkStatus(r))).toMatchObject({ state: 'revoked' });

    const newer = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-000000000009';
    const replaced = setup({ [`${ONLINE}${DID}`]: { did: DID, status: 'active', credentialId: newer } });
    const s = replaced.verify();
    expect(replaced.v.standing(s, await replaced.v.checkStatus(s, { via: 'online' }))).toMatchObject({ state: 'superseded' });
  });

  it('is unknown without evidence: unknown is never good', async () => {
    const { v, verify } = setup();
    const c = verify();
    expect(v.standing(c, await v.checkStatus(c))).toMatchObject({ state: 'unknown', reason: 'unavailable' });
  });

  it('judges freshness and validity at the call, not when the evidence was obtained', async () => {
    const { v, verify, at } = setup({ [LIST_URL]: statusList(issuer, []), [`${ONLINE}${DID}`]: { did: DID, status: 'active', credentialId: signed.id } });
    const c = verify();
    const list = await v.checkStatus(c);
    const online = await v.checkStatus(c, { via: 'online' });
    expect(v.standing(c, online)).toMatchObject({ state: 'good', source: 'online' });

    at(NOW + 61_000);
    expect(v.standing(c, online)).toMatchObject({ state: 'unknown', reason: 'stale', judgedAt: '2026-11-01T12:01:01Z' });
    expect(v.standing(c, list)).toMatchObject({ state: 'good' });

    at(NOW + 2 * HOUR);
    expect(v.standing(c, list)).toMatchObject({ state: 'unknown', reason: 'stale' });

    at(Date.parse(c.validUntil));
    expect(v.standing(c, list)).toMatchObject({ state: 'not_valid_now' });
  });

  it('takes status evidence only about that same verified result', async () => {
    const { v, verify } = setup({ [LIST_URL]: statusList(issuer, []) });
    const first = verify();
    const status = await v.checkStatus(first);
    expect(v.standing(verify(), status)).toMatchObject({ state: 'unknown', reason: 'other_document' });
  });

  it('refuses status evidence that is copied, hand-made or another verifier’s', async () => {
    const { v, verify } = setup({ [LIST_URL]: statusList(issuer, []) });
    const c = verify();
    const genuine = await v.checkStatus(c);
    const other = setup({ [LIST_URL]: statusList(issuer, []) });
    const foreign = await other.v.checkStatus(other.verify());
    const forged: unknown[] = [{ ...genuine }, { kind: 'status-evidence', state: 'active', credential: c.binding }, foreign];
    for (const value of forged) expect(() => v.standing(c, value as StatusEvidence)).toThrow(AriaUsageError);
    expect(() => v.standing(other.verify(), genuine)).toThrow(AriaUsageError);
  });

  it('is a frozen judgment, not evidence', async () => {
    const { v, verify } = setup();
    const c = verify();
    const judged = v.standing(c, await v.checkStatus(c));
    expect(Object.isFrozen(judged)).toBe(true);
    // A judgment cannot stand in for status evidence.
    expect(() => v.standing(c, judged as unknown as StatusEvidence)).toThrow(AriaUsageError);
  });
});
