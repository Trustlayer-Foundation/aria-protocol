// S0-R1: a result is trusted only as the exact object its verifier produced.
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier, type VerifiedCredential } from '../src';
import { evaluate } from '../src/internal/policy';
import { recall } from '../src/internal/provenance';
import type { CredentialSnapshot } from '../src/internal/verify-credential';
import { credential, fakeFetch, HOUR, LIST_URL, newIssuer, NOW, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const clock = () => new Date(NOW);
const signed = sign(credential(), issuer);

function verifiedBy(v: ReturnType<typeof createVerifier>): VerifiedCredential {
  const r = v.verifyCredential(signed);
  if (!r.ok) throw new Error(r.reason);
  return r.credential;
}

describe('copies and alterations are refused', () => {
  const v = createVerifier({ trust: [profile(issuer)], clock });
  const genuine = verifiedBy(v);

  it('accepts the genuine object', async () => {
    await expect(v.checkStatus(genuine)).resolves.toMatchObject({ kind: 'status-evidence' });
  });

  it('refuses a spread copy with changed scopes, level and HITL', async () => {
    const copy = { ...genuine, scopes: ['admin:all:write'], trustLevel: 'L3', hitlRequired: [] } as VerifiedCredential;
    await expect(v.checkStatus(copy)).rejects.toBeInstanceOf(AriaUsageError);
  });

  it('refuses a copy that carries every own property and symbol', async () => {
    const mirror = Object.create(Object.getPrototypeOf(genuine), Object.getOwnPropertyDescriptors(genuine)) as VerifiedCredential;
    expect(Object.getOwnPropertySymbols(mirror)).toEqual(Object.getOwnPropertySymbols(genuine));
    await expect(v.checkStatus(mirror)).rejects.toBeInstanceOf(AriaUsageError);
  });

  it('refuses a hand-made object cast to the type', async () => {
    await expect(v.checkStatus({ kind: 'verified-credential', did: genuine.did } as unknown as VerifiedCredential)).rejects.toBeInstanceOf(AriaUsageError);
  });

  it('cannot be altered in place: the view is deeply frozen, and the verifier reads its own copy', () => {
    expect(Object.isFrozen(genuine)).toBe(true);
    expect(Object.isFrozen(genuine.scopes)).toBe(true);
    expect(Object.isFrozen(genuine.binding)).toBe(true);
    expect(() => (genuine.scopes as string[]).push('admin:all:write')).toThrow(TypeError);
    expect(() => {
      (genuine as { trustLevel: string }).trustLevel = 'L3';
    }).toThrow(TypeError);
    expect(typeof genuine.validUntil).toBe('string');
    const snapshot = recall<CredentialSnapshot>(v, 'credential', genuine);
    expect(snapshot.scopes).not.toContain('admin:all:write');
    expect(snapshot.trustLevel).toBe('L0');
  });
});

describe('results belong to their verifier, not to a profile name', () => {
  it('refuses a result of another verifier with other keys under the same profile name', async () => {
    const a = createVerifier({ trust: [profile(issuer, { id: 'demo' })], clock });
    const b = createVerifier({ trust: [profile(newIssuer(), { id: 'demo' })], clock });
    await expect(b.checkStatus(verifiedBy(a))).rejects.toThrow(/another verifier/);
  });

  it('refuses it even when the other verifier has the same keys', async () => {
    const a = createVerifier({ trust: [profile(issuer)], clock });
    const b = createVerifier({ trust: [profile(issuer)], clock });
    await expect(b.checkStatus(verifiedBy(a))).rejects.toBeInstanceOf(AriaUsageError);
  });
});

describe('the trusted configuration is copied when the verifier is created', () => {
  it('changing the key bytes or the arrays afterwards changes nothing', () => {
    const other = newIssuer();
    const config = profile(issuer, { keys: { mldsa65: issuer.pq.publicKey.slice(), ed25519: issuer.edPublic.slice() }, statusLists: [LIST_URL] });
    const mldsa = config.keys.mldsa65;
    const lists = config.statusLists as string[];
    const v = createVerifier({ trust: [config], clock });
    mldsa.set(other.pq.publicKey);
    (config.keys.ed25519 as Uint8Array).set(other.edPublic);
    lists.push('https://evil.example.test/status');
    expect(v.verifyCredential(signed)).toMatchObject({ ok: true });
    expect(v.verifyCredential(sign(credential(), other))).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });

  it('refuses ambiguous or malformed trust', () => {
    expect(() => createVerifier({ trust: [], clock })).toThrow(AriaUsageError);
    expect(() => createVerifier({ trust: [profile(issuer), profile(newIssuer(), { id: 'other' })], clock })).toThrow(/same issuer/);
    expect(() => createVerifier({ trust: [profile(issuer, { keys: { mldsa65: new Uint8Array(10), ed25519: issuer.edPublic } })], clock })).toThrow(AriaUsageError);
  });
});

describe('time-sensitive evidence is judged when it is used', () => {
  it('a credential verified earlier is expired at admission time', () => {
    const v = createVerifier({ trust: [profile(issuer)], clock });
    const snapshot = recall<CredentialSnapshot>(v, 'credential', verifiedBy(v));
    const status = { source: 'status-list' as const, state: 'active' as const, credential: snapshot, list: { url: LIST_URL, index: 7, validFrom: NOW, validUntil: NOW + 48 * HOUR }, fetchedAt: NOW };
    expect(evaluate({ ...input(snapshot, status), now: snapshot.validUntil + 1 })).toEqual({ decision: 'deny', reason: 'credential_expired' });
  });

  it('status evidence that was fresh is stale later, and status of another document is no evidence', async () => {
    const fetch = fakeFetch({ [LIST_URL]: statusList(issuer, []) });
    const v = createVerifier({ trust: [profile(issuer)], clock, fetch: { allowedOrigins: ['https://status.example.test'], fetch } });
    const c = verifiedBy(v);
    const snapshot = recall<CredentialSnapshot>(v, 'credential', c);
    const status = recall<any>(v, 'status', await v.checkStatus(c));
    expect(evaluate(input(snapshot, status))).toEqual({ decision: 'allow' });
    expect(evaluate({ ...input(snapshot, status), now: NOW + 2 * HOUR })).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });

    const second = recall<CredentialSnapshot>(v, 'credential', verifiedBy(v));
    expect(evaluate(input(second, status))).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
  });
});

function input(credential: CredentialSnapshot, status: any) {
  return {
    credential,
    status,
    audienceMatches: true,
    operation: { scope: 'data:documents:read', minLevel: 'L0' as const, onMissingApproval: 'refuse' as const },
    operationId: 'op-1',
    fingerprint: 'fp-1',
    approval: null,
    now: NOW,
    skewMs: 5000,
    statusMaxAgeMs: HOUR,
    onlineMaxAgeMs: 60_000,
  };
}
