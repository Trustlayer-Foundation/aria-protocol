// Regressions for the S1 review (ops/updates/REVIEW-s1-sdk-credentials-2026-10-31.md):
// each case failed, or was characterized as a defect, at adbcb9b.
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';
import { createVerifier, type StatusEvidence } from '../src';
import { acceptableEd25519Key } from '../src/internal/verify-credential';
import { credential, DID, fakeFetch, HOUR, iso, LIST_URL, newIssuer, NOW, ONLINE, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const ORIGIN = 'https://status.example.test';
const signed = sign(credential(), issuer);

async function listStatus(body: unknown, clock: () => Date = () => new Date(NOW), routes?: Parameters<typeof fakeFetch>[0]): Promise<StatusEvidence> {
  const v = createVerifier({ trust: [profile(issuer)], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch(routes ?? { [LIST_URL]: body }) } });
  const r = v.verifyCredential(signed);
  if (!r.ok) throw new Error(r.reason);
  return v.checkStatus(r.credential);
}

describe('S1-F1: the list must be the one the credential names, in the supported profile', () => {
  it('reads the named list, active and revoked', async () => {
    expect(await listStatus(statusList(issuer, []))).toMatchObject({ state: 'active' });
    expect(await listStatus(statusList(issuer, [7]))).toMatchObject({ state: 'revoked' });
  });

  it('refuses another genuine list of the same issuer served in its place', async () => {
    const other = statusList(issuer, [], { id: 'https://status.example.test/v1/status/2' });
    expect(await listStatus(other)).toMatchObject({ state: 'unavailable', reason: 'malformed' });
  });

  it('refuses the right ID edited onto another list without re-signing', async () => {
    const other = statusList(issuer, [], { id: 'https://status.example.test/v1/status/2' });
    other.id = LIST_URL;
    expect((await listStatus(other)).state).toBe('unavailable');
  });

  it('refuses a subject it does not support', async () => {
    expect(await listStatus(statusList(issuer, [], { subject: { statusSize: 2 } }))).toMatchObject({ state: 'unavailable', reason: 'malformed' });
    expect(await listStatus(statusList(issuer, [], { subject: { type: 'StatusList2021' } }))).toMatchObject({ state: 'unavailable', reason: 'malformed' });
    expect(await listStatus(statusList(issuer, [], { subject: { statusPurpose: 'suspension' } }))).toMatchObject({ state: 'unavailable', reason: 'malformed' });
  });
});

describe('S1-F2: trusted keys are owned copies, whatever their input type', () => {
  for (const [name, wrap] of [
    ['Uint8Array', (k: Uint8Array) => Uint8Array.from(k)],
    ['Buffer', (k: Uint8Array) => Buffer.from(k)],
    ['Buffer at an offset', (k: Uint8Array) => Buffer.concat([Buffer.alloc(7), Buffer.from(k)]).subarray(7)],
  ] as const) {
    it(`changing the caller's ${name} after construction changes nothing`, () => {
      const replacement = newIssuer();
      const mldsa65 = wrap(issuer.pq.publicKey);
      const ed = wrap(issuer.edPublic);
      const v = createVerifier({ trust: [profile(issuer, { keys: { mldsa65, ed25519: ed } })], clock: () => new Date(NOW) });
      const theirs = sign(credential(), replacement);
      expect(v.verifyCredential(signed)).toMatchObject({ ok: true });
      expect(v.verifyCredential(theirs)).toMatchObject({ ok: false, reason: 'signature_invalid' });
      mldsa65.set(replacement.pq.publicKey);
      ed.set(replacement.edPublic);
      expect(v.verifyCredential(signed)).toMatchObject({ ok: true });
      expect(v.verifyCredential(theirs)).toMatchObject({ ok: false, reason: 'signature_invalid' });
    });
  }
});

describe('S1-F3: the holder key meets the authority’s strict rule', () => {
  const P = 2n ** 255n - 19n;
  const le = (n: bigint): Uint8Array => {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
    return out;
  };
  const identity = le(1n); // y = 1, x = 0: the neutral element
  const minusOne = le(P - 1n); // y = -1: order 2
  const nonCanonical = le(P + 1n); // y = p + 1, a second spelling of the identity
  const honest = ed25519.getPublicKey(new Uint8Array(32).fill(9));
  const mixed = ed25519.Point.fromBytes(honest).add(ed25519.Point.fromBytes(minusOne)).toBytes();

  it('accepts an honestly generated key', () => {
    expect(acceptableEd25519Key(honest)).toBe(true);
  });

  it('refuses identity, small-order, non-canonical and mixed-torsion keys', () => {
    for (const key of [identity, minusOne, nonCanonical, mixed]) expect(acceptableEd25519Key(key)).toBe(false);
  });

  it('refuses a credential whose holder key is the identity point', () => {
    const c = credential();
    c.credentialSubject.holderKey.publicKeyMultibase = 'z' + base58(identity);
    const r = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW) }).verifyCredential(sign(c, issuer));
    expect(r).toMatchObject({ ok: false, reason: 'holder_key_invalid' });
  });
});

describe('S1-F4: status is judged when the evidence is complete', () => {
  function advancingClock(): { clock: () => Date; advance: (ms: number) => void } {
    let t = NOW;
    return { clock: () => new Date(t), advance: (ms) => (t += ms) };
  }

  it('a list that expires during retrieval is not active', async () => {
    const { clock, advance } = advancingClock();
    // Signed long ago, valid until one second after the call starts.
    const list = statusList(issuer, [], { ageMs: HOUR - 1000, validityMs: HOUR });
    const routes = { [LIST_URL]: () => (advance(2000), new Response(JSON.stringify(list), { status: 200 })) };
    const v = createVerifier({ trust: [profile(issuer)], clock, statusMaxAgeSeconds: 2 * 3600, fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch(routes) } });
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    expect(await v.checkStatus(r.credential)).toMatchObject({ state: 'unavailable', reason: 'not_valid_now', fetchedAt: iso(2000) });
  });

  it('a list that crosses the maximum age during retrieval is stale', async () => {
    const { clock, advance } = advancingClock();
    const list = statusList(issuer, [], { ageMs: HOUR - 1000 });
    const routes = { [LIST_URL]: () => (advance(2000), new Response(JSON.stringify(list), { status: 200 })) };
    expect(await listStatus(undefined, clock, routes)).toMatchObject({ state: 'unavailable', reason: 'stale' });
  });

  it('valid evidence stays usable, and fetchedAt is when it arrived', async () => {
    const { clock, advance } = advancingClock();
    const routes = { [LIST_URL]: () => (advance(1500), new Response(JSON.stringify(statusList(issuer, [])), { status: 200 })) };
    expect(await listStatus(undefined, clock, routes)).toMatchObject({ state: 'active', fetchedAt: iso(1500) });
  });

  it('an online answer is stamped with the time it was observed', async () => {
    const { clock, advance } = advancingClock();
    const routes = { [`${ONLINE}${DID}`]: () => (advance(3000), new Response(JSON.stringify({ did: DID, status: 'active', credentialId: signed.id }), { status: 200 })) };
    const v = createVerifier({ trust: [profile(issuer)], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch(routes) } });
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    expect(await v.checkStatus(r.credential, { via: 'online' })).toMatchObject({ state: 'active', fetchedAt: iso(3000) });
  });
});

describe('N1: an incomplete online answer is not evidence of a replacement', () => {
  const url = `${ONLINE}${DID}`;
  for (const [name, answer] of [
    ['an empty reference and no status', { did: DID, credentialId: '' }],
    ['another reference and no status', { did: DID, credentialId: 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-0000000000ff' }],
    ['a reference that is not a URL', { did: DID, credentialId: 'abc', status: 'active' }],
  ] as const) {
    it(`${name} is unavailable`, async () => {
      const v = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW), fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch({ [url]: answer }) } });
      const r = v.verifyCredential(signed);
      if (!r.ok) throw new Error(r.reason);
      expect(await v.checkStatus(r.credential, { via: 'online' })).toMatchObject({ state: 'unavailable', reason: 'malformed' });
    });
  }
});

function base58(bytes: Uint8Array): string {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  let out = '';
  while (n) {
    out = alphabet[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}
