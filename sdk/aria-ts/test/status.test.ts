import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { createVerifier, type StatusEvidence } from '../src';
import { credential, DID, fakeFetch, HOUR, LIST_URL, newIssuer, NOW, ONLINE, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const clock = () => new Date(NOW);
const ORIGIN = 'https://status.example.test';
const signed = sign(credential(), issuer);

async function status(routes: Parameters<typeof fakeFetch>[0], via?: 'online', extra: { statusMaxAgeSeconds?: number; origins?: string[] } = {}): Promise<StatusEvidence> {
  const fetch = fakeFetch(routes);
  const v = createVerifier({
    trust: [profile(issuer)],
    clock,
    ...(extra.statusMaxAgeSeconds === undefined ? {} : { statusMaxAgeSeconds: extra.statusMaxAgeSeconds }),
    fetch: { allowedOrigins: extra.origins ?? [ORIGIN], fetch },
  });
  const r = v.verifyCredential(signed);
  if (!r.ok) throw new Error(r.reason);
  return v.checkStatus(r.credential, via ? { via } : undefined);
}

describe('the signed status list', () => {
  it('reads the credential’s own bit, with the list’s signed times kept apart from the fetch time', async () => {
    const s = await status({ [LIST_URL]: statusList(issuer, [3]) });
    expect(s).toMatchObject({ source: 'status-list', state: 'active', list: { url: LIST_URL, index: 7 }, fetchedAt: '2026-11-01T12:00:00Z' });
    expect((s as { list: { validFrom: string } }).list.validFrom).toBe('2026-11-01T11:50:00Z');
    expect(await status({ [LIST_URL]: statusList(issuer, [7]) })).toMatchObject({ state: 'revoked' });
  });

  it('a list no older than the maximum age counts; an old list fetched now is stale', async () => {
    expect(await status({ [LIST_URL]: statusList(issuer, [], { ageMs: 2 * HOUR }) })).toMatchObject({ state: 'unavailable', reason: 'stale' });
    expect(await status({ [LIST_URL]: statusList(issuer, [], { ageMs: 2 * HOUR }) }, undefined, { statusMaxAgeSeconds: 3 * 3600 })).toMatchObject({ state: 'active' });
  });

  it('refuses a list it cannot trust', async () => {
    const other = newIssuer();
    expect(await status({ [LIST_URL]: statusList(other, []) })).toMatchObject({ state: 'unavailable', reason: 'signature_invalid' });
    expect(await status({ [LIST_URL]: { ...statusList(issuer, []), issuer: 'did:aria:other.example.test' } })).toMatchObject({ state: 'unavailable', reason: 'wrong_issuer' });
    expect(await status({ [LIST_URL]: statusList(issuer, [], { validityMs: 48 * HOUR }) })).toMatchObject({ state: 'unavailable', reason: 'not_valid_now' });
    expect(await status({ [LIST_URL]: statusList(issuer, [], { entries: 8 * 1024 }) })).toMatchObject({ state: 'unavailable', reason: 'malformed' });
  });

  it('refuses an uncompressed list and a decompression bomb', async () => {
    const raw = statusList(issuer, []);
    raw.credentialSubject.encodedList = 'u' + Buffer.alloc(16_384).toString('base64url');
    expect(await status({ [LIST_URL]: sign(raw, issuer) })).toMatchObject({ state: 'unavailable', reason: 'malformed' });
    const bomb = statusList(issuer, []);
    bomb.credentialSubject.encodedList = 'u' + gzipSync(Buffer.alloc(8 * 1024 * 1024)).toString('base64url');
    expect(await status({ [LIST_URL]: sign(bomb, issuer) })).toMatchObject({ state: 'unavailable', reason: 'malformed' });
  });

  it('fetches only from allowed origins, never follows a redirect, and bounds the body', async () => {
    expect(await status({ [LIST_URL]: statusList(issuer, []) }, undefined, { origins: ['https://api.aria.bar'] })).toMatchObject({ state: 'unavailable', reason: 'origin_not_allowed' });
    expect(await status({ [LIST_URL]: () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/' } }) })).toMatchObject({ state: 'unavailable', reason: 'fetch_failed' });
    expect(await status({ [LIST_URL]: () => new Response('x'.repeat(300_000), { status: 200 }) })).toMatchObject({ state: 'unavailable', reason: 'too_large' });
  });

  it('without a fetch policy the verifier is offline', async () => {
    const v = createVerifier({ trust: [profile(issuer)], clock });
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    expect(await v.checkStatus(r.credential)).toMatchObject({ state: 'unavailable', reason: 'offline' });
  });
});

describe('the online answer', () => {
  const url = `${ONLINE}${DID}`;

  it('is about the presented document only: another current document makes it superseded', async () => {
    expect(await status({ [url]: { did: DID, status: 'active', credentialId: signed.id } }, 'online')).toMatchObject({ source: 'online', state: 'active' });
    expect(await status({ [url]: { did: DID, status: 'revoked', credentialId: signed.id } }, 'online')).toMatchObject({ state: 'revoked' });
    const newer = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-0000000000ff';
    expect(await status({ [url]: { did: DID, status: 'active', credentialId: newer } }, 'online')).toMatchObject({ state: 'superseded', currentCredentialId: newer });
  });

  it('carries no signed time, refuses an answer about another DID, and needs a configured endpoint', async () => {
    const s = await status({ [url]: { did: DID, status: 'active', credentialId: signed.id } }, 'online');
    expect(s).not.toHaveProperty('list');
    expect(await status({ [url]: { did: 'did:aria:example.test:other', status: 'active', credentialId: signed.id } }, 'online')).toMatchObject({ state: 'unavailable', reason: 'malformed' });
    const v = createVerifier({ trust: [{ ...profile(issuer), onlineStatus: undefined } as never], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch({}) } });
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    expect(await v.checkStatus(r.credential, { via: 'online' })).toMatchObject({ state: 'unavailable', reason: 'no_online_endpoint' });
  });
});
