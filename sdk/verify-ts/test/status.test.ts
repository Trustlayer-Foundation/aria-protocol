import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { checkCredentialStatus } from '../src/status';
import { checkRevocation } from '../src/revocation';
import { canonicalJson } from '../src/canonical-json';
import { RevocationCheckError } from '../src/errors';

const fixtures = join(import.meta.dirname, 'fixtures');
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), 'utf-8'));
const credential = read('valid-aid.json');
const keys = read('registry-keys.json');

const LIST_URL: string = credential.credentialStatus.statusListCredential;
const INDEX = Number(credential.credentialStatus.statusListIndex);
const HOUR = 3_600_000;
const iso = (offset: number) => new Date(Date.now() + offset).toISOString().replace(/\.\d{3}Z$/, 'Z');

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

interface ListOptions {
  revoked?: number[];
  entries?: number;
  /** Change the list before it is signed. */
  edit?: (list: Record<string, unknown>) => void;
}

/** A Bitstring Status List credential signed with the test registry keys. */
function signedList({ revoked = [], entries = 131_072, edit }: ListOptions = {}) {
  const bits = new Uint8Array(entries / 8);
  for (const i of revoked) bits[i >> 3] |= 0x80 >> (i & 7);
  const unsigned: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: LIST_URL,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: credential.issuer,
    validFrom: iso(-HOUR),
    validUntil: iso(23 * HOUR),
    credentialSubject: {
      id: `${LIST_URL}#list`,
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: 'u' + base64url(gzipSync(bits)),
    },
  };
  edit?.(unsigned);
  const payload = new TextEncoder().encode(canonicalJson(unsigned));
  const pq = ml_dsa65.sign(payload, hex(keys.pqSecretKey));
  const ed = ed25519.sign(payload, hex(keys.edSecretKey));
  const composite = new Uint8Array(4 + pq.length + ed.length);
  new DataView(composite.buffer).setUint32(0, pq.length, false);
  composite.set(pq, 4);
  composite.set(ed, 4 + pq.length);
  return {
    ...unsigned,
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'mldsa65-ed25519-2026',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${credential.issuer}#key-1`,
      proofValue: 'u' + base64url(composite),
    },
  };
}

function answer(body: unknown, status = 200) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }) as unknown as typeof fetch;
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe('checkCredentialStatus, from the signed status list', () => {
  it('reads the credential as active when its own bit is clear', async () => {
    answer(signedList({ revoked: [INDEX - 1, INDEX + 1] }));
    const result = await checkCredentialStatus(credential);
    expect(result).toMatchObject({
      status: 'active',
      via: 'statusList',
      credentialId: credential.id,
      did: credential.credentialSubject.id,
    });
    expect(globalThis.fetch).toHaveBeenCalledWith(LIST_URL, expect.any(Object));
  });

  it('reads the credential as revoked when its own bit is set', async () => {
    answer(signedList({ revoked: [INDEX] }));
    expect((await checkCredentialStatus(credential)).status).toBe('revoked');
  });

  it('fetches from a custom API origin, keeping the list the credential names', async () => {
    answer(signedList());
    await checkCredentialStatus(credential, { apiUrl: 'https://custom-api.example.com' });
    expect(globalThis.fetch).toHaveBeenCalledWith(
      `https://custom-api.example.com${new URL(LIST_URL).pathname}`,
      expect.any(Object),
    );
  });

  const refused: Array<[string, RegExp, () => unknown, number?]> = [
    ['a list altered after signing', /signature does not verify/, () => {
      const list = signedList();
      (list.credentialSubject as Record<string, unknown>).encodedList = signedList({ revoked: [INDEX] })
        .credentialSubject.encodedList;
      return list;
    }],
    ['a list with one signature half replaced', /signature does not verify/, () => {
      const list = signedList();
      const value = list.proof.proofValue;
      list.proof.proofValue = value.slice(0, -10) + 'AAAAAAAAAA';
      return list;
    }],
    ['a list that states no validUntil', /valid validFrom and validUntil/, () => signedList({ edit: (l) => { delete l.validUntil; } })],
    ['a list that states no validFrom', /valid validFrom and validUntil/, () => signedList({ edit: (l) => { delete l.validFrom; } })],
    ['a list with a malformed validFrom', /valid validFrom and validUntil/, () => signedList({ edit: (l) => { l.validFrom = 'not a date'; } })],
    ['a list with a malformed validUntil', /valid validFrom and validUntil/, () => signedList({ edit: (l) => { l.validUntil = '2026-10-02'; } })],
    ['a list whose window ends before it starts', /validity window/, () => signedList({ edit: (l) => { l.validUntil = iso(-2 * HOUR); } })],
    ['a list valid for a year', /validity window/, () => signedList({ edit: (l) => { l.validUntil = iso(365 * 24 * HOUR); } })],
    ['a list valid for one second more than a day', /validity window/, () => signedList({ edit: (l) => { l.validUntil = iso(23 * HOUR + 1_000); } })],
    ['an expired list', /has expired/, () => signedList({ edit: (l) => { l.validUntil = iso(-60_000); } })],
    ['a list not yet valid', /not valid yet/, () => signedList({ edit: (l) => { l.validFrom = iso(HOUR); } })],
    ['another list', /not the one the credential names/, () => signedList({ edit: (l) => { l.id = `${LIST_URL}-other`; } })],
    ['a list by another issuer', /not the one the credential names/, () => signedList({ edit: (l) => { l.issuer = 'did:aria:other.example'; } })],
    ['a list one byte shorter than 131,072 entries', /shorter than 131,072 entries/, () => signedList({ entries: 131_064 })],
    ['a list of six bytes', /shorter than 131,072 entries/, () => signedList({ entries: 48 })],
    ['a list that is unavailable', /HTTP 503/, () => ({}), 503],
  ];
  for (const [name, why, list, status] of refused) {
    it(`refuses ${name}`, async () => {
      answer(list(), status);
      const check = checkCredentialStatus(credential);
      await expect(check).rejects.toThrow(RevocationCheckError);
      await expect(check).rejects.toThrow(why);
    });
  }

  it('accepts a window of exactly 24 hours and a list of exactly 131,072 entries', async () => {
    const list = signedList();
    expect(Date.parse(list.validUntil as string) - Date.parse(list.validFrom as string)).toBe(24 * HOUR);
    const encoded = (list.credentialSubject as { encodedList: string }).encodedList;
    expect(gunzipSync(Buffer.from(encoded.slice(1), 'base64url')).length).toBe(131_072 / 8);
    answer(list);
    expect((await checkCredentialStatus(credential)).status).toBe('active');
  });

  it('refuses an index the list does not cover', async () => {
    const beyond = structuredClone(credential);
    beyond.credentialStatus.statusListIndex = '200000';
    answer(signedList());
    await expect(checkCredentialStatus(beyond)).rejects.toThrow(/does not cover/);
  });

  it('refuses a credential without an instance identifier', async () => {
    answer(signedList());
    await expect(checkCredentialStatus(read('valid-aid-pre-cutover.json')))
      .rejects.toThrow(RevocationCheckError);
  });
});

describe('checkCredentialStatus, online', () => {
  const did = credential.credentialSubject.id;
  const online = { via: 'online' as const };

  it('reads active only for the credential the answer names', async () => {
    answer({ did, credentialId: credential.id, status: 'active' });
    const result = await checkCredentialStatus(credential, online);
    expect(result).toMatchObject({ status: 'active', via: 'online', credentialId: credential.id });
    expect(globalThis.fetch).toHaveBeenCalledWith(
      `https://api.aria.bar/v1/verify/${encodeURIComponent(did)}`,
      expect.any(Object),
    );
  });

  it('reads revoked', async () => {
    answer({ did, credentialId: credential.id, status: 'revoked' });
    expect((await checkCredentialStatus(credential, online)).status).toBe('revoked');
  });

  it('reads superseded when the answer concerns a newer credential of the DID', async () => {
    answer({
      did,
      credentialId: 'https://api.aria.bar/v1/credentials/0199aaaa-0000-7000-8000-000000000000',
      status: 'active',
    });
    expect((await checkCredentialStatus(credential, online)).status).toBe('superseded');
  });

  for (const [name, why, body] of [
    ['without a status', /recognized revocation status/, { did, credentialId: credential.id }],
    ['with an unrecognized status', /recognized revocation status/, { did, credentialId: credential.id, status: 'unknown' }],
    ['without a credential identifier', /name the credential/, { did, status: 'active' }],
  ] as const) {
    it(`refuses an answer ${name}`, async () => {
      answer(body);
      const check = checkCredentialStatus(credential, online);
      await expect(check).rejects.toThrow(RevocationCheckError);
      await expect(check).rejects.toThrow(why);
    });
  }

  it('refuses a failed request', async () => {
    answer({ error: 'unavailable' }, 503);
    await expect(checkCredentialStatus(credential, online)).rejects.toThrow(/HTTP 503/);
  });
});

describe('checkRevocation fails closed', () => {
  for (const [name, body] of [
    ['without a status', { did: 'did:aria:example.com:agent' }],
    ['with an unrecognized status', { status: 'suspended' }],
  ] as const) {
    it(`refuses an answer ${name}`, async () => {
      answer(body);
      const check = checkRevocation('did:aria:example.com:agent');
      await expect(check).rejects.toThrow(RevocationCheckError);
      await expect(check).rejects.toThrow(/recognized revocation status/);
    });
  }
});
