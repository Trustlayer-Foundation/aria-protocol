// Synthetic test material: ephemeral keys made per process, never written anywhere.
// The same material as @aria-registry/sdk's test fixtures, through its public API only.
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { canonicalJson, type TrustProfile } from '@aria-registry/sdk';

export const NOW = Date.parse('2026-11-01T12:00:00Z');
export const iso = (offsetMs: number): string => new Date(NOW + offsetMs).toISOString().replace('.000Z', 'Z');
export const HOUR = 3_600_000;

export const ISSUER = 'did:aria:issuer.example.test';
export const METHOD = `${ISSUER}#key-1`;
export const LIST_URL = 'https://status.example.test/v1/status/1';
export const ONLINE = 'https://status.example.test/v1/verify/';
export const DID = 'did:aria:example.test:probe';

export interface Issuer {
  readonly pq: { publicKey: Uint8Array; secretKey: Uint8Array };
  readonly edSecret: Uint8Array;
  readonly edPublic: Uint8Array;
}

export function newIssuer(): Issuer {
  const pq = ml_dsa65.keygen();
  const edSecret = randomBytes(32);
  return { pq, edSecret, edPublic: ed25519.getPublicKey(edSecret) };
}

export function profile(issuer: Issuer, overrides: Partial<TrustProfile> = {}): TrustProfile {
  return {
    id: 'demo',
    issuer: ISSUER,
    verificationMethod: METHOD,
    keys: { mldsa65: issuer.pq.publicKey, ed25519: issuer.edPublic },
    maxLevel: 'L1',
    statusLists: [LIST_URL],
    onlineStatus: ONLINE,
    ...overrides,
  };
}

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

export const holderSecret = randomBytes(32);
export const holderMultibase = 'z' + base58(ed25519.getPublicKey(holderSecret));

/** An unsigned AID 1.0 that conforms to the schema. */
export function credential(): Record<string, any> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://aria.bar/ns/v1'],
    id: 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-000000000001',
    type: ['VerifiableCredential', 'ARIAIdentityDocument'],
    issuer: ISSUER,
    validFrom: iso(-HOUR),
    validUntil: iso(24 * HOUR),
    credentialSubject: {
      id: DID,
      agentName: 'probe',
      version: '1.0.0',
      spec_version: '1.0',
      trustLevel: 'L0',
      scope: ['data:documents:read', 'payments:transfer:create'],
      hitlRequired: ['payments:transfer:create'],
      delegationDepth: 0,
      maxDelegationDepth: 0,
      principal: { type: 'Person', did: 'did:aria:example.test:owner', jurisdiction: 'MX', verificationStatus: 'self-declared' },
      holderKey: { id: `${DID}#holder-key-1`, type: 'Ed25519VerificationKey2020', publicKeyMultibase: holderMultibase },
      enrollmentAttestation: { userAgentAgreement: true, attestedAt: iso(-2 * HOUR), termsVersion: '1.0.0', privacyVersion: '1.0.0' },
    },
    credentialStatus: { id: `${LIST_URL}#7`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: LIST_URL },
  };
}

/** Signs `document` (without its `proof`) with both halves of `issuer`'s key; `corrupt` damages one half. */
export function sign(document: Record<string, any>, issuer: Issuer, corrupt?: 'pq' | 'classical'): Record<string, any> {
  const unsigned = structuredClone(document);
  delete unsigned.proof;
  const payload = new TextEncoder().encode(canonicalJson(unsigned));
  const pqSig = ml_dsa65.sign(payload, issuer.pq.secretKey);
  const edSig = ed25519.sign(payload, issuer.edSecret);
  if (corrupt === 'pq') pqSig[0] = pqSig[0]! ^ 1;
  if (corrupt === 'classical') edSig[0] = edSig[0]! ^ 1;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(pqSig.length);
  return {
    ...unsigned,
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'mldsa65-ed25519-2026',
      created: iso(-HOUR),
      verificationMethod: METHOD,
      proofPurpose: 'assertionMethod',
      proofValue: 'u' + Buffer.concat([length, Buffer.from(pqSig), Buffer.from(edSig)]).toString('base64url'),
    },
  };
}

/** A signed status list with `revoked` indexes set, signed `ageMs` ago and valid for `validityMs`. */
export function statusList(
  issuer: Issuer,
  revoked: number[],
  { ageMs = 10 * 60_000, validityMs = 24 * HOUR, entries = 131_072, id = LIST_URL, subject = {} as Record<string, unknown> } = {},
): Record<string, any> {
  const bits = Buffer.alloc(entries / 8);
  for (const i of revoked) bits[i >> 3]! |= 0x80 >> (i & 7);
  return sign(
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: ISSUER,
      validFrom: iso(-ageMs),
      validUntil: iso(-ageMs + validityMs),
      credentialSubject: { id: `${id}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u' + gzipSync(bits).toString('base64url'), ...subject },
    },
    issuer,
  );
}

/** A fetch that serves fixed bodies and records every call. */
export function fakeFetch(routes: Record<string, unknown | ((init?: RequestInit) => Response)>): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (init?.redirect !== 'error') throw new Error('the SDK must refuse redirects');
    const route = routes[url];
    if (route === undefined) return new Response('not found', { status: 404 });
    if (typeof route === 'function') return (route as (i?: RequestInit) => Response)(init);
    return new Response(JSON.stringify(route), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch & { calls: string[] };
  f.calls = calls;
  return f;
}
