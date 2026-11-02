// Synthetic issuer, credential and status list for the artifact checks. Keys are
// made per run and never written. Uses only the public API of @trustlayer-foundation/aria-sdk.
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { canonicalJson } from '@trustlayer-foundation/aria-sdk';

export const NOW = Date.parse('2026-11-01T12:00:00Z');
export const HOUR = 3_600_000;
const iso = (offset) => new Date(NOW + offset).toISOString().replace('.000Z', 'Z');
const ISSUER = 'did:aria:issuer.example.test';
const METHOD = `${ISSUER}#key-1`;
export const LIST_URL = 'https://status.example.test/v1/status/1';
export const ORIGIN = 'https://status.example.test';
const DID = 'did:aria:example.test:probe';

const pq = ml_dsa65.keygen();
const edSecret = randomBytes(32);
const probeHolder = ed25519.getPublicKey(randomBytes(32));

export const profile = {
  id: 'demo',
  issuer: ISSUER,
  verificationMethod: METHOD,
  keys: { mldsa65: pq.publicKey, ed25519: ed25519.getPublicKey(edSecret) },
  maxLevel: 'L1',
  statusLists: [LIST_URL],
  onlineStatus: 'https://status.example.test/v1/verify/',
};

function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  let out = '';
  while (n) {
    out = alphabet[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return out;
}

export function sign(document) {
  const unsigned = structuredClone(document);
  delete unsigned.proof;
  const payload = new TextEncoder().encode(canonicalJson(unsigned));
  const pqSig = ml_dsa65.sign(payload, pq.secretKey);
  const edSig = ed25519.sign(payload, edSecret);
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
      proofValue: `u${Buffer.concat([length, Buffer.from(pqSig), Buffer.from(edSig)]).toString('base64url')}`,
    },
  };
}

const unsignedCredential = {
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
    scope: ['data:documents:read'],
    hitlRequired: [],
    delegationDepth: 0,
    maxDelegationDepth: 0,
    principal: { type: 'Person', did: 'did:aria:example.test:owner', jurisdiction: 'MX', verificationStatus: 'self-declared' },
    holderKey: { id: `${DID}#holder-key-1`, type: 'Ed25519VerificationKey2020', publicKeyMultibase: `z${base58(probeHolder)}` },
    enrollmentAttestation: { userAgentAgreement: true, attestedAt: iso(-2 * HOUR), termsVersion: '1.0.0', privacyVersion: '1.0.0' },
  },
  credentialStatus: { id: `${LIST_URL}#7`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: LIST_URL },
};
export const credential = sign(unsignedCredential);

/** A credential of `did` with its own holder key (index `n` in the status list), and that key as a signer. */
export function holder(did, n, { level = 'L1', scopes = ['payments:transfer:create'], hitl = [] } = {}) {
  const secret = randomBytes(32);
  const doc = structuredClone(unsignedCredential);
  const keyId = `${did}#holder-key-${n}`;
  doc.id = `https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  Object.assign(doc.credentialSubject, { id: did, trustLevel: level, scope: scopes, hitlRequired: hitl });
  doc.credentialSubject.holderKey = { id: keyId, type: 'Ed25519VerificationKey2020', publicKeyMultibase: `z${base58(ed25519.getPublicKey(secret))}` };
  doc.credentialStatus = { ...doc.credentialStatus, id: `${LIST_URL}#${n}`, statusListIndex: String(n) };
  return { document: sign(doc), url: doc.id, signer: { keyId, algorithm: 'ed25519', sign: async (bytes) => ed25519.sign(bytes, secret) } };
}

export function statusList(revoked) {
  const bits = Buffer.alloc(131_072 / 8);
  for (const i of revoked) bits[i >> 3] |= 0x80 >> (i & 7);
  return sign({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: LIST_URL,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: ISSUER,
    validFrom: iso(-10 * 60_000),
    validUntil: iso(24 * HOUR - 10 * 60_000),
    credentialSubject: { id: `${LIST_URL}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: `u${gzipSync(bits).toString('base64url')}` },
  });
}

/** Serves the status list: `body`, or what `body()` returns at each fetch. */
export function fetchServing(body) {
  return async (input, init) => {
    if (init?.redirect !== 'error') throw new Error('redirects must be refused');
    if (String(input) !== LIST_URL) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(typeof body === 'function' ? body() : body), { status: 200 });
  };
}

/** Collects named checks; `done` prints them and sets the exit code. */
export function checks(name) {
  const results = [];
  return {
    async check(label, fn) {
      try {
        const ok = await fn();
        results.push({ label, ok: ok === true, ...(ok === true ? {} : { got: String(ok) }) });
      } catch (error) {
        results.push({ label, ok: false, error: `${error?.name}: ${error?.message}` });
      }
    },
    done() {
      const failed = results.filter((r) => !r.ok).length;
      console.log(JSON.stringify({ scenario: name, passed: results.length - failed, failed, results }));
      process.exitCode = failed ? 1 : 0;
    },
  };
}

export async function rejects(promiseOrFn, type) {
  try {
    await (typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn);
    return 'did not throw';
  } catch (error) {
    return error instanceof type ? true : `threw ${error?.name}`;
  }
}
