#!/usr/bin/env node
// Generates the ARIA AP request, fingerprint, receipt, receiver identity and historical
// receipt vectors (provisional profile).
//
// Keys are synthetic: each seed is SHA-256 of a public label below, so anyone can
// rebuild them. They exist only to make these vectors and are never trusted anywhere.
// The output is deterministic; `npm run generate` followed by `git diff` shows drift.
//
// Expectations are declared per case. Derived values (signature base digest,
// fingerprint) are computed here with this file's own code; check.mjs recomputes them
// with independent implementations and compares.

import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const profile = JSON.parse(readFileSync(new URL('./profile.json', import.meta.url), 'utf8'));
const enc = new TextEncoder();
const Point = ed25519.Point;
const L = Point.Fn.ORDER;
const P = Point.Fp.ORDER;

const NOW = Date.parse('2026-11-01T12:00:00Z') / 1000;
const ORIGIN = 'https://bank.example.test';
const RECEIVER_DID = 'did:aria:bank.example.test:transfers';
const SENDER_DID = 'did:aria:customer.example.test:payments-agent';
const REGISTRY = 'https://registry.example.test/v1/credentials/';

// ---------------------------------------------------------------- encodings

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const digest = (bytes) => `sha-256=:${b64(sha256(bytes))}:`;
const utf8 = (text) => enc.encode(text);
const iso = (epoch) => new Date(epoch * 1000).toISOString().replace('.000Z', 'Z');

// ARIA canonical JSON, as in sdk/aria-ts/src/internal/canonical.ts.
function canonical(value) {
  return JSON.stringify(value, (_, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.keys(v).sort().reduce((sorted, key) => {
        sorted[key] = v[key];
        return sorted;
      }, {});
    }
    return v;
  });
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return out;
}

function uuid(label) {
  const b = sha256(utf8(`aria-ap-1 vector uuid: ${label}`)).slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Buffer.from(b).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const challenge = (label) => b64url(sha256(utf8(`aria-ap-1 challenge: ${label}`)).slice(0, 16));
const sfString = (s) => `"${s}"`;

const numberLE = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex') || '0'}`);
function toLE(n, length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
const concat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));
const modL = (n) => ((n % L) + L) % L;

// ---------------------------------------------------------------- keys

function key(label) {
  const seed = sha256(utf8(`aria-ap-1 synthetic test key: ${label}`));
  return { seed, publicKey: ed25519.getPublicKey(seed) };
}

const T8 = ED25519_TORSION_SUBGROUP.map((h) => Point.fromHex(h)).find(
  (p) => p.multiplyUnsafe(8n).is0() && !p.multiplyUnsafe(4n).is0(),
);

// An Ed25519 signature computed by hand, so a case can use a torsioned R or a
// mixed-torsion public key. Without options it equals ed25519.sign (asserted below).
function signManual(seed, message, { torsionR = false, publicKey } = {}) {
  const { prefix, scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed);
  const r = modL(numberLE(sha512(concat(prefix, message))));
  let R = Point.BASE.multiply(r);
  if (torsionR) R = R.add(T8);
  const Rb = R.toBytes();
  const k = modL(numberLE(sha512(concat(Rb, publicKey ?? pointBytes, message))));
  return concat(Rb, toLE(modL(r + k * scalar), 32));
}
{
  const probe = key('probe');
  const m = utf8('probe');
  if (b64(signManual(probe.seed, m)) !== b64(ed25519.sign(m, probe.seed))) {
    throw new Error('manual signing diverges from ed25519.sign');
  }
}

// ---------------------------------------------------------------- credentials

// A verified view of a credential: what S1's verifyCredential establishes. The full
// AID is not needed here; the digest commits to this stand-in document.
function credential(name, did, n, publicKey) {
  const url = REGISTRY + uuid(`credential ${name}`);
  const holderKey = {
    id: `${did}#holder-key-${n}`,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: `z${base58(publicKey)}`,
  };
  return { url, digest: digest(utf8(canonical({ id: url, did, holderKey }))), did, holderKey };
}

const KEYS = {
  s1: key('sender holder key 1'),
  s2: key('sender holder key 2'),
  attacker: key('attacker key'),
  mixedBase: key('sender mixed-torsion base key'),
  r1: key('receiver holder key 1'),
  r2: key('receiver holder key 2'),
  other: key('other receiver holder key'),
};
const IDENTITY = Point.ZERO.toBytes();
const NONCANONICAL_IDENTITY = toLE(P + 1n, 32); // y = p + 1 encodes y = 1 non-canonically
const MIXED = Point.fromBytes(KEYS.mixedBase.publicKey).add(T8).toBytes();

const SENDERS = {
  s1: credential('sender 1', SENDER_DID, 1, KEYS.s1.publicKey),
  s2: credential('sender 2 (renewed)', SENDER_DID, 2, KEYS.s2.publicKey),
  weak: credential('weak identity key', 'did:aria:customer.example.test:weak-agent', 1, IDENTITY),
  noncanonical: credential('non-canonical key', 'did:aria:customer.example.test:odd-agent', 1, NONCANONICAL_IDENTITY),
  mixed: credential('mixed-torsion key', 'did:aria:customer.example.test:mixed-agent', 1, MIXED),
};
const RECEIVERS = {
  r1: { ...credential('receiver 1', RECEIVER_DID, 1, KEYS.r1.publicKey), validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' },
  r2: { ...credential('receiver 2 (renewed)', RECEIVER_DID, 2, KEYS.r2.publicKey), validFrom: '2026-11-05T00:00:00Z', validUntil: '2027-11-05T00:00:00Z' },
  other: { ...credential('other receiver', 'did:aria:other.example.test:service', 1, KEYS.other.publicKey), validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' },
};

// ---------------------------------------------------------------- descriptors

const DESCRIPTORS = [
  { name: 'transfers.create', class: 'unsafe-body', method: 'POST', path: '/v1/transfers', mediaType: 'application/json', query: [], semanticHeaders: [] },
  { name: 'transfers.update', class: 'unsafe-body', method: 'PATCH', path: '/v1/transfers/t-1001', mediaType: 'application/json', query: [], semanticHeaders: ['if-match'] },
  { name: 'transfers.cancel', class: 'unsafe-empty', method: 'DELETE', path: '/v1/transfers/t-1001', query: [], semanticHeaders: [] },
  { name: 'balance.read', class: 'safe-receiptable', method: 'GET', path: '/v1/accounts/acc-1/balance', query: ['currency'], semanticHeaders: [] },
  { name: 'operations.lookup', class: 'retrieval', method: 'GET', path: '/v1/operations', query: ['operation'], semanticHeaders: [] },
];
const descriptor = (name) => DESCRIPTORS.find((d) => d.name === name);

const OP = { X: uuid('operation X'), Y: uuid('operation Y'), Z: uuid('operation Z'), W: uuid('operation W') };
const TRANSFER = '{"amount":"10.00","currency":"EUR","to":"acc-2"}';

// ---------------------------------------------------------------- requests

const header = (headers, name) => headers.find(([n]) => n === name)?.[1];

function fingerprintOf(d, target, headers, body) {
  const url = new URL(target, ORIGIN);
  const query = {};
  for (const name of d.query) if (url.searchParams.has(name)) query[name] = url.searchParams.get(name);
  const semanticHeaders = {};
  for (const name of d.semanticHeaders) {
    const value = header(headers, name);
    if (value !== undefined) semanticHeaders[name] = value;
  }
  const object = { class: d.class, method: d.method, path: url.pathname, query, semanticHeaders };
  if (d.class === 'unsafe-body') {
    object.mediaType = d.mediaType;
    object.contentDigest = digest(utf8(body));
  }
  if (d.class === 'unsafe-empty') object.contentDigest = digest(new Uint8Array());
  return digest(utf8(canonical(object)));
}

const challengesUsed = new Set();

function build(spec) {
  const d = descriptor(spec.descriptor);
  const method = spec.method ?? d.method;
  const target = spec.target ?? d.path + (spec.query ? `?${spec.query}` : '');
  const sender = SENDERS[spec.credential ?? 's1'];
  const receiptable = d.class !== 'retrieval';
  const unsafe = d.class === 'unsafe-body' || d.class === 'unsafe-empty';
  const body = spec.body !== undefined ? spec.body : d.class === 'unsafe-body' ? TRANSFER : null;

  const headers = [];
  const contentType = spec.contentType === null ? undefined : spec.contentType ?? d.mediaType;
  if (body !== null && contentType !== undefined) headers.push(['content-type', contentType]);
  if (unsafe && spec.contentDigest !== null) headers.push(['content-digest', spec.contentDigest ?? digest(utf8(body ?? ''))]);
  if (receiptable && spec.operation !== null) headers.push(['aria-operation', sfString(spec.operation ?? OP.X)]);
  const credentialDigest = spec.credentialDigest ?? sender.digest;
  headers.push(['aria-credential', `${sfString(spec.credentialUrl ?? sender.url)};digest=${credentialDigest.slice('sha-256='.length)}`]);
  headers.push(['aria-audience', sfString(spec.audience ?? RECEIVER_DID)]);
  for (const [name, value] of spec.headers ?? []) headers.push([name, value]);

  const present = d.semanticHeaders.filter((h) => header(headers, h) !== undefined);
  const covered = spec.covered ?? [...profile.classes[d.class].components, ...present];
  const signedValue = (component) => {
    if (component === '@method') return method;
    if (component === '@target-uri') return (spec.signedOrigin ?? ORIGIN) + target;
    // A repeated field is combined as RFC 9421 does; the profile refuses it (REQ-054).
    // A repeated field is signed over its RFC 9421 combination (REQ-054); an absent one as before.
    const values = headers.filter(([n]) => n === component).map(([, v]) => v);
    return values.length > 1 ? values.join(', ') : header(headers, component);
  };
  const label = spec.challenge ?? spec.id;
  challengesUsed.add(label);
  const created = NOW + (spec.created ?? -5);
  const expires = NOW + (spec.expires ?? 25);
  const params = {
    created,
    expires,
    nonce: sfString(challenge(label)),
    keyid: sfString(spec.keyid ?? sender.holderKey.id),
    alg: sfString('ed25519'),
    tag: sfString(profile.transport.tag),
    ...spec.params,
  };
  const signatureParams = `(${covered.map(sfString).join(' ')})${Object.entries(params)
    .filter(([, v]) => v !== null)
    .map(([k, v]) => `;${k}=${v}`)
    .join('')}`;
  const base = [...covered.map((c) => `${sfString(c)}: ${signedValue(c)}`), `"@signature-params": ${signatureParams}`].join('\n');
  const message = utf8(base);

  const signer = spec.signer ?? 'holder';
  const seed = { holder: KEYS[spec.credential ?? 's1']?.seed, attacker: KEYS.attacker.seed, mixed: KEYS.mixedBase.seed }[signer] ?? KEYS.s1.seed;
  let signature;
  if (signer === 'small-order') signature = concat(IDENTITY, new Uint8Array(32)); // R = identity, S = 0
  else if (signer === 'mixed') signature = signManual(KEYS.mixedBase.seed, message, { publicKey: MIXED });
  else if (signer === 'torsion-r') signature = signManual(seed, message, { torsionR: true });
  else signature = ed25519.sign(message, seed);
  if (spec.nonCanonicalS) signature = concat(signature.slice(0, 32), toLE(numberLE(signature.slice(32)) + L, 32));

  const labelName = spec.label ?? 'aria';
  if (!spec.unsigned) {
    headers.push(['signature-input', `${labelName}=${signatureParams}${spec.extraSignatureInput ?? ''}`]);
    headers.push(['signature', `${labelName}=:${encodeSignature(signature, spec.signatureEncoding)}:${spec.extraSignature ?? ''}`]);
  }

  const request = { method, target, headers, body: body === null ? null : body };
  if (spec.after) spec.after(request);
  return {
    request: { method: request.method, target: request.target, headers: request.headers, ...(request.body === null ? {} : { body: { utf8: request.body } }) },
    requestDigest: digest(message),
    fingerprint: receiptable ? fingerprintOf(d, target, headers, body ?? '') : undefined,
    sender,
    descriptor: d,
    operation: spec.operation ?? OP.X,
  };
}

// Base64 spellings of the same 64 bytes that a lenient decoder accepts and the profile refuses.
function encodeSignature(signature, how) {
  const text = b64(signature);
  if (how === 'unpadded') return text.replace(/=+$/, '');
  if (how === 'noncanonical') {
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const at = text.length - 3; // the last data character, whose four low bits are padding
    return text.slice(0, at) + ALPHABET[ALPHABET.indexOf(text[at]) | 1] + text.slice(at + 1);
  }
  return text;
}

const replaceHeader = (name, value) => (r) => {
  r.headers = r.headers.map(([n, v]) => (n === name ? [n, value] : [n, v]));
};
const dropHeader = (name) => (r) => {
  r.headers = r.headers.filter(([n]) => n !== name);
};

const authenticated = (built) => ({
  result: 'authenticated',
  descriptor: built.descriptor.name,
  class: built.descriptor.class,
  sender: { did: built.sender.did, credential: built.sender.url },
  requestDigest: built.requestDigest,
  ...(built.descriptor.class === 'retrieval'
    ? { retrieves: new URL(built.request.target, ORIGIN).searchParams.get('operation') }
    : { operation: built.operation, fingerprint: built.fingerprint }),
});
const refused = (http, code, extra = {}) => ({ result: 'refused', http, code, ...extra });
const unsigned400 = refused(400, 'aria.request_invalid', { signed: false });
const unsigned401 = (subtype) => refused(401, 'aria.authentication_failed', { subtype, signed: false });

// Each case: id, title, covers, the request spec, and the expected result. `expect`
// may be a function of the built request when the result carries derived values.
const CASES = [
  // Classes, signed operation reference and body rules (proposal §3 point 1; §5.9 #19).
  { id: 'REQ-001', title: 'unsafe-body POST, valid', covers: ['§5.9 #19', 'classes'], spec: { descriptor: 'transfers.create' }, expect: authenticated },
  { id: 'REQ-002', title: 'retry of REQ-001: same operation and content, fresh challenge, window and signature', covers: ['§5.9 #22', 'fresh challenge per request'], spec: { descriptor: 'transfers.create', created: -2, expires: 28 }, expect: authenticated, note: 'Same fingerprint as REQ-001, different request digest.' },
  { id: 'REQ-003', title: 'Content-Type in another case normalises to the declared media type', covers: ['fingerprint media type'], spec: { descriptor: 'transfers.create', contentType: 'Application/JSON' }, expect: authenticated, note: 'Same fingerprint as REQ-001: the signed raw header differs, the operation does not.' },
  { id: 'REQ-004', title: 'body 42 as application/json', covers: ['§5.9 #21'], spec: { descriptor: 'transfers.create', operation: OP.Z, body: '42' }, expect: authenticated },
  { id: 'REQ-005', title: 'body 42 as text/plain on an operation that declares application/json', covers: ['§5.9 #21'], spec: { descriptor: 'transfers.create', operation: OP.Z, body: '42', contentType: 'text/plain' }, expect: unsigned400, note: 'Refused before any claim: it can never receive the JSON operation\'s result.' },
  { id: 'REQ-006', title: 'a media type parameter the descriptor does not declare', covers: ['fingerprint media type'], spec: { descriptor: 'transfers.create', contentType: 'application/json; charset=utf-8' }, expect: unsigned400 },
  { id: 'REQ-007', title: 'unsafe-body without a body', covers: ['classes'], spec: { descriptor: 'transfers.create', body: null }, expect: unsigned400 },
  { id: 'REQ-008', title: 'DELETE without a body, content-digest of empty content covered', covers: ['§5.9 #19'], spec: { descriptor: 'transfers.cancel', operation: OP.W }, expect: authenticated },
  { id: 'REQ-009', title: 'DELETE without content-digest', covers: ['§5.9 #19'], spec: { descriptor: 'transfers.cancel', operation: OP.W, contentDigest: null, covered: ['@method', '@target-uri', 'aria-operation', 'aria-credential', 'aria-audience'] }, expect: unsigned401('digest') },
  { id: 'REQ-010', title: 'DELETE with a body', covers: ['classes'], spec: { descriptor: 'transfers.cancel', operation: OP.W, body: '{}' }, expect: unsigned400 },
  { id: 'REQ-011', title: 'safe-receiptable GET with its declared query', covers: ['§5.9 #19', 'classes'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR' }, expect: authenticated },
  { id: 'REQ-012', title: 'query changed after signing on a GET with a receipt', covers: ['§5.9 #19'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR', after: (r) => { r.target = '/v1/accounts/acc-1/balance?currency=USD'; } }, expect: unsigned401('signature') },
  { id: 'REQ-013', title: 'GET with a body', covers: ['§5.9 #19'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR', after: (r) => { r.body = '{}'; } }, expect: unsigned400 },
  { id: 'REQ-014', title: 'HEAD', covers: ['§5.9 #19'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR', method: 'HEAD' }, expect: unsigned400 },
  { id: 'REQ-015', title: 'ARIA-Operation missing on a receiptable class', covers: ['§5.9 #19', 'AP-R3'], spec: { descriptor: 'transfers.create', operation: null, covered: ['@method', '@target-uri', 'content-type', 'content-digest', 'aria-credential', 'aria-audience'] }, expect: unsigned400 },
  { id: 'REQ-016', title: 'ARIA-Operation present but not covered', covers: ['§5.9 #19', 'AP-R3'], spec: { descriptor: 'transfers.create', covered: ['@method', '@target-uri', 'content-type', 'content-digest', 'aria-credential', 'aria-audience'] }, expect: unsigned401('unsigned_operation') },
  { id: 'REQ-017', title: 'ARIA-Operation changed after signing', covers: ['§5.9 #19', 'AP-R3'], spec: { descriptor: 'transfers.create', after: replaceHeader('aria-operation', sfString(OP.Y)) }, expect: unsigned401('signature') },
  { id: 'REQ-018', title: 'ARIA-Operation repeated', covers: ['AP-R3'], spec: { descriptor: 'transfers.create', after: (r) => { r.headers.push(['aria-operation', sfString(OP.Y)]); } }, expect: unsigned400 },
  { id: 'REQ-019', title: 'ARIA-Operation not a UUID', covers: ['AP-R3'], spec: { descriptor: 'transfers.create', operation: 'transfer-1' }, expect: unsigned400 },
  { id: 'REQ-020', title: 'an unsigned Idempotency-Key does not count', covers: ['AP-R3'], spec: { descriptor: 'transfers.create', headers: [['idempotency-key', 'client-key-2']] }, expect: authenticated, note: 'The operation is the covered ARIA-Operation; changing the unsigned header changes nothing.' },
  { id: 'REQ-021', title: 'a query parameter the descriptor does not declare', covers: ['classes'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR&limit=5' }, expect: unsigned400 },
  { id: 'REQ-022', title: 'a declared query parameter repeated', covers: ['classes'], spec: { descriptor: 'balance.read', operation: OP.Y, query: 'currency=EUR&currency=USD' }, expect: unsigned400 },
  { id: 'REQ-023', title: 'a semantic header (if-match) covered and in the fingerprint', covers: ['fingerprint semantic headers'], spec: { descriptor: 'transfers.update', operation: OP.Y, body: '{"amount":"12.00"}', headers: [['if-match', '"v1"']] }, expect: authenticated },
  { id: 'REQ-024', title: 'a semantic header present but not covered', covers: ['fingerprint semantic headers'], spec: { descriptor: 'transfers.update', operation: OP.Y, body: '{"amount":"12.00"}', headers: [['if-match', '"v1"']], covered: profile.classes['unsafe-body'].components }, expect: unsigned401('signature') },
  { id: 'REQ-025', title: 'a semantic header changed after signing', covers: ['fingerprint semantic headers'], spec: { descriptor: 'transfers.update', operation: OP.Y, body: '{"amount":"12.00"}', headers: [['if-match', '"v1"']], after: replaceHeader('if-match', '"v2"') }, expect: unsigned401('signature') },

  // Retrieval and receiver challenges (D3: a fresh challenge for every request).
  { id: 'REQ-030', title: 'retrieval of operation X', covers: ['§5.9 #20'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}` }, expect: authenticated },
  { id: 'REQ-031', title: 'retrieval whose operation query changed after signing', covers: ['§5.9 #20'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}`, after: (r) => { r.target = `/v1/operations?operation=${OP.Y}`; } }, expect: unsigned401('signature') },
  { id: 'REQ-032', title: 'retrieval reusing the challenge an earlier lookup consumed', covers: ['fresh challenge per request'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}`, challenge: 'consumed by a lookup' }, context: { consumed: ['consumed by a lookup'] }, expect: unsigned401('challenge') },
  { id: 'REQ-033', title: 'mutation reusing the challenge a lookup consumed', covers: ['fresh challenge per request', 'S0-R2'], spec: { descriptor: 'transfers.create', challenge: 'consumed by a lookup' }, context: { consumed: ['consumed by a lookup'] }, expect: unsigned401('challenge') },
  { id: 'REQ-034', title: 'retrieval carrying ARIA-Operation', covers: ['§5.9 #20'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}`, headers: [['aria-operation', sfString(OP.X)]] }, expect: unsigned400 },
  { id: 'REQ-035', title: 'retrieval without the operation parameter', covers: ['§5.9 #20'], spec: { descriptor: 'operations.lookup' }, expect: unsigned400 },
  { id: 'REQ-036', title: 'retrieval naming something other than a UUID', covers: ['§5.9 #20'], spec: { descriptor: 'operations.lookup', query: 'operation=latest' }, expect: unsigned400 },
  { id: 'REQ-037', title: 'retrieval with the renewed credential of the same DID', covers: ['D4 provisional', 'R2a'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}`, credential: 's2' }, expect: authenticated, note: 'Authenticates as the same DID with its current credential; admission then decides with current status.' },
  { id: 'REQ-038', title: 'a challenge this receiver never issued', covers: ['challenge'], spec: { descriptor: 'transfers.create', challenge: 'never issued' }, expect: unsigned401('challenge') },
  { id: 'REQ-039', title: 'an expired challenge', covers: ['challenge'], spec: { descriptor: 'transfers.create', challenge: 'expired' }, expect: unsigned401('challenge') },

  // Signature, window and digest.
  { id: 'REQ-040', title: 'unsigned request', covers: ['authentication'], spec: { descriptor: 'transfers.create', unsigned: true }, expect: unsigned401('signature') },
  { id: 'REQ-041', title: 'window longer than 60 s', covers: ['window'], spec: { descriptor: 'transfers.create', created: -5, expires: 56 }, expect: unsigned401('window') },
  { id: 'REQ-042', title: 'created beyond the 5 s skew', covers: ['window'], spec: { descriptor: 'transfers.create', created: 6, expires: 30 }, expect: unsigned401('window') },
  { id: 'REQ-043', title: 'created within the 5 s skew', covers: ['window'], spec: { descriptor: 'transfers.create', created: 4, expires: 30 }, expect: authenticated },
  { id: 'REQ-044', title: 'expired beyond the 5 s skew', covers: ['window'], spec: { descriptor: 'transfers.create', created: -40, expires: -6 }, expect: unsigned401('window') },
  { id: 'REQ-045', title: 'body changed after signing', covers: ['digest'], spec: { descriptor: 'transfers.create', after: (r) => { r.body = '{"amount":"9999.00","currency":"EUR","to":"acc-9"}'; } }, expect: unsigned401('digest') },
  { id: 'REQ-046', title: 'content-digest with only sha-512', covers: ['digest'], spec: { descriptor: 'transfers.create', contentDigest: `sha-512=:${b64(sha512(utf8(TRANSFER)))}:` }, expect: unsigned401('digest') },
  { id: 'REQ-047', title: 'another tag', covers: ['signature parameters'], spec: { descriptor: 'transfers.create', params: { tag: sfString('aria-ap/0') } }, expect: unsigned401('signature') },
  { id: 'REQ-048', title: 'alg missing', covers: ['signature parameters'], spec: { descriptor: 'transfers.create', params: { alg: null } }, expect: unsigned401('signature') },
  { id: 'REQ-049', title: 'a component outside the class list covered', covers: ['components'], spec: { descriptor: 'transfers.create', headers: [['date', 'Sun, 01 Nov 2026 12:00:00 GMT']], covered: [...profile.classes['unsafe-body'].components, 'date'] }, expect: unsigned401('signature') },
  { id: 'REQ-050', title: 'a component covered twice', covers: ['components'], spec: { descriptor: 'transfers.create', covered: [...profile.classes['unsafe-body'].components, 'aria-audience'] }, expect: unsigned401('signature') },
  { id: 'REQ-051', title: 'a second signature beside aria', covers: ['signature label'], spec: { descriptor: 'transfers.create', extraSignatureInput: ', other=("@method");created=1793534395', extraSignature: ', other=:AAAA:' }, expect: unsigned401('signature') },
  { id: 'REQ-052', title: 'signed for another origin', covers: ['@target-uri from the configured origin'], spec: { descriptor: 'transfers.create', signedOrigin: 'https://other.example.test' }, expect: unsigned401('signature') },

  // Strict possession (Codex S1-F3 follow-up; proposal §3 point 8).
  { id: 'REQ-060', title: 'keyid other than the credential\'s holder key', covers: ['possession'], spec: { descriptor: 'transfers.create', keyid: `${SENDER_DID}#holder-key-2` }, expect: unsigned401('credential') },
  { id: 'REQ-061', title: 'credential digest that does not match the named document', covers: ['possession'], spec: { descriptor: 'transfers.create', credentialDigest: digest(utf8('another document')) }, expect: unsigned401('credential') },
  { id: 'REQ-062', title: 'a credential the receiver cannot resolve', covers: ['possession'], spec: { descriptor: 'transfers.create', credentialUrl: `${REGISTRY}${uuid('unknown credential')}` }, expect: unsigned401('credential') },
  { id: 'REQ-063', title: 'a copied credential presented without its key', covers: ['possession'], spec: { descriptor: 'transfers.create', signer: 'attacker' }, expect: unsigned401('signature') },
  { id: 'REQ-064', title: 'non-canonical S (S + L)', covers: ['strict Ed25519'], spec: { descriptor: 'transfers.create', nonCanonicalS: true }, expect: unsigned401('signature') },
  { id: 'REQ-065', title: 'R with an order-8 component, made by the key holder', covers: ['strict Ed25519'], spec: { descriptor: 'transfers.create', signer: 'torsion-r' }, expect: unsigned401('signature'), lenient: 'cofactored', note: 'A cofactored verifier accepts it; the profile rule (R canonical, torsion free, not small order) does not, so every implementation agrees.' },
  { id: 'REQ-066', title: 'identity-point holder key with R = identity, S = 0', covers: ['strict Ed25519', 'S1-F3'], spec: { descriptor: 'transfers.create', credential: 'weak', signer: 'small-order' }, expect: unsigned401('credential'), lenient: 'zip215', note: 'Valid for every message under ZIP-215; the key is refused before any signature check.' },
  { id: 'REQ-067', title: 'mixed-torsion holder key, signed by its holder', covers: ['strict Ed25519', 'S1-F3'], spec: { descriptor: 'transfers.create', credential: 'mixed', signer: 'mixed' }, expect: unsigned401('credential'), lenient: 'cofactored', note: 'Not small order, so a strict-mode cofactored verifier accepts it; the key is not torsion free.' },
  { id: 'REQ-068', title: 'non-canonical encoding of the identity as holder key', covers: ['strict Ed25519', 'S1-F3'], spec: { descriptor: 'transfers.create', credential: 'noncanonical', signer: 'small-order' }, expect: unsigned401('credential'), lenient: 'zip215' },

  // Audience: checked after authentication (proposal §5.4).
  { id: 'REQ-070', title: 'signed for another receiver DID', covers: ['§5.4 audience'], spec: { descriptor: 'transfers.create', audience: 'did:aria:other.example.test:service' }, expect: refused(403, 'aria.audience_mismatch', { signed: true, applies: 'attempt' }) },
  { id: 'REQ-071', title: 'retrieval signed for another receiver DID', covers: ['§5.4 audience', '§5.9 #20'], spec: { descriptor: 'operations.lookup', query: `operation=${OP.X}`, audience: 'did:aria:other.example.test:service' }, expect: refused(403, 'aria.audience_mismatch', { signed: false }), note: 'A retrieval produces no receipt, so its refusal is a problem document.' },

  // Exact parsing choices: refused, never normalised or combined.
  { id: 'REQ-053', title: 'a target the URL parser would normalise', covers: ['parsing'], spec: { descriptor: 'transfers.create', target: '/v1/./transfers' }, expect: unsigned400, note: 'The target is taken exactly: one that is not its own serialization is refused, not normalised.' },
  { id: 'REQ-054', title: 'a covered header repeated, signed over its combined value', covers: ['parsing'], spec: { descriptor: 'transfers.create', headers: [['aria-audience', sfString(RECEIVER_DID)]] }, expect: unsigned401('signature'), note: 'A repeated covered field is refused, though the signature matches its RFC 9421 combination.' },
  { id: 'REQ-055', title: 'the signature with non-zero padding bits in its base64', covers: ['parsing', 'canonical byte sequences'], spec: { descriptor: 'transfers.create', signatureEncoding: 'noncanonical' }, expect: unsigned401('signature'), note: 'The same 64 bytes to a lenient decoder; only the canonical spelling is accepted.' },
  { id: 'REQ-056', title: 'the signature base64 without its padding', covers: ['parsing', 'canonical byte sequences'], spec: { descriptor: 'transfers.create', signatureEncoding: 'unpadded' }, expect: unsigned401('signature') },

  // Challenge expiry is exclusive.
  { id: 'REQ-072', title: 'a challenge expiring exactly now', covers: ['challenge expiry'], spec: { descriptor: 'transfers.create', challenge: 'at-expiry' }, expect: unsigned401('challenge'), note: 'A challenge is live strictly before its expiry.' },

  // Freshness after asynchronous steps: the window is judged again after resolving the credential and after consuming the challenge.
  { id: 'REQ-090', title: 'credential resolution ends at the last instant of the window', covers: ['freshness after asynchronous steps'], spec: { descriptor: 'transfers.create' }, timeline: { resolvedAfter: 30 }, expect: authenticated, note: 'expires is now + 25 s; with the 5 s skew the window ends at now + 30 s.' },
  { id: 'REQ-091', title: 'credential resolution ends after the window', covers: ['freshness after asynchronous steps'], spec: { descriptor: 'transfers.create' }, timeline: { resolvedAfter: 31 }, expect: unsigned401('window') },
  { id: 'REQ-092', title: 'the challenge is consumed after the window ended', covers: ['freshness after asynchronous steps'], spec: { descriptor: 'transfers.create' }, timeline: { consumedAfter: 31 }, expect: unsigned401('window'), note: 'The challenge stays consumed.' },
];

const requestVectors = CASES.map((c) => {
  const built = build({ ...c.spec, id: c.id });
  const expect = typeof c.expect === 'function' ? c.expect(built) : c.expect;
  return {
    id: c.id,
    title: c.title,
    covers: c.covers,
    ...(c.note ? { note: c.note } : {}),
    ...(c.context ? { context: Object.fromEntries(Object.entries(c.context).map(([k, labels]) => [k, labels.map(challenge)])) } : {}),
    ...(c.lenient ? { lenient: c.lenient } : {}),
    ...(c.timeline ? { timeline: c.timeline } : {}),
    request: built.request,
    expect,
  };
});
const byId = Object.fromEntries(requestVectors.map((v) => [v.id, v]));

const requestContext = {
  now: iso(NOW),
  skewSeconds: profile.transport.skewSeconds,
  maxWindowSeconds: profile.transport.maxWindowSeconds,
  receiver: { origin: ORIGIN, did: RECEIVER_DID },
  descriptors: DESCRIPTORS,
  credentials: Object.values(SENDERS),
  challenges: [...challengesUsed]
    .filter((label) => label !== 'never issued')
    .map((label) => ({ value: challenge(label), expires: iso(label === 'expired' ? NOW - 1 : label === 'at-expiry' ? NOW : NOW + 50) })),
};

// ---------------------------------------------------------------- fingerprints

const fingerprintInputs = {
  'json-42': { class: 'unsafe-body', method: 'POST', path: '/v1/transfers', query: {}, semanticHeaders: {}, mediaType: 'application/json', contentDigest: digest(utf8('42')) },
  'text-42': { class: 'unsafe-body', method: 'POST', path: '/v1/transfers', query: {}, semanticHeaders: {}, mediaType: 'text/plain', contentDigest: digest(utf8('42')) },
  'json-string-42': { class: 'unsafe-body', method: 'POST', path: '/v1/transfers', query: {}, semanticHeaders: {}, mediaType: 'application/json', contentDigest: digest(utf8('"42"')) },
  'if-match-v1': { class: 'unsafe-body', method: 'PATCH', path: '/v1/transfers/t-1001', query: {}, semanticHeaders: { 'if-match': '"v1"' }, mediaType: 'application/json', contentDigest: digest(utf8('{"amount":"12.00"}')) },
  'if-match-v2': { class: 'unsafe-body', method: 'PATCH', path: '/v1/transfers/t-1001', query: {}, semanticHeaders: { 'if-match': '"v2"' }, mediaType: 'application/json', contentDigest: digest(utf8('{"amount":"12.00"}')) },
  'delete-empty': { class: 'unsafe-empty', method: 'DELETE', path: '/v1/transfers/t-1001', query: {}, semanticHeaders: {}, contentDigest: digest(new Uint8Array()) },
  'post-empty': { class: 'unsafe-empty', method: 'POST', path: '/v1/transfers/t-1001', query: {}, semanticHeaders: {}, contentDigest: digest(new Uint8Array()) },
  'get-eur': { class: 'safe-receiptable', method: 'GET', path: '/v1/accounts/acc-1/balance', query: { currency: 'EUR' }, semanticHeaders: {} },
  'get-usd': { class: 'safe-receiptable', method: 'GET', path: '/v1/accounts/acc-1/balance', query: { currency: 'USD' }, semanticHeaders: {} },
};
const fingerprintVectors = {
  algorithm: profile.fingerprint.algorithm,
  cases: Object.entries(fingerprintInputs).map(([id, input]) => ({ id, input, fingerprint: digest(utf8(canonical(input))) })),
  relations: [
    { a: 'json-42', b: 'text-42', same: false, why: 'Same bytes, other media type: a conflict, never the first result (§5.9 #21).' },
    { a: 'json-42', b: 'json-string-42', same: false, why: 'A number and a string are different content.' },
    { a: 'if-match-v1', b: 'if-match-v2', same: false, why: 'A semantic header changes the operation.' },
    { a: 'delete-empty', b: 'post-empty', same: false, why: 'The method is part of the operation.' },
    { a: 'get-eur', b: 'get-usd', same: false, why: 'The declared query is part of the operation.' },
  ],
  requestRelations: [
    { a: 'REQ-001', b: 'REQ-002', same: true, why: 'A retry with a fresh challenge and signature is the same operation (§5.9 #22).' },
    { a: 'REQ-001', b: 'REQ-003', same: true, why: 'The media type is normalised before it enters the fingerprint.' },
    { a: 'REQ-001', b: 'REQ-020', same: true, why: 'An unsigned Idempotency-Key is not part of the operation.' },
    { a: 'REQ-001', b: 'REQ-004', same: false, why: 'Other content.' },
  ],
  requestCases: [
    { request: 'REQ-004', case: 'json-42' },
    { request: 'REQ-008', case: 'delete-empty' },
    { request: 'REQ-011', case: 'get-eur' },
    { request: 'REQ-023', case: 'if-match-v1' },
  ],
};
for (const r of fingerprintVectors.requestRelations) {
  const same = byId[r.a].expect.fingerprint === byId[r.b].expect.fingerprint;
  if (same !== r.same) throw new Error(`generator: request relation ${r.a}/${r.b} does not hold`);
}
for (const r of fingerprintVectors.requestCases) {
  const expected = fingerprintVectors.cases.find((c) => c.id === r.case).fingerprint;
  if (byId[r.request].expect.fingerprint !== expected) throw new Error(`generator: ${r.request} is not case ${r.case}`);
}

// ---------------------------------------------------------------- receipts

const attemptOf = (id, receiver = RECEIVERS.r1) => {
  const v = byId[id].expect;
  return {
    request: id,
    requestDigest: v.requestDigest,
    operation: v.operation,
    sender: v.sender,
    receiver: { did: receiver.did, credential: receiver.url },
  };
};
const ATTEMPT = {
  a1: attemptOf('REQ-001'),
  a2: attemptOf('REQ-002'),
  y: attemptOf('REQ-011'),
};
const RESULT = digest(utf8('{"state":"booked","transfer":"t-1001"}'));

function receipt(spec) {
  const receiver = spec.receiverView ?? RECEIVERS[spec.receiver ?? 'r1'];
  const attempt = spec.attempt ?? ATTEMPT.a1;
  const body = {
    type: spec.type ?? 'aria-ap-receipt/1',
    id: `urn:uuid:${uuid(`receipt ${spec.label}`)}`,
    request: { id: attempt.operation, sender: spec.sender ?? attempt.sender, digest: attempt.requestDigest },
    receiver: { did: receiver.did, credential: spec.receiverUrl ?? receiver.url },
    issuedAt: spec.issuedAt ?? '2026-11-01T12:00:01Z',
    outcome: spec.outcome,
    ...spec.extra,
  };
  const proof = { alg: 'ed25519', keyid: spec.keyid ?? receiver.holderKey.id };
  const signedBytes = utf8(canonical(spec.withoutProofMetadata ? body : { ...body, proof }));
  const seed = KEYS[spec.signer ?? spec.receiver ?? 'r1'].seed;
  const full = { ...body, proof: { ...proof, value: b64url(ed25519.sign(signedBytes, seed)) } };
  let text = JSON.stringify(full);
  if (spec.alter) {
    const parsed = JSON.parse(text);
    spec.alter(parsed);
    text = JSON.stringify(parsed);
  }
  if (spec.text) text = spec.text(text);
  return text;
}

const completed = { state: 'completed', applies: 'operation', status: 201, code: 'aria.completed', result: { digest: RESULT } };
const accepted = { state: 'accepted', applies: 'operation', status: 202, code: 'aria.accepted' };
const refusedAttempt = { state: 'rejected', applies: 'attempt', status: 403, code: 'aria.credential_revoked' };
const refusedOperation = { state: 'rejected', applies: 'operation', status: 422, code: 'bank.insufficient_funds' };

const client = (attempts, receiver = 'r1') => ({ receiver: RECEIVERS[receiver], attempts: attempts.map((a) => ATTEMPT[a]) });
const valid = (outcome, attempt, extra = {}) => ({ result: 'valid', state: outcome.state, applies: outcome.applies, status: outcome.status, code: outcome.code, attempt: attempt.request, ...extra });
const invalid = (reason) => ({ result: 'invalid', reason });

const RECEIPTS = [
  { id: 'RCP-01', title: 'completed, decision mode', covers: ['§5.9 #1'], receipt: { label: 'completed', outcome: completed }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: valid(completed, ATTEMPT.a1) },
  { id: 'RCP-02', title: 'fresh 403 refusal of an attempt', covers: ['§5.9 #2', 'O3: signed after authentication'], receipt: { label: 'refused attempt', outcome: refusedAttempt, attempt: ATTEMPT.a2 }, mode: 'decision', transportStatus: 403, client: client(['a1', 'a2']), expect: valid(refusedAttempt, ATTEMPT.a2), note: 'Kept as evidence of that attempt; the operation stays as it was.' },
  { id: 'RCP-03', title: 'operation rejected with 422, retrieved with 200', covers: ['§5.9 #3', '§5.5'], receipt: { label: 'refused operation', outcome: refusedOperation }, mode: 'retrieval', transportStatus: 200, client: client(['a1']), expect: valid(refusedOperation, ATTEMPT.a1) },
  { id: 'RCP-04', title: 'transport 201 carrying a rejected receipt, decision mode', covers: ['§5.9 #4'], receipt: { label: 'refused operation', outcome: refusedOperation }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('status_mismatch') },
  { id: 'RCP-05a', title: 'outcome.code altered', covers: ['§5.9 #5'], receipt: { label: 'completed', outcome: completed, alter: (r) => { r.outcome.code = 'aria.accepted'; r.outcome.state = 'accepted'; r.outcome.status = 202; } }, mode: 'decision', transportStatus: 202, client: client(['a1']), expect: invalid('signature_invalid') },
  { id: 'RCP-05b', title: 'outcome.status altered (201 to 200)', covers: ['§5.9 #5'], receipt: { label: 'completed', outcome: completed, alter: (r) => { r.outcome.status = 200; } }, mode: 'decision', transportStatus: 200, client: client(['a1']), expect: invalid('signature_invalid') },
  { id: 'RCP-05c', title: 'signed without its proof metadata, as aria-receipt/0.1 did', covers: ['§5.9 #5', 'proof.alg and proof.keyid are signed'], receipt: { label: 'completed', outcome: completed, withoutProofMetadata: true }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('signature_invalid') },
  { id: 'RCP-05d', title: 'issuedAt altered', covers: ['§5.9 #5'], receipt: { label: 'completed', outcome: completed, alter: (r) => { r.issuedAt = '2026-11-01T11:00:00Z'; } }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('signature_invalid') },
  { id: 'RCP-06a', title: 'names another credential of the same receiver DID', covers: ['§5.9 #6'], receipt: { label: 'completed by r2', receiver: 'r2', outcome: completed }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('receiver_mismatch') },
  { id: 'RCP-06b', title: 'names the expected credential, signed with another credential\'s key', covers: ['§5.9 #6'], receipt: { label: 'completed', outcome: completed, signer: 'r2' }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('signature_invalid') },
  { id: 'RCP-06c', title: 'from another receiver DID', covers: ['§5.9 #6'], receipt: { label: 'completed by other', receiver: 'other', outcome: completed }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('receiver_mismatch') },
  { id: 'RCP-06d', title: 'signed with the expected key and keyid, naming another credential document', covers: ['§5.9 #6', 'exact receiver instance'], receipt: { label: 'completed misnamed', outcome: completed, receiverUrl: `${REGISTRY}${uuid('credential receiver 1 (other copy)')}` }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('receiver_mismatch'), note: 'Only the named instance differs; a historical verifier would otherwise fetch the wrong document.' },
  { id: 'RCP-07a', title: 'for a request this client never sent', covers: ['§5.9 #7'], receipt: { label: 'completed y', outcome: completed, attempt: ATTEMPT.y }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('binding') },
  { id: 'RCP-07b', title: 'binds a kept attempt but names another sender', covers: ['§5.9 #7'], receipt: { label: 'completed other sender', outcome: completed, sender: { did: 'did:aria:customer.example.test:other-agent', credential: SENDERS.s1.url } }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('binding') },
  { id: 'RCP-07c', title: 'binds a kept attempt but names another operation', covers: ['§5.9 #7'], receipt: { label: 'completed other operation', outcome: completed, attempt: { ...ATTEMPT.a1, operation: OP.W } }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('binding') },
  { id: 'RCP-08a', title: 'retry answered with the original receipt, original attempt kept', covers: ['§5.9 #8', '§5.9 #22'], receipt: { label: 'completed', outcome: completed }, mode: 'decision', transportStatus: 201, client: client(['a1', 'a2']), expect: valid(completed, ATTEMPT.a1) },
  { id: 'RCP-08b', title: 'retry answered with the original receipt, checked only against the retry', covers: ['§5.9 #8'], receipt: { label: 'completed', outcome: completed }, mode: 'decision', transportStatus: 201, client: client(['a2']), expect: invalid('binding') },
  { id: 'RCP-08c', title: 'no attempt kept at all', covers: ['§5.6 client rule 2'], receipt: { label: 'completed', outcome: completed }, mode: 'decision', transportStatus: 201, client: client([]), expect: invalid('binding_unverifiable') },
  { id: 'RCP-09', title: 'accepted without completion', covers: ['§5.9 #9'], receipt: { label: 'accepted', outcome: accepted }, mode: 'decision', transportStatus: 202, client: client(['a1']), expect: valid(accepted, ATTEMPT.a1), note: 'An operation state of accepted, never shown as completed.' },
  { id: 'RCP-10a', title: 'duplicate key whose last value is the signed one', covers: ['§5.9 #10'], receipt: { label: 'completed', outcome: completed, text: (t) => t.replace('"code":"aria.completed"', '"code":"bank.reversed","code":"aria.completed"') }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('malformed'), note: 'A parser keeping the last value would verify the signature.' },
  { id: 'RCP-10b', title: 'unknown member, signed', covers: ['§5.9 #10'], receipt: { label: 'completed', outcome: completed, extra: { note: 'signed but not in the profile' } }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('malformed') },
  { id: 'RCP-10c', title: 'number written with a fraction', covers: ['§5.9 #10'], receipt: { label: 'completed', outcome: completed, text: (t) => t.replace('"status":201', '"status":201.0') }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('malformed'), note: 'JSON.parse yields 201 and the signature would verify.' },
  { id: 'RCP-10d', title: 'larger than 4 KiB, signed', covers: ['§5.9 #10'], receipt: { label: 'large', outcome: { ...refusedOperation, code: `bank.${'x'.repeat(4096)}` } }, mode: 'retrieval', transportStatus: 200, client: client(['a1']), expect: invalid('malformed') },
  { id: 'RCP-11a', title: 'after the receiver renewed: verified against the exact instance', covers: ['§5.9 #11'], receipt: { label: 'completed', outcome: completed }, mode: 'retrieval', transportStatus: 200, client: client(['a1'], 'r1'), expect: valid(completed, ATTEMPT.a1) },
  { id: 'RCP-11b', title: 'after the receiver renewed: checked against the DID\'s current document', covers: ['§5.9 #11'], receipt: { label: 'completed', outcome: completed }, mode: 'retrieval', transportStatus: 200, client: client(['a1'], 'r2'), expect: invalid('receiver_mismatch') },
  { id: 'RCP-13', title: 'an attempt refusal presented as a retrieval result', covers: ['§5.5'], receipt: { label: 'refused attempt', outcome: refusedAttempt, attempt: ATTEMPT.a2 }, mode: 'retrieval', transportStatus: 200, client: client(['a1', 'a2']), expect: invalid('not_operation') },
  { id: 'RCP-14', title: 'another receipt type', covers: ['type'], receipt: { label: 'old type', outcome: completed, type: 'aria-receipt/0.1' }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('unsupported_type') },
  { id: 'RCP-15a', title: 'completed that applies to an attempt', covers: ['§5.2 outcome.applies'], receipt: { label: 'completed attempt', outcome: { ...completed, applies: 'attempt' } }, mode: 'decision', transportStatus: 201, client: client(['a1']), expect: invalid('malformed') },
  { id: 'RCP-15b', title: 'rejected operation with a protocol code', covers: ['§5.4'], receipt: { label: 'rejected aria code', outcome: { ...refusedOperation, code: 'aria.scope_missing' } }, mode: 'decision', transportStatus: 422, client: client(['a1']), expect: invalid('malformed') },
  { id: 'RCP-15c', title: 'rejected attempt with status 422', covers: ['§5.4'], receipt: { label: 'rejected attempt 422', outcome: { ...refusedAttempt, status: 422 } }, mode: 'decision', transportStatus: 422, client: client(['a1']), expect: invalid('malformed') },
];

const receiptVectors = RECEIPTS.map((c) => ({
  id: c.id,
  title: c.title,
  covers: c.covers,
  ...(c.note ? { note: c.note } : {}),
  mode: c.mode,
  ...(c.transportStatus ? { transportStatus: c.transportStatus } : {}),
  client: c.client,
  receipt: receipt(c.receipt),
  expect: c.expect,
}));

// ---------------------------------------------------------------- receiver identity

// The receiver's identity statement (`aria-ap-identity/1`) answering the client's nonce,
// with the credential document it names. Documents are stand-ins committed to by each
// view's digest; a view also says when it is valid and its status at NOW.
const IDENTITY_NONCE = b64url(sha256(utf8('aria-ap-1 identity nonce')).slice(0, 18));
const REVOKED_KEY = key('revoked receiver holder key');
const IDENTITY_VIEWS = {
  r1: { ...RECEIVERS.r1, status: 'good', signer: KEYS.r1 },
  r2: { ...RECEIVERS.r2, status: 'good', signer: KEYS.r2 },
  other: { ...RECEIVERS.other, status: 'good', signer: KEYS.other },
  revoked: {
    ...credential('revoked receiver', RECEIVER_DID, 3, REVOKED_KEY.publicKey),
    validFrom: '2026-10-01T00:00:00Z',
    validUntil: '2027-10-01T00:00:00Z',
    status: 'revoked',
    signer: REVOKED_KEY,
  },
};
const documentOf = (v) => ({ id: v.url, did: v.did, holderKey: v.holderKey });

// spec: by (the view that signs and is presented), fields (statement members, set before
// signing), omit (members removed before signing), proof (alg/keyid overrides, signed),
// signer (another key), document (another presented document), value (how proof.value
// is spelled after signing).
function identityResponse(id, spec = {}) {
  const view = IDENTITY_VIEWS[spec.by ?? 'r1'];
  const s = {
    type: 'aria-ap-identity/1',
    subject: view.did,
    credential: view.url,
    origin: ORIGIN,
    audience: SENDER_DID,
    nonce: IDENTITY_NONCE,
    challenge: challenge(`identity ${id}`),
    created: iso(NOW),
    ...spec.fields,
  };
  for (const k of spec.omit ?? []) delete s[k];
  const proof = { alg: 'ed25519', keyid: view.holderKey.id, ...spec.proof };
  const signature = ed25519.sign(utf8(canonical({ ...s, proof })), (spec.signer ?? view.signer).seed);
  let value = b64url(signature);
  if (spec.value === 'flipped') {
    const flipped = Uint8Array.from(signature);
    flipped[40] ^= 0x01;
    value = b64url(flipped);
  } else if (spec.value === 'padded') value = `${value}==`;
  else if (spec.value === 'noncanonical') value = value.slice(0, -1) + B64URL[B64URL.indexOf(value.at(-1)) | 1];
  return { credential: spec.document ?? documentOf(view), statement: { ...s, proof: { ...proof, value } } };
}
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const identityOk = (id, by = 'r1') => ({ result: 'authenticated', credential: IDENTITY_VIEWS[by].url, keyid: IDENTITY_VIEWS[by].holderKey.id, challenge: challenge(`identity ${id}`) });
const identityRefused = (reason) => ({ result: 'refused', reason });

const IDENTITY_CASES = [
  { id: 'IDN-001', title: 'a current statement by the pinned receiver', covers: ['identity'], expect: identityOk },
  { id: 'IDN-002', title: 'another receiver, with its own valid credential, answers', covers: ['pin'], spec: { by: 'other' }, expect: identityRefused('unexpected_receiver') },
  { id: 'IDN-003', title: 'the statement names another origin', covers: ['pin'], spec: { fields: { origin: 'https://payments.example.test' } }, expect: identityRefused('origin') },
  { id: 'IDN-004', title: 'a client pin outside the origin rule matches no statement', covers: ['pin', 'origin'], pin: { origin: 'https://BANK.example.test' }, expect: identityRefused('origin') },
  { id: 'IDN-005', title: 'the statement is for another client', covers: ['audience'], spec: { fields: { audience: 'did:aria:customer.example.test:other-agent' } }, expect: identityRefused('audience') },
  { id: 'IDN-006', title: 'the statement answers another nonce', covers: ['nonce'], spec: { fields: { nonce: b64url(sha256(utf8('aria-ap-1 another nonce')).slice(0, 18)) } }, expect: identityRefused('nonce') },
  { id: 'IDN-007', title: 'created exactly 60 s before now', covers: ['freshness', 'boundary'], spec: { fields: { created: iso(NOW - 60) } }, expect: identityOk },
  { id: 'IDN-008', title: 'created 61 s before now', covers: ['freshness', 'boundary'], spec: { fields: { created: iso(NOW - 61) } }, expect: identityRefused('stale') },
  { id: 'IDN-009', title: 'created 5 s ahead, within the skew', covers: ['freshness', 'boundary'], spec: { fields: { created: iso(NOW + 5) } }, expect: identityOk },
  { id: 'IDN-010', title: 'created 6 s ahead, beyond the skew', covers: ['freshness', 'boundary'], spec: { fields: { created: iso(NOW + 6) } }, expect: identityRefused('stale') },
  { id: 'IDN-011', title: 'one signature bit flipped', covers: ['signature'], spec: { value: 'flipped' }, expect: identityRefused('signature') },
  { id: 'IDN-012', title: 'keyid names another key of the DID, signed by the right key', covers: ['signature', 'keyid'], spec: { proof: { keyid: `${RECEIVER_DID}#holder-key-2` } }, expect: identityRefused('signature') },
  { id: 'IDN-013', title: 'signed by a key that is not the credential\'s holder key', covers: ['signature'], spec: { signer: KEYS.attacker }, expect: identityRefused('signature') },
  { id: 'IDN-014', title: 'another proof algorithm', covers: ['signature'], spec: { proof: { alg: 'es256' } }, expect: identityRefused('signature') },
  { id: 'IDN-015', title: 'proof value with base64 padding', covers: ['signature', 'encoding'], spec: { value: 'padded' }, expect: identityRefused('signature') },
  { id: 'IDN-016', title: 'proof value with non-zero trailing bits (decodes to the same bytes)', covers: ['signature', 'encoding'], spec: { value: 'noncanonical' }, expect: identityRefused('signature') },
  { id: 'IDN-017', title: 'the statement names another credential than the one presented', covers: ['credential'], spec: { fields: { credential: RECEIVERS.r2.url } }, expect: identityRefused('credential') },
  { id: 'IDN-018', title: 'the statement\'s subject is not the credential\'s DID', covers: ['credential'], spec: { fields: { subject: 'did:aria:bank.example.test:other-service' } }, expect: identityRefused('credential') },
  { id: 'IDN-019', title: 'the presented credential is not valid yet', covers: ['credential'], spec: { by: 'r2' }, expect: identityRefused('credential') },
  { id: 'IDN-020', title: 'a presented document the verifier does not accept (holder key substituted)', covers: ['credential'], spec: { signer: KEYS.attacker, document: { ...documentOf(IDENTITY_VIEWS.r1), holderKey: { ...IDENTITY_VIEWS.r1.holderKey, publicKeyMultibase: `z${base58(KEYS.attacker.publicKey)}` } } }, expect: identityRefused('credential') },
  { id: 'IDN-021', title: 'an extra member in the statement, signed', covers: ['malformed'], spec: { fields: { note: 'x' } }, expect: identityRefused('malformed') },
  { id: 'IDN-022', title: 'no challenge, signed', covers: ['malformed'], spec: { omit: ['challenge'] }, expect: identityRefused('malformed') },
  { id: 'IDN-023', title: 'a creation date that does not exist', covers: ['malformed', 'time'], spec: { fields: { created: '2026-11-31T12:00:00Z' } }, expect: identityRefused('malformed') },
  { id: 'IDN-024', title: 'a creation time with fractional seconds', covers: ['malformed', 'time'], spec: { fields: { created: '2026-11-01T12:00:00.000Z' } }, expect: identityRefused('malformed') },
  { id: 'IDN-025', title: 'an origin with a path', covers: ['malformed', 'origin'], spec: { fields: { origin: `${ORIGIN}/` } }, expect: identityRefused('malformed') },
  { id: 'IDN-026', title: 'an origin with the default port', covers: ['malformed', 'origin'], spec: { fields: { origin: `${ORIGIN}:443` } }, expect: identityRefused('malformed') },
  { id: 'IDN-027', title: 'an origin that matches the syntax but is not valid IDNA', covers: ['malformed', 'origin'], spec: { fields: { origin: 'https://xn--a.example' } }, expect: identityRefused('malformed') },
  { id: 'IDN-028', title: 'another statement type', covers: ['malformed'], spec: { fields: { type: 'aria-ap-identity/2' } }, expect: identityRefused('malformed') },
  { id: 'IDN-029', title: 'a challenge outside the profile syntax', covers: ['malformed', 'challenge'], spec: { fields: { challenge: 'two words' } }, expect: identityRefused('malformed') },
  { id: 'IDN-030', title: 'the receiver credential is revoked', covers: ['status'], spec: { by: 'revoked' }, expect: identityRefused('status') },
  { id: 'IDN-031', title: 'status established 60 s after creation', covers: ['freshness', 'asynchronous'], timeline: { statusAfter: 60 }, expect: identityOk },
  { id: 'IDN-032', title: 'status established 61 s after creation', covers: ['freshness', 'asynchronous'], timeline: { statusAfter: 61 }, expect: identityRefused('stale') },
  { id: 'IDN-033', title: 'order: stale and a wrong signature', covers: ['order'], spec: { fields: { created: iso(NOW - 61) }, value: 'flipped' }, expect: identityRefused('stale') },
  { id: 'IDN-034', title: 'order: another receiver with a wrong signature', covers: ['order'], spec: { by: 'other', value: 'flipped' }, expect: identityRefused('unexpected_receiver') },
];

const identityContext = {
  now: iso(NOW),
  pin: { did: RECEIVER_DID, origin: ORIGIN },
  expected: { nonce: IDENTITY_NONCE, audience: SENDER_DID },
  maxAgeSeconds: profile.identity.maxAgeSeconds,
  skewSeconds: profile.transport.skewSeconds,
  credentials: Object.values(IDENTITY_VIEWS).map(({ signer: _, ...v }) => ({ ...v, document: documentOf(v) })),
};
const identityVectors = IDENTITY_CASES.map((c) => ({
  id: c.id,
  title: c.title,
  covers: c.covers,
  ...(c.pin ? { pin: c.pin } : {}),
  ...(c.timeline ? { timeline: c.timeline } : {}),
  response: identityResponse(c.id, c.spec),
  expect: typeof c.expect === 'function' ? c.expect(c.id) : c.expect,
}));

// ---------------------------------------------------------------- historical receipts

// Receipts checked long after the exchange against retained evidence: real AID 1.0
// documents and status lists, signed by a synthetic issuer with the composite suite.
// ML-DSA-65 signs deterministically (no extra entropy); status lists use stored deflate
// blocks, so their bytes do not depend on a zlib build.
const ISSUER_DID = 'did:aria:registry.example.test';
const ISSUER_METHOD = `${ISSUER_DID}#key-1`;
const STATUS_LIST = 'https://registry.example.test/v1/status/1';
const ISSUER_PQ = ml_dsa65.keygen(sha256(utf8('aria-ap-1 synthetic issuer ML-DSA-65 seed')));
const ISSUER_ED = key('synthetic issuer Ed25519 key');
const HISTORICAL_AT = '2028-01-01T00:00:00Z';

function issuerSigned(document, created, corrupt) {
  const payload = utf8(canonical(document));
  const pq = ml_dsa65.sign(payload, ISSUER_PQ.secretKey, { extraEntropy: false });
  const ed = Uint8Array.from(ed25519.sign(payload, ISSUER_ED.seed));
  if (corrupt === 'classical') ed[0] ^= 0x01;
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, pq.length, false);
  const proofValue = `u${b64url(Buffer.concat([header, pq, ed]))}`;
  return { ...document, proof: { type: 'DataIntegrityProof', cryptosuite: 'mldsa65-ed25519-2026', created, verificationMethod: ISSUER_METHOD, proofPurpose: 'assertionMethod', proofValue } };
}

function uuid7(label) {
  const b = sha256(utf8(`aria-ap-1 vector uuid7: ${label}`)).slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Buffer.from(b).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function aid({ label, n, holder, validFrom, validUntil, index }, corrupt) {
  const document = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://aria.bar/ns/v1'],
    id: `https://api.aria.bar/v1/credentials/${uuid7(label)}`,
    type: ['VerifiableCredential', 'ARIAIdentityDocument'],
    issuer: ISSUER_DID,
    validFrom,
    validUntil,
    credentialSubject: {
      id: RECEIVER_DID,
      agentName: 'transfers',
      version: '1.0.0',
      spec_version: '1.0',
      trustLevel: 'L1',
      scope: ['payments:transfer:receive'],
      hitlRequired: [],
      delegationDepth: 0,
      maxDelegationDepth: 0,
      principal: { type: 'Organization', legalName: 'Example Bank', did: 'did:aria:bank.example.test:owner', jurisdiction: 'ES', verificationStatus: 'registry-confirmed' },
      holderKey: { id: `${RECEIVER_DID}#holder-key-${n}`, type: 'Ed25519VerificationKey2020', publicKeyMultibase: `z${base58(holder.publicKey)}` },
      enrollmentAttestation: { userAgentAgreement: true, attestedAt: validFrom, termsVersion: '1.0.0', privacyVersion: '1.0.0' },
    },
    credentialStatus: { id: `${STATUS_LIST}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: STATUS_LIST },
  };
  return issuerSigned(document, validFrom, corrupt);
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
// gzip (RFC 1952) of one stored deflate block (RFC 1951 §3.2.4); `bits` is at most 65535 bytes.
function gzipStored(bits) {
  const out = Buffer.alloc(10 + 5 + bits.length + 8);
  out.set([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
  out.writeUInt8(1, 10);
  out.writeUInt16LE(bits.length, 11);
  out.writeUInt16LE(~bits.length & 0xffff, 13);
  out.set(bits, 15);
  out.writeUInt32LE(crc32(bits), 15 + bits.length);
  out.writeUInt32LE(bits.length, 19 + bits.length);
  return out;
}

function statusListDocument({ revoked = [], validFrom, id = STATUS_LIST }, corrupt) {
  const bits = new Uint8Array(131_072 / 8);
  for (const i of revoked) bits[i >> 3] |= 0x80 >> (i & 7);
  const document = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: ISSUER_DID,
    validFrom,
    validUntil: iso(Date.parse(validFrom) / 1000 + 24 * 3600),
    credentialSubject: { id: `${id}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: `u${b64url(gzipStored(bits))}` },
  };
  return issuerSigned(document, validFrom, corrupt);
}

const R1 = { label: 'receiver 1 (retained)', n: 1, holder: KEYS.r1, validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z', index: 21 };
const R2 = { label: 'receiver 2 (renewed)', n: 2, holder: KEYS.r2, validFrom: '2027-09-01T00:00:00Z', validUntil: '2028-09-01T00:00:00Z', index: 22 };
const DOCUMENTS = {
  r1: { document: aid(R1), authentic: true, note: 'expired at the check: verifyCredential refuses it, authenticity holds' },
  r2: { document: aid(R2), authentic: true, note: 'the same DID\'s current document at the check' },
  'r1-altered': { document: aid(R1, 'classical'), authentic: false, reason: 'signature_invalid' },
};
const STATUS_LISTS = {
  revoked: { document: statusListDocument({ revoked: [R1.index], validFrom: '2026-12-01T00:00:00Z' }), read: { state: 'revoked' } },
  active: { document: statusListDocument({ revoked: [R2.index], validFrom: '2026-11-01T00:00:00Z' }), read: { state: 'active' } },
  forged: { document: statusListDocument({ revoked: [R1.index], validFrom: '2026-12-01T00:00:00Z' }, 'classical'), read: { reason: 'signature_invalid' } },
  'other-list': { document: statusListDocument({ revoked: [R1.index], validFrom: '2026-12-01T00:00:00Z', id: 'https://registry.example.test/v1/status/2' }), read: { reason: 'malformed' } },
};

const R1_VIEW = { did: RECEIVER_DID, url: DOCUMENTS.r1.document.id, holderKey: DOCUMENTS.r1.document.credentialSubject.holderKey };
const H_ATTEMPT = { a1: attemptOf('REQ-001', R1_VIEW), y: attemptOf('REQ-011', R1_VIEW) };
const findings = (within, retained, period) => ({ issuedAtWithinValidity: within, retainedStatus: retained, retainedStatusPeriod: period ?? null, signingTime: 'receiver_claim' });
const period = (validFrom) => ({ validFrom, validUntil: iso(Date.parse(validFrom) / 1000 + 24 * 3600) });
const hist = (spec) => ({ receiverView: R1_VIEW, attempt: H_ATTEMPT.a1, outcome: completed, ...spec });

const HISTORICAL = [
  { id: 'RCP-12a', title: 'receiver credential revoked after issuedAt, by a retained list', covers: ['§5.9 #12'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r1', statusList: 'revoked' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(true, 'revoked', period('2026-12-01T00:00:00Z')) }), note: 'Valid: authenticity and bindings hold. The list says revoked during its own validity, after issuedAt; that is reported, not turned into invalidity.' },
  { id: 'RCP-12b', title: 'no retained receiver credential', covers: ['§5.9 #12'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: {}, expect: invalid('evidence_missing') },
  { id: 'RCP-12c', title: 'the DID\'s current document instead of the named one', covers: ['§5.9 #12'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r2' }, expect: invalid('evidence_missing') },
  { id: 'RCP-12d', title: 'issuedAt outside the named credential\'s validity', covers: ['§5.9 #12'], receipt: hist({ label: 'historical completed late', issuedAt: '2027-12-01T00:00:00Z' }), attempts: ['a1'], evidence: { document: 'r1' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(false, 'not_retained') }), note: 'The statement verifies; its claimed time does not fall in the credential\'s validity, and that is reported, not hidden.' },
  { id: 'RCP-12e', title: 'a retained document that is not authentic is no evidence', covers: ['authenticity'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r1-altered' }, expect: invalid('evidence_missing') },
  { id: 'RCP-12f', title: 'a retained list valid at issuedAt says active', covers: ['retained status'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r1', statusList: 'active' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(true, 'active', period('2026-11-01T00:00:00Z')) }) },
  { id: 'RCP-12g', title: 'a retained list whose signature fails is not retained status', covers: ['retained status'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r1', statusList: 'forged' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(true, 'not_retained') }) },
  { id: 'RCP-12h', title: 'another genuine list of the issuer is not this credential\'s', covers: ['retained status'], receipt: hist({ label: 'historical completed' }), attempts: ['a1'], evidence: { document: 'r1', statusList: 'other-list' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(true, 'not_retained') }) },
  { id: 'RCP-12i', title: 'issuedAt exactly at validFrom', covers: ['boundary'], receipt: hist({ label: 'historical at validFrom', issuedAt: R1.validFrom }), attempts: ['a1'], evidence: { document: 'r1' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(true, 'not_retained') }) },
  { id: 'RCP-12j', title: 'issuedAt exactly at validUntil', covers: ['boundary'], receipt: hist({ label: 'historical at validUntil', issuedAt: R1.validUntil }), attempts: ['a1'], evidence: { document: 'r1' }, expect: valid(completed, H_ATTEMPT.a1, { findings: findings(false, 'not_retained') }), note: 'validUntil is exclusive, as when a credential is judged now.' },
  { id: 'RCP-12k', title: 'signed by a key other than the named credential\'s holder key', covers: ['authenticity'], receipt: hist({ label: 'historical forged', signer: 'attacker' }), attempts: ['a1'], evidence: { document: 'r1' }, expect: invalid('signature_invalid') },
  { id: 'RCP-12l', title: 'bound to no kept attempt', covers: ['binding'], receipt: hist({ label: 'historical other operation', attempt: H_ATTEMPT.y }), attempts: ['a1'], evidence: { document: 'r1' }, expect: invalid('binding') },
  { id: 'RCP-12m', title: 'keyid of another key of the receiver', covers: ['receiver'], receipt: hist({ label: 'historical other key', keyid: `${RECEIVER_DID}#holder-key-2` }), attempts: ['a1'], evidence: { document: 'r1' }, expect: invalid('receiver_mismatch') },
  { id: 'RCP-12n', title: 'the digest selects a kept attempt, the receipt names another operation', covers: ['binding'], receipt: hist({ label: 'historical operation swapped', extra: { request: { id: OP.Y, sender: H_ATTEMPT.a1.sender, digest: H_ATTEMPT.a1.requestDigest } } }), attempts: ['a1'], evidence: { document: 'r1' }, expect: invalid('binding') },
];

const historicalContext = {
  at: HISTORICAL_AT,
  issuer: {
    did: ISSUER_DID,
    verificationMethod: ISSUER_METHOD,
    maxLevel: 'L1',
    statusLists: [STATUS_LIST],
    keys: { mldsa65: b64(ISSUER_PQ.publicKey), ed25519: b64(ISSUER_ED.publicKey) },
  },
  documents: DOCUMENTS,
  statusLists: STATUS_LISTS,
};
const historicalVectors = HISTORICAL.map((c) => ({
  id: c.id,
  title: c.title,
  covers: c.covers,
  ...(c.note ? { note: c.note } : {}),
  attempts: c.attempts.map((a) => H_ATTEMPT[a]),
  evidence: c.evidence,
  receipt: receipt(c.receipt),
  expect: c.expect,
}));

// ---------------------------------------------------------------- write

const header0 = {
  status: profile.status,
  generatedBy: 'conformance/ap/generate.mjs',
  keys: 'synthetic: seeds are SHA-256 of public labels in generate.mjs; never trusted anywhere',
};
const outDir = new URL('./vectors/', import.meta.url);
mkdirSync(outDir, { recursive: true });
const write = (name, value) => writeFileSync(new URL(name, outDir), `${JSON.stringify(value, null, 2)}\n`);
write('requests.json', { ...header0, context: requestContext, vectors: requestVectors });
write('fingerprints.json', { ...header0, ...fingerprintVectors });
write('receipts.json', { ...header0, vectors: receiptVectors });
write('identity.json', { ...header0, context: identityContext, vectors: identityVectors });
write('historical.json', { ...header0, context: historicalContext, vectors: historicalVectors });
console.log(`requests ${requestVectors.length}, fingerprints ${fingerprintVectors.cases.length}, receipts ${receiptVectors.length}, identity ${identityVectors.length}, historical ${historicalVectors.length}`);
