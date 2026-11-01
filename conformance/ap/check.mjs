#!/usr/bin/env node
// Independent checker for the ARIA AP vectors (provisional profile). Exits 1 on any failure.
//
// It shares no code with generate.mjs: the RFC 9421 signature base is rebuilt by
// http-message-signatures, structured fields are parsed by structured-headers, canonical
// JSON is RFC 8785 (canonicalize; equal to ARIA canonical JSON for the receipt and
// fingerprint data models), and the receiver and receipt rules are written here.
//
//   node check.mjs [--verbose] [--report <file>]

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import canonicalize from 'canonicalize';
import { httpbis } from 'http-message-signatures';
import { parseDictionary, parseItem } from 'structured-headers';
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { createReference, MUTANTS, runSequence } from './model.mjs';

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const reportPath = args.includes('--report') ? args[args.indexOf('--report') + 1] : null;

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const profile = load('./profile.json');
const requests = load('./vectors/requests.json');
const fingerprints = load('./vectors/fingerprints.json');
const receipts = load('./vectors/receipts.json');
const sequences = load('./vectors/sequences.json');
const scopes = load('./vectors/scopes.json');
const identity = load('./vectors/identity.json');
const historical = load('./vectors/historical.json');
const identitySchema = load('../../schema/aria-ap-identity-1.json');
const aid10 = load('../../schema/aid-1.0.json');

const Point = ed25519.Point;
const L = Point.Fn.ORDER;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DIGEST = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;
const RECEIVER_CODE = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;
const NO_TIME_LIMIT = Number.MAX_SAFE_INTEGER; // the library's own clock is bypassed; windows are judged here

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const sha256Field = (bytes) => `sha-256=:${b64(sha256(bytes))}:`;
const jcs = (value) => new TextEncoder().encode(canonicalize(value));

function equal(a, b) {
  return canonicalize(a ?? null) === canonicalize(b ?? null);
}

// ---------------------------------------------------------------- Ed25519, strict

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function holderKeyBytes(multibase) {
  if (typeof multibase !== 'string' || !multibase.startsWith('z')) return null;
  let n = 0n;
  for (const ch of multibase.slice(1)) {
    const d = B58.indexOf(ch);
    if (d < 0) return null;
    n = n * 58n + BigInt(d);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const zeros = multibase.slice(1).match(/^1*/)[0].length;
  const bytes = Buffer.concat([Buffer.alloc(zeros), n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex')]);
  return bytes.length === 32 ? new Uint8Array(bytes) : null;
}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const numberLE = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`);

// The authority's holder-key rule: canonical encoding of a point, not small order, torsion free.
function acceptableKey(key) {
  try {
    const A = Point.fromBytes(key, false);
    return sameBytes(A.toBytes(), key) && !A.isSmallOrder() && A.isTorsionFree();
  } catch {
    return false;
  }
}

// Profile rule: acceptable key; R canonical, not small order, torsion free; S < L; then
// RFC 8032 verification. With A and R in the prime-order subgroup, the cofactored and
// cofactorless equations agree, so implementations cannot diverge.
function strictVerify(signature, message, key) {
  if (signature.length !== 64 || !acceptableKey(key)) return false;
  const Rb = signature.subarray(0, 32);
  try {
    const R = Point.fromBytes(Rb, false);
    if (!sameBytes(R.toBytes(), Rb) || R.isSmallOrder() || !R.isTorsionFree()) return false;
  } catch {
    return false;
  }
  if (numberLE(signature.subarray(32)) >= L) return false;
  return ed25519.verify(signature, message, key, { zip215: false });
}

// ---------------------------------------------------------------- receiver authentication

const unsigned = (http, code, subtype) => ({ result: 'refused', http, code, ...(subtype ? { subtype } : {}), signed: false });
const invalidRequest = () => unsigned(400, 'aria.request_invalid');
const authFailed = (subtype) => unsigned(401, 'aria.authentication_failed', subtype);

function fieldsOf(headers) {
  const fields = new Map();
  for (const [name, value] of headers) {
    const key = name.toLowerCase();
    fields.set(key, [...(fields.get(key) ?? []), value]);
  }
  return fields;
}

// The byte sequence of member or parameter `name` in `text` is the canonical, padded base64 of its bytes.
function canonicalBytes(text, name) {
  const m = new RegExp(`(?:^|[,;])\\s*${name.replace(/[-.]/g, '\\$&')}=:([^:]*):`).exec(text);
  return !!m && Buffer.from(m[1], 'base64').toString('base64') === m[1];
}

function sfString(value) {
  try {
    const [item, params] = parseItem(value);
    return typeof item === 'string' && params.size === 0 ? item : null;
  } catch {
    return null;
  }
}

function mediaType(value) {
  const [type, ...rest] = value.split(';');
  const t = type.trim().toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(t)) return null;
  const params = rest.map((p) => {
    const at = p.indexOf('=');
    return at < 0 ? null : [p.slice(0, at).trim().toLowerCase(), p.slice(at + 1).trim()];
  });
  if (params.includes(null)) return null;
  params.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return [t, ...params.map(([k, v]) => `${k}=${v}`)].join(';');
}

function messageOf(origin, request, fields) {
  return {
    method: request.method,
    url: origin + request.target,
    headers: Object.fromEntries([...fields].map(([k, vs]) => [k, vs.length === 1 ? vs[0] : vs])),
  };
}

// Rebuilds the base with the library and hands it to `verify`; returns its verdict and the base.
async function withBase(message, verify) {
  let base = null;
  const ok = await httpbis
    .verifyMessage(
      {
        tolerance: NO_TIME_LIMIT,
        all: true,
        keyLookup: async () => ({
          algs: ['ed25519'],
          verify: async (data, signature) => {
            base = new Uint8Array(data);
            return verify(new Uint8Array(signature), base);
          },
        }),
      },
      message,
    )
    .catch(() => false);
  return { ok: ok === true, base };
}

async function authenticate(vector, context) {
  const now = Date.parse(context.now) / 1000;
  const consumed = new Set(vector.context?.consumed ?? []);
  const { request } = vector;
  const origin = context.receiver.origin;
  const fields = fieldsOf(request.headers);
  const body = request.body ? Buffer.from(request.body.utf8, 'utf8') : Buffer.alloc(0);

  // 1. A supported method and exactly one described operation.
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return invalidRequest();
  if (!request.target.startsWith('/') || request.target.includes('#')) return invalidRequest();
  const url = new URL(request.target, origin);
  if (url.origin !== origin) return invalidRequest();
  // The target is taken exactly: one that is not its own serialization is refused, not normalised.
  if (url.href !== origin + request.target) return invalidRequest();
  const d = context.descriptors.find((x) => x.method === request.method && x.path === url.pathname);
  if (!d) return invalidRequest();
  const cls = profile.classes[d.class];

  // 2. Body rules and the descriptor's one media type.
  if (cls.body === 'forbidden' && body.length > 0) return invalidRequest();
  if (cls.body === 'required') {
    if (body.length === 0) return invalidRequest();
    const ct = fields.get('content-type');
    if (ct?.length !== 1 || mediaType(ct[0]) !== d.mediaType) return invalidRequest();
  }

  // 3. Only declared query parameters, each at most once.
  const names = [...url.searchParams.keys()];
  if (new Set(names).size !== names.length || names.some((n) => !d.query.includes(n))) return invalidRequest();
  if (d.class === 'retrieval' && !UUID.test(url.searchParams.get('operation') ?? '')) return invalidRequest();

  // 4. The signed operation reference: required on receiptable classes, absent on retrieval.
  const opField = fields.get('aria-operation');
  let operation;
  if (d.class === 'retrieval') {
    if (opField) return invalidRequest();
  } else {
    if (opField?.length !== 1) return invalidRequest();
    operation = sfString(opField[0]);
    if (!operation || !UUID.test(operation)) return invalidRequest();
  }

  // 5. Exactly one signature, labelled aria.
  const si = fields.get('signature-input');
  const sg = fields.get('signature');
  if (si?.length !== 1 || sg?.length !== 1) return authFailed('signature');
  let inputs;
  let signatures;
  try {
    inputs = parseDictionary(si[0]);
    signatures = parseDictionary(sg[0]);
  } catch {
    return authFailed('signature');
  }
  if (inputs.size !== 1 || signatures.size !== 1 || !inputs.has(profile.transport.label) || !signatures.has(profile.transport.label)) {
    return authFailed('signature');
  }
  const [items, params] = inputs.get(profile.transport.label);
  if (!Array.isArray(items)) return authFailed('signature');

  // 6. Covered components: the class list plus the descriptor's semantic headers present.
  const covered = items.map(([name, p]) => (typeof name === 'string' && p.size === 0 ? name : null));
  const semantic = d.semanticHeaders.filter((h) => fields.has(h));
  const required = [...cls.components, ...semantic];
  if (operation !== undefined && !covered.includes('aria-operation')) return authFailed('unsigned_operation');
  if (required.includes('content-digest') && !covered.includes('content-digest')) return authFailed('digest');
  if (covered.includes(null) || new Set(covered).size !== covered.length) return authFailed('signature');
  if (covered.length !== required.length || required.some((c) => !covered.includes(c))) return authFailed('signature');

  // 7. Signature parameters, then the window.
  const expected = ['created', 'expires', 'nonce', 'keyid', 'alg', 'tag'];
  if (params.size !== expected.length || expected.some((k) => !params.has(k))) return authFailed('signature');
  const created = params.get('created');
  const expires = params.get('expires');
  const nonce = params.get('nonce');
  const keyid = params.get('keyid');
  if (params.get('alg') !== profile.transport.alg || params.get('tag') !== profile.transport.tag) return authFailed('signature');
  if (!Number.isInteger(created) || !Number.isInteger(expires) || typeof nonce !== 'string' || typeof keyid !== 'string') {
    return authFailed('signature');
  }
  const skew = context.skewSeconds;
  // Judged at entry, and again after the credential is resolved and after the challenge is consumed.
  const inWindow = (t) => created <= t + skew && expires >= t - skew;
  if (expires <= created || expires - created > context.maxWindowSeconds || !inWindow(now)) {
    return authFailed('window');
  }

  // 8. Content-Digest of the exact content (empty for unsafe-empty).
  if (cls.components.includes('content-digest')) {
    const cd = fields.get('content-digest');
    if (cd?.length !== 1) return authFailed('digest');
    let member;
    try {
      member = parseDictionary(cd[0]).get('sha-256');
    } catch {
      return authFailed('digest');
    }
    if (!(member?.[0] instanceof ArrayBuffer) || b64(member[0]) !== b64(sha256(body)) || !canonicalBytes(cd[0], 'sha-256')) return authFailed('digest');
  }

  // 9. A challenge this receiver issued, live strictly before its expiry, and not yet consumed.
  const issued = context.challenges.find((c) => c.value === nonce);
  if (!issued || Date.parse(issued.expires) / 1000 <= now || consumed.has(nonce)) return authFailed('challenge');

  // 10. The exact credential named, its digest, its holder key and that key's acceptability.
  const ac = fields.get('aria-credential');
  if (ac?.length !== 1) return authFailed('credential');
  let credentialUrl;
  let credentialDigest;
  try {
    const [item, p] = parseItem(ac[0]);
    credentialUrl = item;
    credentialDigest = p.get('digest');
  } catch {
    return authFailed('credential');
  }
  const credential = context.credentials.find((c) => c.url === credentialUrl);
  if (!credential || !(credentialDigest instanceof ArrayBuffer)) return authFailed('credential');
  if (`sha-256=:${b64(credentialDigest)}:` !== credential.digest || keyid !== credential.holderKey.id || !canonicalBytes(ac[0], 'digest')) return authFailed('credential');
  const key = holderKeyBytes(credential.holderKey.publicKeyMultibase);
  if (!key || !acceptableKey(key)) return authFailed('credential');

  // 11. The signature over the base rebuilt from the receiver's own origin; a covered field
  // must appear once, and the signature's bytes must be spelled canonically.
  if (covered.some((c) => !c.startsWith('@') && fields.get(c)?.length !== 1) || !canonicalBytes(sg[0], profile.transport.label)) return authFailed('signature');
  const { ok, base } = await withBase(messageOf(origin, request, fields), (signature, data) => strictVerify(signature, data, key));
  if (!ok) return authFailed('signature');
  if (!inWindow(now + (vector.timeline?.resolvedAfter ?? 0))) return authFailed('window');

  // 12. Consumed once authenticated (atomically, in a real store), and still inside the window after that.
  consumed.add(nonce);
  if (!inWindow(now + (vector.timeline?.consumedAfter ?? vector.timeline?.resolvedAfter ?? 0))) return authFailed('window');

  // Admission's first step: the audience the signature covers.
  if (sfString(fields.get('aria-audience')[0]) !== context.receiver.did) {
    return d.class === 'retrieval'
      ? unsigned(403, 'aria.audience_mismatch')
      : { result: 'refused', http: 403, code: 'aria.audience_mismatch', signed: true, applies: 'attempt' };
  }

  const out = {
    result: 'authenticated',
    descriptor: d.name,
    class: d.class,
    sender: { did: credential.did, credential: credential.url },
    requestDigest: sha256Field(base),
  };
  if (d.class === 'retrieval') return { ...out, retrieves: url.searchParams.get('operation') };
  const fp = {
    class: d.class,
    method: d.method,
    path: url.pathname,
    query: Object.fromEntries(d.query.filter((n) => url.searchParams.has(n)).map((n) => [n, url.searchParams.get(n)])),
    semanticHeaders: Object.fromEntries(semantic.map((h) => [h, fields.get(h)[0]])),
  };
  if (d.class === 'unsafe-body') {
    fp.mediaType = d.mediaType;
    fp.contentDigest = sha256Field(body);
  }
  if (d.class === 'unsafe-empty') fp.contentDigest = sha256Field(new Uint8Array());
  return { ...out, operation, fingerprint: sha256Field(jcs(fp)) };
}

// A lenient verifier (no key or R rule): does it accept this vector's signature?
async function lenientAccepts(vector, context, rule) {
  const fields = fieldsOf(vector.request.headers);
  const [url] = parseItem(fields.get('aria-credential')[0]);
  const key = holderKeyBytes(context.credentials.find((c) => c.url === url).holderKey.publicKeyMultibase);
  const { ok } = await withBase(messageOf(context.receiver.origin, vector.request, fields), (signature, data) =>
    ed25519.verify(signature, data, key, { zip215: rule === 'zip215' }),
  );
  return ok;
}

// ---------------------------------------------------------------- receipts

// JSON restricted to the receipt data model: objects, strings and safe integers; ASCII
// alphabetic keys; no duplicate keys; nothing after the value.
function parseReceiptJson(text) {
  let i = 0;
  const fail = (why) => {
    throw new Error(`${why} at ${i}`);
  };
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };
  function string() {
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text.charCodeAt(i) < 0x20) fail('control character');
      i += text[i] === '\\' ? 2 : 1;
    }
    if (text[i] !== '"') fail('unterminated string');
    i++;
    return JSON.parse(text.slice(start, i));
  }
  function integer() {
    const m = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i));
    if (!m) fail('number');
    i += m[0].length;
    if (text[i] === '.' || text[i] === 'e' || text[i] === 'E') fail('not an integer');
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) fail('integer range');
    return n;
  }
  function object() {
    i++;
    const out = {};
    ws();
    if (text[i] === '}') {
      i++;
      return out;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') fail('key');
      const k = string();
      if (!/^[A-Za-z]+$/.test(k)) fail('key not ASCII alphabetic');
      if (Object.hasOwn(out, k)) fail('duplicate key');
      ws();
      if (text[i++] !== ':') fail('colon');
      out[k] = value();
      ws();
      if (text[i] === ',') {
        i++;
        continue;
      }
      if (text[i] === '}') {
        i++;
        return out;
      }
      fail('object');
    }
  }
  function value() {
    ws();
    if (text[i] === '{') return object();
    if (text[i] === '"') return string();
    if (text[i] === '-' || (text[i] >= '0' && text[i] <= '9')) return integer();
    return fail('value type outside the data model');
  }
  const out = value();
  ws();
  if (i !== text.length || typeof out !== 'object') fail('trailing content');
  return out;
}

const members = (o, required, optional = []) =>
  o !== null &&
  typeof o === 'object' &&
  required.every((k) => Object.hasOwn(o, k)) &&
  Object.keys(o).every((k) => required.includes(k) || optional.includes(k));

function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return false;
  const t = Date.parse(value);
  return Number.isFinite(t) && new Date(t).toISOString().replace('.000Z', 'Z') === value;
}

function httpsUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.href === value && !u.search && !u.hash && !u.username;
  } catch {
    return false;
  }
}

const party = (p) => members(p, ['did', 'credential']) && typeof p.did === 'string' && p.did.startsWith('did:aria:') && httpsUrl(p.credential);

function outcomeConsistent(o) {
  if (!members(o, ['state', 'applies', 'status', 'code'], ['result'])) return false;
  if (typeof o.code !== 'string' || !Number.isInteger(o.status)) return false;
  if (o.result !== undefined && !(members(o.result, ['digest']) && DIGEST.test(o.result.digest))) return false;
  const reason = profile.reasons[o.code];
  const receiverCode = RECEIVER_CODE.test(o.code) && !o.code.startsWith('aria.');
  if (o.state === 'completed') return o.applies === 'operation' && o.code === 'aria.completed' && [200, 201].includes(o.status);
  if (o.state === 'accepted') return o.applies === 'operation' && o.code === 'aria.accepted' && o.status === 202;
  if (o.state !== 'rejected') return false;
  if (o.applies === 'operation') return receiverCode && o.status === 422;
  if (o.applies === 'attempt') {
    return (reason?.signed === true && reason.applies === 'attempt' && reason.http === o.status) || (receiverCode && o.status === 403);
  }
  return false;
}

function wellFormed(r) {
  return (
    members(r, ['type', 'id', 'request', 'receiver', 'issuedAt', 'outcome', 'proof']) &&
    typeof r.id === 'string' &&
    UUID.test(r.id.replace(/^urn:uuid:/, '')) &&
    r.id.startsWith('urn:uuid:') &&
    members(r.request, ['id', 'sender', 'digest']) &&
    UUID.test(r.request.id) &&
    r.id !== `urn:uuid:${r.request.id}` &&
    party(r.request.sender) &&
    DIGEST.test(r.request.digest) &&
    party(r.receiver) &&
    instant(r.issuedAt) &&
    outcomeConsistent(r.outcome) &&
    members(r.proof, ['alg', 'keyid', 'value']) &&
    r.proof.alg === 'ed25519' &&
    typeof r.proof.keyid === 'string' &&
    /^[A-Za-z0-9_-]{86}$/.test(r.proof.value)
  );
}

function verifyReceipt(vector) {
  const invalid = (reason) => ({ result: 'invalid', reason });
  const text = vector.receipt;
  if (Buffer.byteLength(text, 'utf8') > profile.receipt.maxBytes) return invalid('malformed');
  let r;
  try {
    r = parseReceiptJson(text);
  } catch {
    return invalid('malformed');
  }
  if (typeof r.type === 'string' && r.type !== profile.receipt.type) return invalid('unsupported_type');
  if (!wellFormed(r)) return invalid('malformed');

  // The receiver: the exact credential instance the client authenticated.
  const expected = vector.client.receiver;
  if (r.receiver.did !== expected.did || r.receiver.credential !== expected.url || r.proof.keyid !== expected.holderKey.id) {
    return invalid('receiver_mismatch');
  }

  // The signature covers the whole receipt except proof.value.
  const { value, ...proof } = r.proof;
  const key = holderKeyBytes(expected.holderKey.publicKeyMultibase);
  if (!key || !strictVerify(new Uint8Array(Buffer.from(value, 'base64url')), jcs({ ...r, proof }), key)) return invalid('signature_invalid');

  // The digest selects a kept attempt; every binding is then checked against it.
  const attempts = vector.client.attempts;
  if (attempts.length === 0) return invalid('binding_unverifiable');
  const attempt = attempts.find((a) => a.requestDigest === r.request.digest);
  if (
    !attempt ||
    attempt.operation !== r.request.id ||
    !equal(attempt.sender, r.request.sender) ||
    !equal(attempt.receiver, r.receiver)
  ) {
    return invalid('binding');
  }

  if (vector.mode === 'decision' && vector.transportStatus !== r.outcome.status) return invalid('status_mismatch');
  if (vector.mode === 'retrieval') {
    if (vector.transportStatus !== 200) return invalid('status_mismatch');
    if (r.outcome.applies !== 'operation') return invalid('not_operation');
  }
  return { result: 'valid', state: r.outcome.state, applies: r.outcome.applies, status: r.outcome.status, code: r.outcome.code, attempt: attempt.request };
}

// ---------------------------------------------------------------- historical receipts

// Retained evidence is judged here without the current time. The composite proof is
// decoded and both halves verified with the same libraries as the SDK; the rules,
// the decoding and the list reading (node:zlib) are this file's. Schema conformance of
// the retained documents is the credential verifier's and S1's vectors'.
const ML_DSA_65_SIGNATURE = 3309;

function issuerSignatureHolds(doc, issuer) {
  const p = doc?.proof;
  if (doc?.issuer !== issuer.did || !p || p.type !== 'DataIntegrityProof' || p.cryptosuite !== 'mldsa65-ed25519-2026' || p.proofPurpose !== 'assertionMethod' || p.verificationMethod !== issuer.verificationMethod) return false;
  if (typeof p.proofValue !== 'string' || !p.proofValue.startsWith('u')) return false;
  const bytes = Buffer.from(p.proofValue.slice(1), 'base64url');
  if (bytes.toString('base64url') !== p.proofValue.slice(1) || bytes.length !== 4 + ML_DSA_65_SIGNATURE + 64 || bytes.readUInt32BE(0) !== ML_DSA_65_SIGNATURE) return false;
  const { proof: _, ...unsigned } = doc;
  const payload = jcs(unsigned);
  const keys = { mldsa65: new Uint8Array(Buffer.from(issuer.keys.mldsa65, 'base64')), ed25519: new Uint8Array(Buffer.from(issuer.keys.ed25519, 'base64')) };
  try {
    return ml_dsa65.verify(bytes.subarray(4, 4 + ML_DSA_65_SIGNATURE), payload, keys.mldsa65) && ed25519.verify(bytes.subarray(4 + ML_DSA_65_SIGNATURE), payload, keys.ed25519, { zip215: false });
  } catch {
    return false;
  }
}

const exactInstant = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) && new Date(Date.parse(v)).toISOString() === v.replace('Z', '.000Z') ? Date.parse(v) : null);

// The document is authentic: signed by the trusted issuer, a validity interval, a
// holder key of its subject, a status entry in a list the issuer publishes. Never judged against now.
function authenticDocument(doc, issuer) {
  if (!issuerSignatureHolds(doc, issuer)) return null;
  const s = doc.credentialSubject;
  const validFrom = exactInstant(doc.validFrom);
  const validUntil = exactInstant(doc.validUntil);
  if (validFrom === null || validUntil === null || validFrom >= validUntil) return null;
  const key = holderKeyBytes(s?.holderKey?.publicKeyMultibase);
  if (!key || !acceptableKey(key) || typeof s.id !== 'string' || !s.holderKey.id.startsWith(`${s.id}#holder-key-`)) return null;
  const st = doc.credentialStatus;
  if (!issuer.statusLists.includes(st?.statusListCredential) || !/^(0|[1-9]\d*)$/.test(st.statusListIndex)) return null;
  return { id: doc.id, did: s.id, keyId: s.holderKey.id, key, validFrom, validUntil, list: st.statusListCredential, index: Number(st.statusListIndex) };
}

// What a retained list said about the credential, or null when it is not that credential's list or does not verify.
function retainedState(list, credential, issuer) {
  const subject = list?.credentialSubject;
  if (list?.id !== credential.list || !Array.isArray(list.type) || !list.type.includes('BitstringStatusListCredential') || !issuerSignatureHolds(list, issuer)) return null;
  if (subject?.type !== 'BitstringStatusList' || subject.statusPurpose !== 'revocation' || (subject.statusSize ?? 1) !== 1 || typeof subject.encodedList !== 'string' || !subject.encodedList.startsWith('u')) return null;
  let bits;
  try {
    bits = gunzipSync(Buffer.from(subject.encodedList.slice(1), 'base64url'));
  } catch {
    return null;
  }
  const validFrom = exactInstant(list.validFrom);
  const validUntil = exactInstant(list.validUntil);
  if (bits.length < 131_072 / 8 || credential.index >= bits.length * 8 || validFrom === null || validUntil === null || validUntil <= validFrom || validUntil - validFrom > 24 * 3_600_000) return null;
  const revoked = (bits[credential.index >> 3] >> (7 - (credential.index & 7))) & 1;
  return { state: revoked ? 'revoked' : 'active', period: { validFrom: list.validFrom, validUntil: list.validUntil } };
}

function verifyHistorical(vector, context) {
  const invalid = (reason) => ({ result: 'invalid', reason });
  if (Buffer.byteLength(vector.receipt, 'utf8') > profile.receipt.maxBytes) return invalid('malformed');
  let r;
  try {
    r = parseReceiptJson(vector.receipt);
  } catch {
    return invalid('malformed');
  }
  if (typeof r.type === 'string' && r.type !== profile.receipt.type) return invalid('unsupported_type');
  if (!wellFormed(r)) return invalid('malformed');

  // Evidence: an authentic document of the exact credential the receipt names.
  const named = vector.evidence.document ? authenticDocument(context.documents[vector.evidence.document].document, context.issuer) : null;
  if (!named || named.id !== r.receiver.credential) return invalid('evidence_missing');
  if (r.receiver.did !== named.did || r.proof.keyid !== named.keyId) return invalid('receiver_mismatch');
  const { value, ...proof } = r.proof;
  if (!strictVerify(new Uint8Array(Buffer.from(value, 'base64url')), jcs({ ...r, proof }), named.key)) return invalid('signature_invalid');
  const attempts = vector.attempts;
  if (attempts.length === 0) return invalid('binding_unverifiable');
  const attempt = attempts.find((a) => a.requestDigest === r.request.digest);
  if (!attempt || attempt.operation !== r.request.id || !equal(attempt.sender, r.request.sender) || !equal(attempt.receiver, r.receiver)) return invalid('binding');

  const t = Date.parse(r.issuedAt);
  const retained = vector.evidence.statusList ? retainedState(context.statusLists[vector.evidence.statusList].document, named, context.issuer) : null;
  return {
    result: 'valid',
    state: r.outcome.state,
    applies: r.outcome.applies,
    status: r.outcome.status,
    code: r.outcome.code,
    attempt: attempt.request,
    findings: {
      issuedAtWithinValidity: named.validFrom <= t && t < named.validUntil,
      retainedStatus: retained?.state ?? 'not_retained',
      retainedStatusPeriod: retained?.period ?? null,
      signingTime: 'receiver_claim',
    },
  };
}

// ---------------------------------------------------------------- receiver identity (D3, provisional)

// The syntax comes from schema/aria-ap-identity-1.json; the order and the rules are written here.
const STATEMENT = identitySchema.properties.statement;
const ORIGIN_RULES = STATEMENT.properties.origin.anyOf.map((a) => [new RegExp(a.pattern), new RegExp(a.not.pattern)]);
const CREATED = new RegExp(STATEMENT.properties.created.pattern);
const STATEMENT_NONCE = new RegExp(STATEMENT.properties.nonce.pattern);
const STATEMENT_CHALLENGE = new RegExp(STATEMENT.properties.challenge.pattern);

const hasExactly = (o, keys) =>
  typeof o === 'object' && o !== null && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

function canonicalOrigin(value) {
  if (typeof value !== 'string' || !ORIGIN_RULES.some(([re, not]) => re.test(value) && !not.test(value))) return false;
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
}

function seconds(value) {
  if (typeof value !== 'string' || !CREATED.test(value)) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) && new Date(t).toISOString() === value.replace('Z', '.000Z') ? t / 1000 : null;
}

// Unpadded base64url of exactly 64 bytes, spelled canonically.
function proofBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === 64 && bytes.toString('base64url') === value ? new Uint8Array(bytes) : null;
}

async function identify(vector, context) {
  const refused = (reason) => ({ result: 'refused', reason });
  const pin = { ...context.pin, ...vector.pin };
  const start = Date.parse(context.now) / 1000;
  const response = vector.response;
  const s = response?.statement;
  if (!hasExactly(response, ['credential', 'statement']) || !hasExactly(s, STATEMENT.required) || !hasExactly(s.proof, ['alg', 'keyid', 'value'])) {
    return refused('malformed');
  }
  const strings = STATEMENT.required.filter((k) => k !== 'proof');
  if (s.type !== STATEMENT.properties.type.const || strings.some((k) => typeof s[k] !== 'string')) return refused('malformed');
  if (!STATEMENT_NONCE.test(s.nonce) || !STATEMENT_CHALLENGE.test(s.challenge) || !canonicalOrigin(s.origin)) return refused('malformed');
  const created = seconds(s.created);
  if (created === null) return refused('malformed');

  // The credential verifier's part, from the views: the document verifies and is valid now.
  const view = context.credentials.find((c) => equal(c.document, response.credential));
  if (!view || Date.parse(view.validFrom) / 1000 > start + context.skewSeconds || Date.parse(view.validUntil) / 1000 <= start) return refused('credential');
  if (view.url !== s.credential || view.did !== s.subject) return refused('credential');
  if (s.subject !== pin.did) return refused('unexpected_receiver');
  if (!canonicalOrigin(pin.origin) || s.origin !== pin.origin) return refused('origin');
  if (s.audience !== context.expected.audience) return refused('audience');
  if (s.nonce !== context.expected.nonce) return refused('nonce');
  const fresh = (t) => created <= t + context.skewSeconds && t - created <= context.maxAgeSeconds;
  if (!fresh(start)) return refused('stale');
  const signature = proofBytes(s.proof.value);
  const { proof, ...unsigned } = s;
  const signed = jcs({ ...unsigned, proof: { alg: proof.alg, keyid: proof.keyid } });
  const key = holderKeyBytes(view.holderKey.publicKeyMultibase);
  if (proof.alg !== 'ed25519' || proof.keyid !== view.holderKey.id || !signature || !key || !strictVerify(signature, signed, key)) return refused('signature');
  if (view.status !== 'good') return refused('status');
  if (!fresh(start + (vector.timeline?.statusAfter ?? 0))) return refused('stale');
  return { result: 'authenticated', credential: view.url, keyid: view.holderKey.id, challenge: s.challenge };
}

// ---------------------------------------------------------------- scopes (D5, provisional)

const NEW_GRANT = /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$/;
const DOCUMENT_10 = new RegExp(aid10.properties.credentialSubject.properties.scope.items.pattern);
const POLICY_PATTERN = /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:([a-z][a-z0-9_]*|\*)$/;

const admitScope = (credentialScopes, required) => (credentialScopes.includes(required) ? 'allow' : 'aria.scope_missing');

function applyPolicy(rules, scope) {
  if (rules.some((r) => !POLICY_PATTERN.test(r.pattern) || !['allow', 'deny'].includes(r.effect))) return 'invalid_policy';
  const matches = (pattern) =>
    pattern.endsWith(':*') ? NEW_GRANT.test(scope) && scope.startsWith(pattern.slice(0, -1)) : pattern === scope;
  if (rules.some((r) => r.effect === 'deny' && matches(r.pattern))) return 'aria.scope_denied';
  return rules.some((r) => r.effect === 'allow' && matches(r.pattern)) ? 'allow' : 'aria.scope_denied';
}

// ---------------------------------------------------------------- run

const report = { sections: {}, failures: [] };
function record(section, id, ok, detail) {
  const s = (report.sections[section] ??= { passed: 0, failed: 0 });
  if (ok) s.passed++;
  else {
    s.failed++;
    report.failures.push({ section, id, ...detail });
  }
  if (verbose) console.log(`${ok ? 'ok  ' : 'FAIL'} ${section} ${id}`);
}

function mutateExpectation(expect) {
  const m = structuredClone(expect);
  if (m.result === 'authenticated') m.requestDigest = m.requestDigest.replace(/.(?==:$)/, (c) => (c === 'A' ? 'B' : 'A'));
  else if (m.result === 'refused') m.subtype = m.subtype === 'signature' ? 'window' : 'signature';
  else if (m.result === 'valid') m.state = m.state === 'completed' ? 'accepted' : 'completed';
  else m.reason = m.reason === 'malformed' ? 'binding' : 'malformed';
  return m;
}

function flipSignature(headers) {
  return headers.map(([n, v]) => {
    if (n !== 'signature') return [n, v];
    const bytes = Buffer.from(v.slice('aria=:'.length, -1), 'base64');
    bytes[40] ^= 0x01;
    return [n, `aria=:${bytes.toString('base64')}:`];
  });
}

// Requests
const requestResults = new Map();
for (const v of requests.vectors) {
  const got = await authenticate(v, requests.context);
  requestResults.set(v.id, got);
  record('requests', v.id, equal(got, v.expect), { expected: v.expect, got });
  record('controls: expectation mutated', v.id, !equal(got, mutateExpectation(v.expect)), { note: 'a mutated expectation still matched' });
  if (v.lenient) {
    const accepts = await lenientAccepts(v, requests.context, v.lenient);
    record('controls: lenient verifier accepts', v.id, accepts, { rule: v.lenient, note: 'the vector does not separate strict from lenient' });
  }
  if (v.expect.result === 'authenticated') {
    const tampered = { ...v, request: { ...v.request, headers: flipSignature(v.request.headers) } };
    const t = await authenticate(tampered, requests.context);
    record('controls: signature bit flipped', v.id, equal(t, authFailed('signature')), { got: t });
  }
}

// Fingerprints
for (const c of fingerprints.cases) {
  const got = sha256Field(jcs(c.input));
  record('fingerprints', c.id, got === c.fingerprint, { expected: c.fingerprint, got });
}
const fp = Object.fromEntries(fingerprints.cases.map((c) => [c.id, sha256Field(jcs(c.input))]));
for (const r of fingerprints.relations) record('fingerprints: relations', `${r.a}/${r.b}`, (fp[r.a] === fp[r.b]) === r.same, { why: r.why });
for (const r of fingerprints.requestRelations) {
  const a = requestResults.get(r.a)?.fingerprint;
  const b = requestResults.get(r.b)?.fingerprint;
  record('fingerprints: request relations', `${r.a}/${r.b}`, Boolean(a && b) && (a === b) === r.same, { why: r.why });
}
for (const r of fingerprints.requestCases) {
  record('fingerprints: request cases', `${r.request}=${r.case}`, requestResults.get(r.request)?.fingerprint === fp[r.case], {});
}

// Receipts
for (const v of receipts.vectors) {
  const got = verifyReceipt(v);
  record('receipts', v.id, equal(got, v.expect), { expected: v.expect, got });
  record('controls: expectation mutated', v.id, !equal(got, mutateExpectation(v.expect)), { note: 'a mutated expectation still matched' });
  if (v.expect.result === 'valid') {
    const parsed = JSON.parse(v.receipt);
    const sig = Buffer.from(parsed.proof.value, 'base64url');
    sig[40] ^= 0x01;
    parsed.proof.value = sig.toString('base64url');
    const t = verifyReceipt({ ...v, receipt: JSON.stringify(parsed) });
    record('controls: signature bit flipped', v.id, equal(t, { result: 'invalid', reason: 'signature_invalid' }), { got: t });
  }
}

// Historical receipts: the evidence first, then each receipt.
for (const [name, d] of Object.entries(historical.context.documents)) {
  const got = authenticDocument(d.document, historical.context.issuer) !== null;
  record('historical: evidence', `document ${name}`, got === d.authentic, { expected: d.authentic, got });
}
{
  const r1 = authenticDocument(historical.context.documents.r1.document, historical.context.issuer);
  for (const [name, l] of Object.entries(historical.context.statusLists)) {
    const got = retainedState(l.document, r1, historical.context.issuer);
    record('historical: evidence', `list ${name}`, l.read.state ? got?.state === l.read.state : got === null, { expected: l.read, got });
  }
}
for (const v of historical.vectors) {
  const got = verifyHistorical(v, historical.context);
  record('historical', v.id, equal(got, v.expect), { expected: v.expect, got });
  record('controls: expectation mutated', v.id, !equal(got, mutateExpectation(v.expect)), { note: 'a mutated expectation still matched' });
  if (v.expect.result === 'valid') {
    const parsed = JSON.parse(v.receipt);
    const sig = Buffer.from(parsed.proof.value, 'base64url');
    sig[40] ^= 0x01;
    parsed.proof.value = sig.toString('base64url');
    const t = verifyHistorical({ ...v, receipt: JSON.stringify(parsed) }, historical.context);
    record('controls: signature bit flipped', v.id, equal(t, { result: 'invalid', reason: 'signature_invalid' }), { got: t });
  }
}

// Receiver identity
for (const v of identity.vectors) {
  const got = await identify(v, identity.context);
  record('identity', v.id, equal(got, v.expect), { expected: v.expect, got });
  const mutated = v.expect.result === 'authenticated' ? { ...v.expect, challenge: `${v.expect.challenge}x` } : { ...v.expect, reason: v.expect.reason === 'stale' ? 'signature' : 'stale' };
  record('controls: expectation mutated', v.id, !equal(got, mutated), { note: 'a mutated expectation still matched' });
  if (v.expect.result === 'authenticated') {
    const t = structuredClone(v);
    const sig = Buffer.from(t.response.statement.proof.value, 'base64url');
    sig[40] ^= 0x01;
    t.response.statement.proof.value = sig.toString('base64url');
    const got2 = await identify(t, identity.context);
    record('controls: signature bit flipped', v.id, equal(got2, { result: 'refused', reason: 'signature' }), { got: got2 });
  }
}

// Scopes
for (const g of scopes.grants) {
  const got = { newGrant: NEW_GRANT.test(g.value), document10: DOCUMENT_10.test(g.value) };
  record('scopes: grammar', g.value, got.newGrant === g.newGrant && got.document10 === g.document10, { expected: g, got });
}
for (const a of scopes.admission) {
  const got = admitScope(a.credentialScopes, a.required);
  record('scopes: admission', a.id, got === a.expect, { expected: a.expect, got });
}
for (const p of scopes.policy) {
  const got = applyPolicy(p.rules, p.scope);
  record('scopes: policy', p.id, got === p.expect, { expected: p.expect, got });
}

// Sequences, then every model mutant must be caught by at least one sequence.
for (const s of sequences.sequences) {
  const failures = await runSequence(s, (o) => createReference(o));
  record('sequences', s.id, failures.length === 0, { failures });
}
for (const mutant of MUTANTS) {
  const caughtBy = [];
  for (const s of sequences.sequences) {
    if ((await runSequence(s, (o) => createReference({ ...o, mutant }))).length > 0) caughtBy.push(s.id);
  }
  record('controls: model mutants detected', mutant, caughtBy.length > 0, { caughtBy });
  report.sections['controls: model mutants detected'].caught = {
    ...(report.sections['controls: model mutants detected'].caught ?? {}),
    [mutant]: caughtBy,
  };
}

let failed = 0;
for (const [name, s] of Object.entries(report.sections)) {
  failed += s.failed;
  console.log(`${s.failed ? 'FAIL' : 'ok  '} ${name}: ${s.passed} passed, ${s.failed} failed`);
}
for (const f of report.failures) console.log(`\n${f.section} ${f.id}\n${JSON.stringify(f, null, 2)}`);
if (reportPath) writeFileSync(reportPath, `${JSON.stringify({ status: profile.status, ...report }, null, 2)}\n`);
console.log(failed ? `\n${failed} failure(s)` : '\nall vectors, sequences and controls hold');
process.exit(failed ? 1 : 0);
