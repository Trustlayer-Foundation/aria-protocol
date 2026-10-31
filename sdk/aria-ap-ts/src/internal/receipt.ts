import { canonicalJson, type Did } from '@aria-registry/sdk';
import type { Receipt, SentAttempt } from '../receipt';
import type { Signer } from '../types';
import { DIGEST, fromBase64url, instantOf, toBase64url, utf8, UUID } from './bytes';
import { strictVerify } from './ed25519';

// The receipt `aria-ap-receipt/1` (provisional, D4): a closed data model, signed
// over its ARIA canonical JSON without `proof.value`, so `alg` and `keyid` are signed.

export const RECEIPT_TYPE = 'aria-ap-receipt/1';
export const MAX_RECEIPT_BYTES = 4096;

/** The protocol's reason registry: HTTP status, whether the answer is signed, and what a signed one applies to. */
export const REASONS: Readonly<Record<string, { readonly http: number | readonly number[]; readonly signed: boolean; readonly applies?: 'attempt' | 'operation' }>> = Object.freeze({
  'aria.request_invalid': { http: 400, signed: false },
  'aria.authentication_failed': { http: 401, signed: false },
  'aria.audience_mismatch': { http: 403, signed: true, applies: 'attempt' },
  'aria.credential_expired': { http: 403, signed: true, applies: 'attempt' },
  'aria.credential_revoked': { http: 403, signed: true, applies: 'attempt' },
  'aria.credential_superseded': { http: 403, signed: true, applies: 'attempt' },
  'aria.level_insufficient': { http: 403, signed: true, applies: 'attempt' },
  'aria.scope_missing': { http: 403, signed: true, applies: 'attempt' },
  'aria.scope_denied': { http: 403, signed: true, applies: 'attempt' },
  'aria.intent_mismatch': { http: 403, signed: true, applies: 'attempt' },
  'aria.approval_required': { http: 403, signed: true, applies: 'attempt' },
  'aria.approval_invalid': { http: 403, signed: true, applies: 'attempt' },
  'aria.delegation_unsupported': { http: 403, signed: true, applies: 'attempt' },
  'aria.idempotency_conflict': { http: 409, signed: true, applies: 'attempt' },
  'aria.operation_in_progress': { http: 409, signed: true, applies: 'attempt' },
  'aria.status_unavailable': { http: 503, signed: true, applies: 'attempt' },
  'aria.rate_limited': { http: 429, signed: false },
  'aria.operation_unknown': { http: 404, signed: false },
  'aria.accepted': { http: 202, signed: true, applies: 'operation' },
  'aria.completed': { http: [200, 201], signed: true, applies: 'operation' },
});

/** A receiver's own code: `<namespace>.<name>`, never in the `aria` namespace. */
export const isReceiverCode = (code: string): boolean => /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(code) && !code.startsWith('aria.');

class Malformed extends Error {}

/** JSON restricted to the receipt data model: objects, strings and safe integers; ASCII alphabetic keys; no duplicate keys. */
export function parseReceiptText(text: string): Record<string, unknown> {
  let i = 0;
  const fail = (): never => {
    throw new Malformed();
  };
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i]!)) i++;
  };
  const string = (): string => {
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text.charCodeAt(i) < 0x20) fail();
      i += text[i] === '\\' ? 2 : 1;
    }
    if (text[i] !== '"') fail();
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const integer = (): number => {
    const m = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i));
    if (!m) return fail();
    i += m[0].length;
    if (text[i] === '.' || text[i] === 'e' || text[i] === 'E') fail();
    const n = Number(m[0]);
    return Number.isSafeInteger(n) ? n : fail();
  };
  const object = (): Record<string, unknown> => {
    i++;
    const out: Record<string, unknown> = {};
    ws();
    if (text[i] === '}') {
      i++;
      return out;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') fail();
      const k = string();
      if (!/^[A-Za-z]+$/.test(k) || Object.hasOwn(out, k)) fail();
      ws();
      if (text[i++] !== ':') fail();
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
      fail();
    }
  };
  const value = (): unknown => {
    ws();
    if (text[i] === '{') return object();
    if (text[i] === '"') return string();
    if (text[i] === '-' || (text[i]! >= '0' && text[i]! <= '9')) return integer();
    return fail();
  };
  const out = value();
  ws();
  if (i !== text.length || typeof out !== 'object' || out === null) fail();
  return out as Record<string, unknown>;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const members = (o: unknown, required: readonly string[], optional: readonly string[] = []): o is Record<string, unknown> =>
  isObject(o) && required.every((k) => Object.hasOwn(o, k)) && Object.keys(o).every((k) => required.includes(k) || optional.includes(k));

function httpsUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.href === value && !u.search && !u.hash && !u.username && !u.password;
  } catch {
    return false;
  }
}

const party = (p: unknown): boolean => members(p, ['did', 'credential']) && typeof p.did === 'string' && p.did.startsWith('did:aria:') && httpsUrl(p.credential);

/** The outcome's state, `applies`, status and code agree with the registry. */
export function outcomeConsistent(o: unknown): boolean {
  if (!members(o, ['state', 'applies', 'status', 'code'], ['result'])) return false;
  if (typeof o.code !== 'string' || !Number.isInteger(o.status)) return false;
  if (o.result !== undefined && !(members(o.result, ['digest']) && typeof o.result.digest === 'string' && DIGEST.test(o.result.digest))) return false;
  const reason = REASONS[o.code];
  if (o.state === 'completed') return o.applies === 'operation' && o.code === 'aria.completed' && (o.status === 200 || o.status === 201);
  if (o.state === 'accepted') return o.applies === 'operation' && o.code === 'aria.accepted' && o.status === 202;
  if (o.state !== 'rejected') return false;
  if (o.applies === 'operation') return isReceiverCode(o.code) && o.status === 422;
  if (o.applies === 'attempt') return (reason?.signed === true && reason.applies === 'attempt' && reason.http === o.status) || (isReceiverCode(o.code) && o.status === 403);
  return false;
}

export function wellFormed(r: Record<string, unknown>): r is Record<string, unknown> & Receipt {
  const req = r.request as Record<string, unknown>;
  const proof = r.proof as Record<string, unknown>;
  return (
    members(r, ['type', 'id', 'request', 'receiver', 'issuedAt', 'outcome', 'proof']) &&
    typeof r.id === 'string' &&
    r.id.startsWith('urn:uuid:') &&
    UUID.test(r.id.slice('urn:uuid:'.length)) &&
    members(req, ['id', 'sender', 'digest']) &&
    typeof req.id === 'string' &&
    UUID.test(req.id) &&
    r.id !== `urn:uuid:${req.id}` &&
    party(req.sender) &&
    typeof req.digest === 'string' &&
    DIGEST.test(req.digest) &&
    party(r.receiver) &&
    instantOf(r.issuedAt) !== null &&
    outcomeConsistent(r.outcome) &&
    members(proof, ['alg', 'keyid', 'value']) &&
    proof.alg === 'ed25519' &&
    typeof proof.keyid === 'string' &&
    typeof proof.value === 'string' &&
    /^[A-Za-z0-9_-]{86}$/.test(proof.value)
  );
}

/** The signed bytes: the canonical JSON of the receipt with `proof.value` removed. */
function payload(r: Omit<Receipt, 'proof'> & { proof: { alg: string; keyid: string } }): Uint8Array {
  return utf8(canonicalJson({ ...r, proof: { alg: r.proof.alg, keyid: r.proof.keyid } }));
}

export async function signReceipt(unsigned: Omit<Receipt, 'proof'>, signer: Signer): Promise<Receipt> {
  const proof = { alg: 'ed25519' as const, keyid: signer.keyId };
  const signature = await signer.sign(payload({ ...unsigned, proof }));
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new TypeError('an Ed25519 signer returns 64 bytes');
  const receipt: Receipt = { ...unsigned, proof: { ...proof, value: toBase64url(signature) } };
  if (!wellFormed(receipt as unknown as Record<string, unknown>)) throw new TypeError('the receipt does not fit aria-ap-receipt/1');
  return receipt;
}

/** The receiver a receipt must come from: its exact credential instance and holder key. */
export interface ReceiverKey {
  readonly did: Did;
  readonly credentialId: string;
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export type ReceiptFailure =
  | 'malformed'
  | 'unsupported_type'
  | 'receiver_mismatch'
  | 'signature_invalid'
  | 'binding'
  | 'binding_unverifiable'
  | 'status_mismatch'
  | 'not_operation';

export type ReceiptMode = { readonly mode: 'decision'; readonly transportStatus: number } | { readonly mode: 'retrieval'; readonly transportStatus?: number };

export type Checked = { readonly ok: true; readonly receipt: Receipt; readonly attempt: SentAttempt } | { readonly ok: false; readonly reason: ReceiptFailure };

/** Parses a receipt from its JSON text, or from an object through the same rules. */
export function readReceipt(input: unknown): { ok: true; receipt: Record<string, unknown> } | { ok: false; reason: 'malformed' | 'unsupported_type' } {
  let text: string;
  try {
    text = typeof input === 'string' ? input : JSON.stringify(input);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (typeof text !== 'string' || utf8(text).length > MAX_RECEIPT_BYTES) return { ok: false, reason: 'malformed' };
  let r: Record<string, unknown>;
  try {
    r = parseReceiptText(text);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (typeof r.type === 'string' && r.type !== RECEIPT_TYPE) return { ok: false, reason: 'unsupported_type' };
  if (!wellFormed(r)) return { ok: false, reason: 'malformed' };
  return { ok: true, receipt: r };
}

const sameParty = (a: { did: string; credential: string }, b: { did: string; credential: string }): boolean => a.did === b.did && a.credential === b.credential;

/**
 * Checks a receipt in the profile's order: data model, type, form; the exact
 * receiver instance; the signature; then the kept attempt its digest selects, and
 * every binding against it; then the transport status for the mode.
 */
export function checkReceipt(input: unknown, receiver: ReceiverKey, attempts: readonly SentAttempt[], mode: ReceiptMode): Checked {
  const read = readReceipt(input);
  if (!read.ok) return read;
  const r = read.receipt as unknown as Receipt;
  if (r.receiver.did !== receiver.did || r.receiver.credential !== receiver.credentialId || r.proof.keyid !== receiver.keyId) return { ok: false, reason: 'receiver_mismatch' };
  const signature = fromBase64url(r.proof.value);
  if (!signature || !strictVerify(signature, payload(r), receiver.publicKey)) return { ok: false, reason: 'signature_invalid' };
  if (attempts.length === 0) return { ok: false, reason: 'binding_unverifiable' };
  const attempt = attempts.find((a) => a.requestDigest === r.request.digest);
  if (!attempt || attempt.operationId !== r.request.id || !sameParty(attempt.sender, r.request.sender) || !sameParty(attempt.receiver, r.receiver)) {
    return { ok: false, reason: 'binding' };
  }
  if (mode.mode === 'decision' && mode.transportStatus !== r.outcome.status) return { ok: false, reason: 'status_mismatch' };
  if (mode.mode === 'retrieval') {
    if (mode.transportStatus !== undefined && mode.transportStatus !== 200) return { ok: false, reason: 'status_mismatch' };
    if (r.outcome.applies !== 'operation') return { ok: false, reason: 'not_operation' };
  }
  return { ok: true, receipt: r, attempt };
}
