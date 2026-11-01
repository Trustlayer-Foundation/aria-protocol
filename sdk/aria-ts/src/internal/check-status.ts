import type { StatusUnavailable } from '../status';
import { SUITE, verifyComposite } from './composite';
import { fromBase64url } from './encoding';
import { boundedGet, gunzipBounded, type Bounds } from './fetch';
import { instant } from './instant';
import type { CredentialSnapshot } from './verify-credential';

/** Status evidence as the verifier holds it. */
export type StatusSnapshot =
  | {
      readonly source: 'status-list';
      readonly state: 'active' | 'revoked';
      readonly credential: CredentialSnapshot;
      readonly list: { readonly url: string; readonly index: number; readonly validFrom: number; readonly validUntil: number };
      readonly fetchedAt: number;
    }
  | {
      readonly source: 'online';
      readonly state: 'active' | 'revoked' | 'superseded';
      readonly credential: CredentialSnapshot;
      readonly currentCredentialId: string | null;
      readonly fetchedAt: number;
    }
  | {
      readonly source: 'status-list' | 'online';
      readonly state: 'unavailable';
      readonly credential: CredentialSnapshot;
      readonly reason: StatusUnavailable;
      readonly fetchedAt: number;
    };

/** The longest validity a status list may state: 24 hours, re-signed hourly (owner decision of 2026-10-02). */
export const MAX_LIST_VALIDITY_MS = 24 * 3_600_000;
const MIN_LIST_BYTES = 131_072 / 8;
const MAX_LIST_BYTES = 2 * 1024 * 1024;

export interface StatusContext {
  readonly bounds: Bounds | null;
  /** The verifier's clock, read when the evidence is complete, not when the request started. */
  readonly now: () => number;
  readonly skewMs: number;
  readonly maxAgeMs: number;
}

const unavailable = (source: 'status-list' | 'online', credential: CredentialSnapshot, reason: StatusUnavailable, fetchedAt: number): StatusSnapshot => ({
  source,
  state: 'unavailable',
  credential,
  reason,
  fetchedAt,
});

function json(body: Uint8Array): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export type ListReading =
  | { readonly ok: true; readonly revoked: boolean; readonly validFrom: number; readonly validUntil: number }
  | { readonly ok: false; readonly reason: 'malformed' | 'signature_invalid' | 'wrong_issuer' | 'invalid_validity' };

/**
 * The credential's own bit in `list`, read only after the list verifies under the
 * same issuer and is the exact list the credential names, in the supported profile
 * (one revocation bit per entry). Its validity bounds are checked as data; whether
 * they hold now is the caller's judgment.
 */
export async function readList(credential: CredentialSnapshot, list: Record<string, unknown>): Promise<ListReading> {
  const profile = credential.profile;
  const proof = list.proof as Record<string, unknown> | undefined;
  const types = list.type;
  if (list.issuer !== profile.issuer) return { ok: false, reason: 'wrong_issuer' };
  if (
    // Another genuine list of the same issuer is not this credential's list.
    list.id !== credential.statusList ||
    !Array.isArray(types) ||
    !types.includes('VerifiableCredential') ||
    !types.includes('BitstringStatusListCredential') ||
    !proof ||
    proof.type !== 'DataIntegrityProof' ||
    proof.cryptosuite !== SUITE ||
    proof.proofPurpose !== 'assertionMethod' ||
    proof.verificationMethod !== profile.verificationMethod ||
    typeof proof.proofValue !== 'string'
  ) {
    return { ok: false, reason: 'malformed' };
  }
  if (!verifyComposite(list, proof.proofValue, profile.keys)) return { ok: false, reason: 'signature_invalid' };

  // The supported subject: a revocation list of one bit per entry, as W3C Bitstring Status List defines by default.
  const subject = list.credentialSubject as Record<string, unknown> | undefined;
  const encoded = subject?.encodedList;
  if (
    !subject ||
    subject.type !== 'BitstringStatusList' ||
    subject.statusPurpose !== 'revocation' ||
    (subject.statusSize !== undefined && subject.statusSize !== 1) ||
    typeof encoded !== 'string' ||
    !encoded.startsWith('u')
  ) {
    return { ok: false, reason: 'malformed' };
  }
  const packed = fromBase64url(encoded.slice(1));
  const bits = packed && (await gunzipBounded(packed, MAX_LIST_BYTES));
  if (!bits || bits.length < MIN_LIST_BYTES || credential.statusIndex >= bits.length * 8) return { ok: false, reason: 'malformed' };

  const validFrom = instant(list.validFrom);
  const validUntil = instant(list.validUntil);
  if (validFrom === null || validUntil === null || validUntil <= validFrom || validUntil - validFrom > MAX_LIST_VALIDITY_MS) return { ok: false, reason: 'invalid_validity' };
  const revoked = ((bits[credential.statusIndex >> 3]! >> (7 - (credential.statusIndex & 7))) & 1) === 1;
  return { ok: true, revoked, validFrom, validUntil };
}

/**
 * The credential's status from the signed list it names, fetched now. Times are
 * judged once the list is processed.
 */
export async function fromStatusList(credential: CredentialSnapshot, context: StatusContext): Promise<StatusSnapshot> {
  const { bounds } = context;
  if (!bounds) return unavailable('status-list', credential, 'offline', context.now());
  const fetched = await boundedGet(credential.statusList, bounds);
  if (!fetched.ok) return unavailable('status-list', credential, fetched.reason, context.now());
  const list = json(fetched.body);
  if (!list) return unavailable('status-list', credential, 'malformed', context.now());
  const read = await readList(credential, list);

  // Judged now, after retrieval, signature and decompression: a list may have expired meanwhile.
  const now = context.now();
  if (!read.ok) return unavailable('status-list', credential, read.reason === 'invalid_validity' ? 'not_valid_now' : read.reason, now);
  const { validFrom, validUntil } = read;
  if (validFrom > now + context.skewMs || validUntil <= now) return unavailable('status-list', credential, 'not_valid_now', now);
  if (now - validFrom > context.maxAgeMs) return unavailable('status-list', credential, 'stale', now);
  return {
    source: 'status-list',
    state: read.revoked ? 'revoked' : 'active',
    credential,
    list: { url: credential.statusList, index: credential.statusIndex, validFrom, validUntil },
    fetchedAt: now,
  };
}

/**
 * The issuer's online answer for the DID's current credential. An answer naming
 * another document makes the presented one `superseded`; the answer carries no
 * signed time.
 */
export async function fromOnline(credential: CredentialSnapshot, context: StatusContext): Promise<StatusSnapshot> {
  const { bounds } = context;
  const endpoint = credential.profile.onlineStatus;
  if (!endpoint) return unavailable('online', credential, 'no_online_endpoint', context.now());
  if (!bounds) return unavailable('online', credential, 'offline', context.now());
  const fetched = await boundedGet(`${endpoint}${credential.did}`, bounds);
  // The time the answer was observed, not when it was requested.
  const now = context.now();
  if (!fetched.ok) return unavailable('online', credential, fetched.reason, now);
  const answer = json(fetched.body);
  // A complete answer first: the DID, an exact document reference and a status. Only then can another reference mean superseded.
  if (
    !answer ||
    answer.did !== credential.did ||
    typeof answer.credentialId !== 'string' ||
    !isCredentialReference(answer.credentialId) ||
    (answer.status !== 'active' && answer.status !== 'revoked')
  ) {
    return unavailable('online', credential, 'malformed', now);
  }
  if (answer.credentialId !== credential.credentialId) {
    return { source: 'online', state: 'superseded', credential, currentCredentialId: answer.credentialId, fetchedAt: now };
  }
  return { source: 'online', state: answer.status, credential, currentCredentialId: null, fetchedAt: now };
}

/**
 * An exact credential document reference: an absolute https URL that the URL
 * parser accepts, with a host and a path, no query, fragment or credentials, and
 * already in its serialized form. Compared afterwards as the exact string.
 */
function isCredentialReference(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname !== '' && url.pathname.length > 1 && !url.search && !url.hash && !url.username && !url.password && url.href === value;
  } catch {
    return false;
  }
}
