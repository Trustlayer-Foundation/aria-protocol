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

/**
 * The credential's own bit in the signed list it names, read only after the list
 * verifies under the same issuer and is that exact list, in the supported profile
 * (one revocation bit per entry). Times are judged once the list is processed.
 */
export async function fromStatusList(credential: CredentialSnapshot, context: StatusContext): Promise<StatusSnapshot> {
  const { bounds } = context;
  if (!bounds) return unavailable('status-list', credential, 'offline', context.now());
  const fetched = await boundedGet(credential.statusList, bounds);
  if (!fetched.ok) return unavailable('status-list', credential, fetched.reason, context.now());
  const list = json(fetched.body);
  if (!list) return unavailable('status-list', credential, 'malformed', context.now());

  const profile = credential.profile;
  const proof = list.proof as Record<string, unknown> | undefined;
  const types = list.type;
  if (list.issuer !== profile.issuer) return unavailable('status-list', credential, 'wrong_issuer', context.now());
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
    return unavailable('status-list', credential, 'malformed', context.now());
  }
  if (!verifyComposite(list, proof.proofValue, profile.keys)) return unavailable('status-list', credential, 'signature_invalid', context.now());

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
    return unavailable('status-list', credential, 'malformed', context.now());
  }
  const packed = fromBase64url(encoded.slice(1));
  const bits = packed && (await gunzipBounded(packed, MAX_LIST_BYTES));
  if (!bits || bits.length < MIN_LIST_BYTES || credential.statusIndex >= bits.length * 8) {
    return unavailable('status-list', credential, 'malformed', context.now());
  }

  // Judged now, after retrieval, signature and decompression: a list may have expired meanwhile.
  const now = context.now();
  const validFrom = instant(list.validFrom);
  const validUntil = instant(list.validUntil);
  if (validFrom === null || validUntil === null || validUntil <= validFrom || validUntil - validFrom > MAX_LIST_VALIDITY_MS) {
    return unavailable('status-list', credential, 'not_valid_now', now);
  }
  if (validFrom > now + context.skewMs || validUntil <= now) return unavailable('status-list', credential, 'not_valid_now', now);
  if (now - validFrom > context.maxAgeMs) return unavailable('status-list', credential, 'stale', now);

  const revoked = ((bits[credential.statusIndex >> 3]! >> (7 - (credential.statusIndex & 7))) & 1) === 1;
  return {
    source: 'status-list',
    state: revoked ? 'revoked' : 'active',
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
    !CREDENTIAL_REFERENCE.test(answer.credentialId) ||
    (answer.status !== 'active' && answer.status !== 'revoked')
  ) {
    return unavailable('online', credential, 'malformed', now);
  }
  if (answer.credentialId !== credential.credentialId) {
    return { source: 'online', state: 'superseded', credential, currentCredentialId: answer.credentialId, fetchedAt: now };
  }
  return { source: 'online', state: answer.status, credential, currentCredentialId: null, fetchedAt: now };
}

/** An exact credential document reference: an https URL with a path. */
const CREDENTIAL_REFERENCE = /^https:\/\/[^\s/?#]+\/[^\s?#]+$/;
