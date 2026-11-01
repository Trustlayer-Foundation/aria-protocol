import { canonicalJson } from '@aria-registry/sdk';
import type { ReceiverIdentityFailure } from '../agent';
import type { ReceiverPin } from '../receipt';
import { fromBase64url, instantOf, isProfileOrigin, utf8 } from './bytes';
import { strictVerify } from './ed25519';
import { PROFILE } from './request';

// The receiver identity statement `aria-ap-identity/1` (provisional, D3), checked in
// its fixed order. Credential verification and status are the caller's, through
// `verify` and `stands`, so the same rules run over the credential verifier and over
// the AP1 vectors' verified views.

export const IDENTITY_TYPE = 'aria-ap-identity/1';
export const STATEMENT_MAX_AGE_MS = 60_000;
export const NONCE = /^[A-Za-z0-9_-]{22,128}$/;
export const CHALLENGE = /^[A-Za-z0-9._~+/=-]{8,256}$/;

const KEYS = ['type', 'subject', 'credential', 'origin', 'audience', 'nonce', 'challenge', 'created', 'proof'];
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const exactly = (o: unknown, keys: readonly string[]): o is Record<string, unknown> => isObject(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

export interface IdentityHolder {
  readonly credentialId: string;
  readonly did: string;
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface IdentityDeps<T> {
  readonly now: () => number;
  /** The statement's credential document, verified under the trusted issuers; `null` when it does not verify. */
  readonly verify: (document: unknown) => { readonly holder: IdentityHolder; readonly handle: T } | null;
  /** Establishes the verified credential's status and says whether it stands now; may take time. */
  readonly stands: (handle: T) => Promise<boolean>;
}

export type IdentityChecked<T> =
  | { readonly ok: true; readonly handle: T; readonly holder: IdentityHolder; readonly challenge: string; readonly created: number }
  | { readonly ok: false; readonly reason: ReceiverIdentityFailure };

export async function checkIdentity<T>(response: unknown, pin: ReceiverPin, expected: { readonly nonce: string; readonly audience: string }, deps: IdentityDeps<T>): Promise<IdentityChecked<T>> {
  const fail = (reason: ReceiverIdentityFailure): IdentityChecked<T> => ({ ok: false, reason });
  const s = isObject(response) ? response.statement : undefined;
  if (!exactly(response, ['credential', 'statement']) || !exactly(s, KEYS) || !exactly(s.proof, ['alg', 'keyid', 'value'])) return fail('malformed');
  if (s.type !== IDENTITY_TYPE || KEYS.slice(1, -1).some((k) => typeof s[k] !== 'string') || !CHALLENGE.test(s.challenge as string) || !NONCE.test(s.nonce as string) || !isProfileOrigin(s.origin)) return fail('malformed');
  const proof = s.proof as Record<string, unknown>;
  const created = instantOf(s.created);
  if (created === null) return fail('malformed');

  const verified = deps.verify(response.credential);
  if (!verified) return fail('credential');
  const { holder } = verified;
  if (holder.credentialId !== s.credential || holder.did !== s.subject) return fail('credential');
  if (s.subject !== pin.did) return fail('unexpected_receiver');
  // A pin outside the origin rule matches no statement.
  if (!isProfileOrigin(pin.origin) || s.origin !== pin.origin) return fail('origin');
  if (s.audience !== expected.audience) return fail('audience');
  if (s.nonce !== expected.nonce) return fail('nonce');
  const t = deps.now();
  if (created > t + PROFILE.skewSeconds * 1000 || t - created > STATEMENT_MAX_AGE_MS) return fail('stale');
  const signature = typeof proof.value === 'string' ? fromBase64url(proof.value) : null;
  const { proof: _, ...unsigned } = s;
  const bytes = utf8(canonicalJson({ ...unsigned, proof: { alg: proof.alg, keyid: proof.keyid } }));
  if (proof.alg !== 'ed25519' || proof.keyid !== holder.keyId || !signature || !strictVerify(signature, bytes, holder.publicKey)) return fail('signature');
  if (!(await deps.stands(verified.handle))) return fail('status');
  // Establishing status took time: the statement, and the challenge it carries, must still be fresh.
  if (deps.now() - created > STATEMENT_MAX_AGE_MS) return fail('stale');
  return { ok: true, handle: verified.handle, holder, challenge: s.challenge as string, created };
}
