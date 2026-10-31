import type { Produced } from './credential';
import type { CredentialBinding } from './types';

/** Why the status of a credential could not be established. */
export type StatusUnavailable =
  /** No fetch policy: the verifier is offline. */
  | 'offline'
  /** The trust profile names no online status endpoint. */
  | 'no_online_endpoint'
  | 'origin_not_allowed'
  | 'fetch_failed'
  | 'too_large'
  | 'malformed'
  | 'signature_invalid'
  | 'wrong_issuer'
  /** Outside its signed validity, or a validity window longer than 24 hours. */
  | 'not_valid_now'
  /** The signed list is older than the verifier's maximum age, counted from its own `validFrom`. */
  | 'stale';

interface StatusBase extends Produced<'status'> {
  readonly kind: 'status-evidence';
  /** The exact document this evidence is about. */
  readonly credential: CredentialBinding;
  /** Local time the evidence was obtained (RFC 3339). Fetching an old list does not make it new. */
  readonly fetchedAt: string;
}

/**
 * Status of one exact credential. Only the signed list carries signed times; an
 * online answer carries none and is only as strong as TLS to the configured
 * endpoint. `superseded` comes only from an online answer that names another
 * current document: a revocation bit cannot say why.
 */
export type StatusEvidence =
  | (StatusBase & {
      readonly source: 'status-list';
      readonly state: 'active' | 'revoked';
      readonly list: { readonly url: string; readonly index: number; readonly validFrom: string; readonly validUntil: string };
    })
  | (StatusBase & {
      readonly source: 'online';
      readonly state: 'active' | 'revoked' | 'superseded';
      /** The current document, when the answer names another one. */
      readonly currentCredentialId?: string;
    })
  | (StatusBase & {
      readonly source: 'status-list' | 'online';
      readonly state: 'unavailable';
      readonly reason: StatusUnavailable;
    });

/** The judgment itself, without its time. */
export type StandingState =
  | { readonly state: 'good'; readonly source: 'status-list' | 'online' }
  /** Outside its signed validity at the moment judged: expired, or not yet valid. */
  | { readonly state: 'not_valid_now' }
  | { readonly state: 'revoked' }
  | { readonly state: 'superseded' }
  | {
      readonly state: 'unknown';
      /** No evidence, evidence past its validity or maximum age, or evidence about another verified result. */
      readonly reason: 'unavailable' | 'stale' | 'other_document';
    };

/**
 * Whether one exact credential stands now, from `Verifier.standing`: judged at
 * the call under the verifier's own clock and freshness rules. A judgment, not
 * evidence: no entry point of this SDK or of ARIA AP accepts it as input.
 */
export type Standing = StandingState & {
  readonly kind: 'standing';
  /** When it was judged (RFC 3339, the verifier's clock). */
  readonly judgedAt: string;
};

export interface StatusOptions {
  /** `status-list` (default) tells the issuer nothing about which credential is checked. */
  readonly via?: 'status-list' | 'online';
}
