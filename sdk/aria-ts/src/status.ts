import type { issued } from './internal';
import type { CredentialBinding } from './types';

/** Why the status of a credential could not be established. */
export type StatusUnavailable =
  | 'offline'
  | 'origin_not_allowed'
  | 'fetch_failed'
  | 'too_large'
  | 'malformed'
  | 'signature_invalid'
  | 'wrong_issuer'
  | 'not_valid_now'
  /** The signed list is older than the verifier's maximum age, counted from its own `validFrom`. */
  | 'stale';

interface StatusBase {
  readonly [issued]: 'status';
  /** The exact document this evidence is about. */
  readonly credential: CredentialBinding;
  /** Local time the evidence was obtained. Fetching an old list does not make it new. */
  readonly fetchedAt: Date;
}

/**
 * Status of one exact credential. Only the signed list carries signed times;
 * an online answer carries none. `superseded` comes only from an online answer
 * that names another current document: a revocation bit cannot say why.
 */
export type StatusEvidence =
  | (StatusBase & {
      readonly source: 'status-list';
      readonly state: 'active' | 'revoked';
      readonly list: {
        readonly url: string;
        readonly index: number;
        readonly validFrom: Date;
        readonly validUntil: Date;
      };
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

export interface StatusOptions {
  /** `status-list` (default) reveals nothing about which credential is asked for. */
  readonly via?: 'status-list' | 'online';
}
