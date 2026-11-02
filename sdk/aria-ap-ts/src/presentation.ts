import type { Did, Produced, TrustLevel, VerifiedCredential } from '@trustlayer-foundation/aria-sdk';
import type { Signer } from './types';

/**
 * The request classes of the ARIA AP HTTP profile. Each fixes which components
 * the request signature must cover; anything outside them is refused.
 */
export type RequestClass =
  /** POST, PUT or PATCH with a body: method, target, `content-type`, `content-digest`, `aria-operation`, credential, audience. */
  | 'unsafe-body'
  /** DELETE, or POST/PATCH without a body: as above with the digest of empty content and no `content-type`. */
  | 'unsafe-empty'
  /** A GET the receiver answers with a receipt: method, target with its full query, `aria-operation`, credential, audience. */
  | 'safe-receiptable'
  /** A signed lookup of an earlier operation (`?operation=<id>`). It returns stored receipts and gets none of its own. */
  | 'retrieval';

/**
 * What happens when a scope needs a human's approval and the request has none:
 * this attempt is refused and a later attempt carrying an approval can proceed.
 * Holding the operation for an approval workflow is deferred, not decided: it
 * needs decision D8 and its continuation contract before the SDK offers it.
 */
export type MissingApproval = 'refuse';

/**
 * One operation a receiver offers. It is the closed list of what may vary: any
 * input that changes dispatch, the resource, the business meaning or a
 * precondition is listed here, signed and part of the operation's fingerprint;
 * anything else is refused, never interpreted.
 */
export interface OperationDescriptor {
  readonly name: string;
  readonly class: RequestClass;
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Exact path; `{name}` matches one segment. */
  readonly path: string;
  /** The one media type a body may have (`unsafe-body` only); another is refused before the operation is claimed. */
  readonly mediaType?: string;
  /** Query parameters the operation accepts; a retrieval takes exactly `operation`. */
  readonly query?: readonly string[];
  /** Further headers that change meaning (e.g. `if-match`); signed and fingerprinted. */
  readonly semanticHeaders?: readonly string[];
  /** The grant the operation needs, exactly. Required on every class but `retrieval`. */
  readonly scope?: string;
  /** Required on every class but `retrieval`. */
  readonly minLevel?: TrustLevel;
  /** Approval policy when the credential lists `scope` in `hitlRequired`. */
  readonly onMissingApproval?: MissingApproval;
}

/** The receiver's own identity, as it serves it. */
export interface ReceiverSelf {
  readonly did: Did;
  /** The origin it is reached at; requests signed for another origin fail. */
  readonly origin: string;
  /** Its own verified credential, from the credential verifier the instance was created with. */
  readonly credential: VerifiedCredential;
  /** That credential's document, served in its identity statement; its canonical digest must be the credential's. */
  readonly document: unknown;
  /** Its holder key, whose `keyId` is the credential's `holderKey.id`. */
  readonly signer: Signer;
}

/** Single-use, short-lived challenges, stored by the adopter. `consume` must be atomic across its instances. */
export interface ChallengeStore {
  issue(audience: Did, ttlSeconds: number): Promise<string>;
  /** Whether `challenge` is live for `audience`, without consuming it. */
  live(challenge: string, audience: Did): Promise<boolean>;
  /** True once for a live challenge issued to `audience`; false afterwards and for anything else. */
  consume(challenge: string, audience: Did): Promise<boolean>;
}

/** Why a request is not well formed (400, `aria.request_invalid`). */
export type RequestInvalidReason = 'method' | 'target' | 'operation_unknown' | 'body' | 'media_type' | 'query' | 'operation_id';

/** Why a request is not authenticated (401, `aria.authentication_failed`, with this subtype). */
export type AuthenticationReason = 'signature' | 'window' | 'digest' | 'challenge' | 'unsigned_operation' | 'credential';

/**
 * A request whose signature verifies under the holder key of an exact verified
 * credential, bound to this receiver, this operation and this content. Not yet
 * admitted: audience, status, level, scope and approval come next.
 */
export interface VerifiedPresentation extends Produced<'presentation'> {
  readonly kind: 'verified-presentation';
  readonly credential: VerifiedCredential;
  readonly operation: OperationDescriptor;
  /** The signed `aria-operation`; `null` for a retrieval, whose target is `lookupOf`. */
  readonly operationId: string | null;
  readonly lookupOf: string | null;
  /** The receiver the request names in `aria-audience`, checked at admission. */
  readonly audience: string;
  /** SHA-256 of the logical content (class, method, path, query, media type, semantic headers, content digest); `null` for a retrieval. */
  readonly fingerprint: string | null;
  /** SHA-256 of this attempt's RFC 9421 signature base. */
  readonly requestDigest: string;
}

/** Failures are unsigned: nothing is attributed to a DID that did not prove its key. */
export type PresentationResult =
  | { readonly ok: true; readonly presentation: VerifiedPresentation }
  | { readonly ok: false; readonly status: 400; readonly code: 'aria.request_invalid'; readonly reason: RequestInvalidReason }
  | { readonly ok: false; readonly status: 401; readonly code: 'aria.authentication_failed'; readonly reason: AuthenticationReason };

export interface PresentationContext {
  readonly receiver: { readonly did: Did; readonly origin: string };
  readonly operations: readonly OperationDescriptor[];
  readonly challenges: ChallengeStore;
  /**
   * The document of the credential a request names by URL, from wherever the
   * adopter keeps or fetches credentials (bounded: allowed origins, size, time);
   * `null` when unknown. ARIA AP verifies it with its credential verifier and
   * requires its exact URL and digest.
   */
  readonly resolveCredential: (url: string) => Promise<unknown>;
}
