import type { Produced, StatusEvidence } from '@aria-registry/sdk';
import type { AttemptRefusal, OperationKey } from './operations';
import type { VerifiedPresentation } from './presentation';

/**
 * A human's approval, from the receiver's own approval system, of exactly this
 * operation by this caller. No portable approval format exists in profile 1.
 */
export interface ApprovalEvidence {
  readonly approvalId: string;
  readonly sender: string;
  readonly credentialId: string;
  readonly operationId: string;
  readonly fingerprint: string;
  /** RFC 3339; judged when admission runs. */
  readonly expiresAt: string;
}

/** The application's own decision on the resource: who may do what to which account. */
export type ResourceAuthorizer = (request: {
  readonly presentation: VerifiedPresentation;
}) => Promise<{ readonly allowed: true } | { readonly allowed: false; readonly code: string }>;

/**
 * One rule of the receiver's scope policy (D5, provisional). `pattern` is a scope of
 * three segments, or two followed by `:*` for any third. A matching deny wins;
 * otherwise a matching allow is needed.
 */
export interface ScopeRule {
  readonly effect: 'allow' | 'deny';
  readonly pattern: string;
}

export interface AdmissionInput {
  /** Required: there is no admission without proof of the holder key. */
  readonly presentation: VerifiedPresentation;
  /**
   * Status evidence of the presentation's exact credential, from the credential
   * verifier this instance was created with. Read through its `standing`, never
   * from its fields: a copy, a hand-made object or another verifier's evidence is refused.
   */
  readonly status: StatusEvidence;
  readonly approval?: ApprovalEvidence;
  /**
   * The receiver's policy over the operation's scope, judged after the credential's
   * own scopes: a scope it does not admit is `aria.scope_denied`. Kept with the admission.
   */
  readonly scopePolicy?: readonly ScopeRule[];
  readonly authorize: ResourceAuthorizer;
}

/** Fixed reasons of an authenticated refusal. */
export type AdmissionReason =
  | 'audience_mismatch'
  | 'credential_expired'
  | 'credential_revoked'
  | 'credential_superseded'
  | 'level_insufficient'
  | 'scope_missing'
  | 'scope_denied'
  | 'approval_required'
  | 'approval_invalid'
  | 'delegation_unsupported'
  /** The resource authorizer refused; its namespaced code travels with it. */
  | 'forbidden';

/**
 * The single admission outcome. Only `allow` lets an operation be claimed and
 * run; there is no mode in which a failed check becomes `allow`. A receiver
 * observing in monitor mode may log `deny`, but what it then runs is not admitted.
 */
export type Admission =
  | (Produced<'admission'> & { readonly decision: 'allow'; readonly presentation: VerifiedPresentation })
  | (Produced<'admission'> & {
      readonly decision: 'deny';
      readonly reason: AdmissionReason;
      /** The receiver's code for `forbidden`, e.g. `bank.account_not_granted`. */
      readonly code?: string;
      /** Signable refusal of this attempt; the operation is not claimed. */
      readonly refusal: AttemptRefusal;
    })
  | (Produced<'admission'> & {
      readonly decision: 'indeterminate';
      /** Required evidence could not be established, e.g. status unavailable or stale. */
      readonly reason: 'status_unavailable';
      readonly refusal: AttemptRefusal;
    });

export type Admitted = Extract<Admission, { decision: 'allow' }>;

export interface LookupInput {
  /** A verified retrieval: the signed lookup of one operation. */
  readonly presentation: VerifiedPresentation;
  /** Status evidence of its exact credential, from the same credential verifier. */
  readonly status: StatusEvidence;
}

/**
 * Whether a retrieval may read an operation's receipts: a credential of the
 * operation's sender DID that stands now (provisional, D4). A revoked, superseded
 * or expired credential reads nothing; the refusal is an unsigned problem, since a
 * retrieval gets no receipt of its own.
 */
export type LookupAdmission =
  | (Produced<'lookup'> & { readonly decision: 'allow'; readonly key: OperationKey })
  | {
      readonly decision: 'deny';
      readonly status: 403 | 503;
      readonly code: 'aria.audience_mismatch' | 'aria.credential_expired' | 'aria.credential_revoked' | 'aria.credential_superseded' | 'aria.status_unavailable';
    };
