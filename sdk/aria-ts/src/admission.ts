import type { issued } from './internal';
import type { AttemptRefusal } from './operations';
import type { VerifiedPresentation } from './presentation';
import type { StatusEvidence } from './status';

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
  readonly expiresAt: Date;
}

/** The application's own decision on the resource: who may do what to which account. */
export type ResourceAuthorizer = (request: {
  readonly presentation: VerifiedPresentation;
}) => Promise<{ readonly allowed: true } | { readonly allowed: false; readonly code: string }>;

export interface AdmissionInput {
  /** Required: there is no admission without proof of the holder key. */
  readonly presentation: VerifiedPresentation;
  /** Status evidence of the presentation's exact credential. */
  readonly status: StatusEvidence;
  readonly approval?: ApprovalEvidence;
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
  | { readonly [issued]: 'admission'; readonly decision: 'allow'; readonly presentation: VerifiedPresentation; readonly approval?: ApprovalEvidence }
  | {
      readonly [issued]: 'admission';
      readonly decision: 'deny';
      readonly reason: AdmissionReason;
      /** The receiver's code for `forbidden`, e.g. `bank.account_not_granted`. */
      readonly code?: string;
      /** Signable refusal of this attempt; the operation is not claimed. */
      readonly refusal: AttemptRefusal;
      /** Set for `approval_required` under `hold`: what the receiver's approval workflow needs. */
      readonly approvalRequest?: { readonly operationId: string; readonly fingerprint: string };
    }
  | {
      readonly [issued]: 'admission';
      readonly decision: 'indeterminate';
      /** Required evidence could not be established, e.g. status unavailable or stale. */
      readonly reason: 'status_unavailable';
      readonly refusal: AttemptRefusal;
    };

export type Admitted = Extract<Admission, { decision: 'allow' }>;
