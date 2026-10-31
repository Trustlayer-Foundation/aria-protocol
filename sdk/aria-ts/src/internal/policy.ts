import type { AdmissionReason } from '../admission';
import type { MissingApproval } from '../presentation';
import type { TrustLevel } from '../types';
import type { StatusSnapshot } from './check-status';
import { LEVELS, type CredentialSnapshot } from './verify-credential';

/** An approval as the receiver's approval system supplied it, already copied. */
export interface ApprovalSnapshot {
  readonly sender: string;
  readonly credentialId: string;
  readonly operationId: string;
  readonly fingerprint: string;
  readonly expiresAt: number;
}

export interface PolicyInput {
  readonly credential: CredentialSnapshot;
  readonly status: StatusSnapshot;
  /** Whether the presentation named this receiver in its signed audience. */
  readonly audienceMatches: boolean;
  readonly operation: { readonly scope: string; readonly minLevel: TrustLevel; readonly onMissingApproval: MissingApproval };
  readonly operationId: string | null;
  readonly fingerprint: string;
  readonly approval: ApprovalSnapshot | null;
  readonly now: number;
  readonly skewMs: number;
  readonly statusMaxAgeMs: number;
  readonly onlineMaxAgeMs: number;
}

export type PolicyOutcome =
  | { readonly decision: 'allow' }
  | { readonly decision: 'deny'; readonly reason: AdmissionReason }
  | { readonly decision: 'indeterminate'; readonly reason: 'status_unavailable' };

/**
 * The admission rules after authentication, in their fixed order. Pure: every
 * time-sensitive input is judged at `now`, not when it was obtained. The public
 * `admit` calls this only with a verified presentation; nothing here runs without one.
 */
export function evaluate(input: PolicyInput): PolicyOutcome {
  const { credential, status, now } = input;
  if (!input.audienceMatches) return { decision: 'deny', reason: 'audience_mismatch' };
  if (credential.validUntil <= now || credential.validFrom > now + input.skewMs) return { decision: 'deny', reason: 'credential_expired' };

  // Status of this exact document, still fresh now.
  if (status.credential !== credential) return { decision: 'indeterminate', reason: 'status_unavailable' };
  if (status.state === 'unavailable') return { decision: 'indeterminate', reason: 'status_unavailable' };
  if (status.source === 'status-list') {
    if (status.list.validUntil <= now || now - status.list.validFrom > input.statusMaxAgeMs) return { decision: 'indeterminate', reason: 'status_unavailable' };
  } else if (now - status.fetchedAt > input.onlineMaxAgeMs) {
    return { decision: 'indeterminate', reason: 'status_unavailable' };
  }
  if (status.state === 'revoked') return { decision: 'deny', reason: 'credential_revoked' };
  if (status.state === 'superseded') return { decision: 'deny', reason: 'credential_superseded' };

  if (LEVELS.indexOf(credential.trustLevel) < LEVELS.indexOf(input.operation.minLevel)) return { decision: 'deny', reason: 'level_insufficient' };
  if (!credential.scopes.includes(input.operation.scope)) return { decision: 'deny', reason: 'scope_missing' };
  if (credential.delegationDepth !== 0) return { decision: 'deny', reason: 'delegation_unsupported' };

  if (credential.hitlRequired.includes(input.operation.scope)) {
    const a = input.approval;
    if (!a) return { decision: 'deny', reason: 'approval_required' };
    if (
      a.sender !== credential.did ||
      a.credentialId !== credential.credentialId ||
      a.operationId !== input.operationId ||
      a.fingerprint !== input.fingerprint ||
      a.expiresAt <= now
    ) {
      return { decision: 'deny', reason: 'approval_invalid' };
    }
  }
  return { decision: 'allow' };
}
