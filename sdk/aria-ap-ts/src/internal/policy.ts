import type { AdmissionReason, ScopeRule } from '../admission';
import { TRUST_LEVELS, type CredentialFacts, type Standing, type TrustLevel } from '@trustlayer-foundation/aria-sdk';
import type { MissingApproval } from '../presentation';
import { scopeAllowed } from './scope-policy';

/** An approval as the receiver's approval system supplied it, already copied. */
export interface ApprovalSnapshot {
  readonly sender: string;
  readonly credentialId: string;
  readonly operationId: string;
  readonly fingerprint: string;
  readonly expiresAt: number;
}

export interface PolicyInput {
  /** From the credential verifier's `facts`: never read from a result's view. */
  readonly credential: CredentialFacts;
  /** From the credential verifier's `standing`, judged for this admission. */
  readonly standing: Standing;
  /** Whether the presentation named this receiver in its signed audience. */
  readonly audienceMatches: boolean;
  readonly operation: { readonly scope: string; readonly minLevel: TrustLevel; readonly onMissingApproval: MissingApproval };
  readonly operationId: string | null;
  readonly fingerprint: string;
  readonly approval: ApprovalSnapshot | null;
  /** The receiver's scope policy, already checked; `null` when it has none. */
  readonly scopePolicy: readonly ScopeRule[] | null;
  /** The instant the standing was judged; approvals expire against the same clock. */
  readonly now: number;
}

export type PolicyOutcome =
  | { readonly decision: 'allow' }
  | { readonly decision: 'deny'; readonly reason: AdmissionReason }
  | { readonly decision: 'indeterminate'; readonly reason: 'status_unavailable' };

/**
 * The admission rules after authentication, in their fixed order. Pure: the
 * credential's standing (validity, status, freshness) is the credential
 * verifier's judgment; level, scope, delegation and approval are judged here.
 * The public `admit` calls this only with a verified presentation.
 */
export function evaluate(input: PolicyInput): PolicyOutcome {
  const { credential, standing } = input;
  if (!input.audienceMatches) return { decision: 'deny', reason: 'audience_mismatch' };

  switch (standing.state) {
    case 'not_valid_now':
      return { decision: 'deny', reason: 'credential_expired' };
    case 'unknown':
      return { decision: 'indeterminate', reason: 'status_unavailable' };
    case 'revoked':
      return { decision: 'deny', reason: 'credential_revoked' };
    case 'superseded':
      return { decision: 'deny', reason: 'credential_superseded' };
    case 'good':
      break;
  }

  if (TRUST_LEVELS.indexOf(credential.trustLevel) < TRUST_LEVELS.indexOf(input.operation.minLevel)) return { decision: 'deny', reason: 'level_insufficient' };
  if (!credential.scopes.includes(input.operation.scope)) return { decision: 'deny', reason: 'scope_missing' };
  if (input.scopePolicy && !scopeAllowed(input.scopePolicy, input.operation.scope)) return { decision: 'deny', reason: 'scope_denied' };
  if (credential.delegationDepth !== 0) return { decision: 'deny', reason: 'delegation_unsupported' };

  if (credential.hitlRequired.includes(input.operation.scope)) {
    const a = input.approval;
    if (!a) return { decision: 'deny', reason: 'approval_required' };
    if (
      a.sender !== credential.did ||
      a.credentialId !== credential.binding.credentialId ||
      a.operationId !== input.operationId ||
      a.fingerprint !== input.fingerprint ||
      a.expiresAt <= input.now
    ) {
      return { decision: 'deny', reason: 'approval_invalid' };
    }
  }
  return { decision: 'allow' };
}
