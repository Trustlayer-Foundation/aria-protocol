import type { StatusEvidence } from '@aria-registry/sdk';
import type { Internals, PresentationSnapshot } from './instance';
import { evaluate, type ApprovalSnapshot, type PolicyOutcome } from './policy';

/**
 * The admission rules applied now: the credential's standing judged again from the
 * same status evidence, approval expiry at that instant, and the presentation's
 * deadline. An admission is judged when it is made and again when it is used.
 */
export function judge(internals: Internals, p: PresentationSnapshot, status: StatusEvidence, approval: ApprovalSnapshot | null): PolicyOutcome | { readonly decision: 'expired' } {
  if (internals.now() > p.expiresAt) return { decision: 'expired' };
  const standing = internals.credentials.standing(p.credential, status);
  const d = p.descriptor;
  return evaluate({
    credential: internals.credentials.facts(p.credential),
    standing,
    audienceMatches: p.audience === p.receiverDid,
    operation: { scope: d.scope!, minLevel: d.minLevel!, onMissingApproval: d.onMissingApproval ?? 'refuse' },
    operationId: p.operationId,
    fingerprint: p.fingerprint!,
    approval,
    now: Date.parse(standing.judgedAt),
  });
}

/** The signed attempt refusal for a denied or indeterminate outcome. */
export function refusalFor(outcome: Exclude<PolicyOutcome, { decision: 'allow' }>, code?: string): { readonly status: 403 | 503; readonly code: string } {
  if (outcome.decision === 'indeterminate') return { status: 503, code: 'aria.status_unavailable' };
  return { status: 403, code: code ?? `aria.${outcome.reason}` };
}

/** A lookup's answer for a standing that is not good, or `null` when it stands. */
export function lookupRefusal(state: 'good' | 'not_valid_now' | 'revoked' | 'superseded' | 'unknown'): { readonly status: 403 | 503; readonly code: 'aria.credential_expired' | 'aria.credential_revoked' | 'aria.credential_superseded' | 'aria.status_unavailable' } | null {
  switch (state) {
    case 'good':
      return null;
    case 'not_valid_now':
      return { status: 403, code: 'aria.credential_expired' };
    case 'revoked':
      return { status: 403, code: 'aria.credential_revoked' };
    case 'superseded':
      return { status: 403, code: 'aria.credential_superseded' };
    case 'unknown':
      return { status: 503, code: 'aria.status_unavailable' };
  }
}
