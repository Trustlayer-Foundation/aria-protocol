import type { StandingState } from '../status';
import type { StatusSnapshot } from './check-status';
import type { CredentialSnapshot } from './verify-credential';

export interface StandingRules {
  readonly now: number;
  readonly skewMs: number;
  readonly statusMaxAgeMs: number;
  readonly onlineMaxAgeMs: number;
}

/**
 * Whether one exact credential stands at `now`, in a fixed order: its signed
 * validity, then status evidence about that same verified result, its
 * availability and freshness, then its state. Pure; judged at every call.
 */
export function judge(credential: CredentialSnapshot, status: StatusSnapshot, rules: StandingRules): StandingState {
  const { now } = rules;
  if (credential.validUntil <= now || credential.validFrom > now + rules.skewMs) return { state: 'not_valid_now' };
  if (status.credential !== credential) return { state: 'unknown', reason: 'other_document' };
  if (status.state === 'unavailable') return { state: 'unknown', reason: 'unavailable' };
  if (status.source === 'status-list') {
    if (status.list.validUntil <= now || now - status.list.validFrom > rules.statusMaxAgeMs) return { state: 'unknown', reason: 'stale' };
  } else if (now - status.fetchedAt > rules.onlineMaxAgeMs) {
    return { state: 'unknown', reason: 'stale' };
  }
  if (status.state === 'revoked') return { state: 'revoked' };
  if (status.state === 'superseded') return { state: 'superseded' };
  return { state: 'good', source: status.source };
}
