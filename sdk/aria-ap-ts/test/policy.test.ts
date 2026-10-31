// The admission rules ARIA AP applies after authentication, over the credential
// verifier's `facts` and `standing` (AP2 wires them to a verified presentation;
// nothing reaches them without one).
import { describe, expect, it } from 'vitest';
import { createVerifier, type Standing } from '@aria-registry/sdk';
import { evaluate, type PolicyInput } from '../src/internal/policy';
import { credential, DID, newIssuer, NOW, profile, sign } from './fixtures';

const issuer = newIssuer();
const v = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW) });
const r = v.verifyCredential(sign(credential(), issuer));
if (!r.ok) throw new Error(r.reason);
const facts = v.facts(r.credential);
const judgedAt = '2026-11-01T12:00:00Z';
const good: Standing = { kind: 'standing', state: 'good', source: 'status-list', judgedAt };

const base: PolicyInput = {
  credential: facts,
  standing: good,
  audienceMatches: true,
  operation: { scope: 'data:documents:read', minLevel: 'L0', onMissingApproval: 'refuse' },
  operationId: 'op-1',
  fingerprint: 'fp-1',
  approval: null,
  now: NOW,
};
const approval = { sender: DID, credentialId: facts.binding.credentialId, operationId: 'op-1', fingerprint: 'fp-1', expiresAt: NOW + 60_000 };
const transfer = { scope: 'payments:transfer:create', minLevel: 'L0' as const, onMissingApproval: 'refuse' as const };

describe('admission rules, in order', () => {
  it('allows only when every check passes', () => {
    expect(evaluate(base)).toEqual({ decision: 'allow' });
  });

  it('refuses another receiver, a level or a scope the credential lacks', () => {
    expect(evaluate({ ...base, audienceMatches: false })).toEqual({ decision: 'deny', reason: 'audience_mismatch' });
    expect(evaluate({ ...base, operation: { ...base.operation, minLevel: 'L1' } })).toEqual({ decision: 'deny', reason: 'level_insufficient' });
    expect(evaluate({ ...base, operation: { ...base.operation, scope: 'data:documents:write' } })).toEqual({ decision: 'deny', reason: 'scope_missing' });
  });

  it('takes validity and status from the credential verifier’s standing, and never allows unless it is good', () => {
    const judged = (s: Partial<Standing>) => ({ ...base, standing: { ...good, ...s } as Standing });
    expect(evaluate(judged({ state: 'not_valid_now' }))).toEqual({ decision: 'deny', reason: 'credential_expired' });
    expect(evaluate(judged({ state: 'revoked' }))).toEqual({ decision: 'deny', reason: 'credential_revoked' });
    expect(evaluate(judged({ state: 'superseded' }))).toEqual({ decision: 'deny', reason: 'credential_superseded' });
    for (const reason of ['unavailable', 'stale', 'other_document'] as const) {
      expect(evaluate(judged({ state: 'unknown', reason }))).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
    }
  });

  it('keeps the order: audience before standing, standing before level and scope', () => {
    const revoked = { ...good, state: 'revoked' } as Standing;
    expect(evaluate({ ...base, audienceMatches: false, standing: revoked })).toEqual({ decision: 'deny', reason: 'audience_mismatch' });
    expect(evaluate({ ...base, standing: revoked, operation: { ...base.operation, minLevel: 'L3' } })).toEqual({ decision: 'deny', reason: 'credential_revoked' });
  });

  it('needs an approval bound to this caller, document, operation and content when the scope requires a human', () => {
    expect(evaluate({ ...base, operation: transfer })).toEqual({ decision: 'deny', reason: 'approval_required' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, operationId: 'op-2' } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, fingerprint: 'fp-2' } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, credentialId: 'https://api.aria.bar/v1/credentials/other' } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, expiresAt: NOW } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval })).toEqual({ decision: 'allow' });
  });

  it('refuses delegation, which profile 1 does not support', () => {
    expect(evaluate({ ...base, credential: { ...facts, delegationDepth: 1 } })).toEqual({ decision: 'deny', reason: 'delegation_unsupported' });
  });
});
