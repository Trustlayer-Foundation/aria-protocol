// The admission rules the public `admit` applies after authentication (AP2 wires
// them to a verified presentation; nothing reaches them without one).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createVerifier } from '../src';
import { evaluate, type PolicyInput } from '../src/internal/policy';
import { recall } from '../src/internal/provenance';
import type { CredentialSnapshot } from '../src/internal/verify-credential';
import { credential, DID, HOUR, LIST_URL, newIssuer, NOW, profile, sign } from './fixtures';

const issuer = newIssuer();
const v = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW) });
const r = v.verifyCredential(sign(credential(), issuer));
if (!r.ok) throw new Error(r.reason);
const snapshot = recall<CredentialSnapshot>(v, 'credential', r.credential);
const active = { source: 'status-list' as const, state: 'active' as const, credential: snapshot, list: { url: LIST_URL, index: 7, validFrom: NOW - 60_000, validUntil: NOW + HOUR }, fetchedAt: NOW };

const base: PolicyInput = {
  credential: snapshot,
  status: active,
  audienceMatches: true,
  operation: { scope: 'data:documents:read', minLevel: 'L0', onMissingApproval: 'refuse' },
  operationId: 'op-1',
  fingerprint: 'fp-1',
  approval: null,
  now: NOW,
  skewMs: 5000,
  statusMaxAgeMs: HOUR,
  onlineMaxAgeMs: 60_000,
};
const approval = { sender: DID, credentialId: snapshot.credentialId, operationId: 'op-1', fingerprint: 'fp-1', expiresAt: NOW + 60_000 };
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

  it('never allows on unavailable, stale or online evidence past its age', () => {
    expect(evaluate({ ...base, status: { source: 'status-list', state: 'unavailable', credential: snapshot, reason: 'fetch_failed', fetchedAt: NOW } })).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
    expect(evaluate({ ...base, now: NOW + HOUR })).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
    const online = { source: 'online' as const, state: 'active' as const, credential: snapshot, currentCredentialId: null, fetchedAt: NOW - 120_000 };
    expect(evaluate({ ...base, status: online })).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
    expect(evaluate({ ...base, status: { ...online, state: 'superseded', currentCredentialId: 'x', fetchedAt: NOW } })).toEqual({ decision: 'deny', reason: 'credential_superseded' });
  });

  it('needs an approval bound to this caller, document, operation and content when the scope requires a human', () => {
    expect(evaluate({ ...base, operation: transfer })).toEqual({ decision: 'deny', reason: 'approval_required' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, operationId: 'op-2' } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, fingerprint: 'fp-2' } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval: { ...approval, expiresAt: NOW } })).toEqual({ decision: 'deny', reason: 'approval_invalid' });
    expect(evaluate({ ...base, operation: transfer, approval })).toEqual({ decision: 'allow' });
  });

  it('refuses delegation, which profile 1 does not support', () => {
    const delegated = { ...snapshot, delegationDepth: 1 };
    expect(evaluate({ ...base, credential: delegated, status: { ...active, credential: delegated } })).toEqual({ decision: 'deny', reason: 'delegation_unsupported' });
  });
});

describe('the embedded schema', () => {
  it('is byte-identical to the protocol’s schema/aid-1.0.json', () => {
    const embedded = readFileSync(new URL('../src/internal/aid-1.0.schema.json', import.meta.url));
    const normative = readFileSync(new URL('../../../schema/aid-1.0.json', import.meta.url));
    expect(embedded.equals(normative)).toBe(true);
  });
});
