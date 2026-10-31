// S1 regressions whose decision belongs to admission (ARIA AP), now reached only
// through the credential verifier's trust interface: `facts` and `standing` of
// results it produced, judged when admission runs. Their credential-layer halves
// stay in credential.test.ts and provenance.test.ts.
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier, type StatusEvidence, type VerifiedCredential } from '../src';
import { evaluate, type PolicyInput } from '../src/internal/policy';
import { credential, fakeFetch, HOUR, LIST_URL, newIssuer, NOW, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const signed = sign(credential(), issuer);

function setup(revoked: number[] | null) {
  let t = NOW;
  const v = createVerifier({
    trust: [profile(issuer)],
    clock: () => new Date(t),
    ...(revoked ? { fetch: { allowedOrigins: ['https://status.example.test'], fetch: fakeFetch({ [LIST_URL]: statusList(issuer, revoked) }) } } : {}),
  });
  const verify = (): VerifiedCredential => {
    const r = v.verifyCredential(signed);
    if (!r.ok) throw new Error(r.reason);
    return r.credential;
  };
  return { v, verify, at: (ms: number) => (t = ms) };
}

/** What admission does with a credential result and status evidence: read both through the verifier, then apply the rules. */
function decide(v: ReturnType<typeof setup>['v'], c: VerifiedCredential, status: StatusEvidence, scope = 'data:documents:read') {
  const standing = v.standing(c, status);
  const input: PolicyInput = {
    credential: v.facts(c),
    standing,
    audienceMatches: true,
    operation: { scope, minLevel: 'L0', onMissingApproval: 'refuse' },
    operationId: 'op-1',
    fingerprint: 'fp-1',
    approval: null,
    now: Date.parse(standing.judgedAt),
  };
  return evaluate(input);
}

describe('former defects, refused at admission', () => {
  it('a failed requested scope is a denial, not a valid result', async () => {
    const { v, verify } = setup([]);
    const c = verify();
    expect(decide(v, c, await v.checkStatus(c), 'banking:payment:execute')).toEqual({ decision: 'deny', reason: 'scope_missing' });
  });

  it('a revoked status is refused, however recent the check', async () => {
    const { v, verify } = setup([7]);
    const c = verify();
    expect(decide(v, c, await v.checkStatus(c))).toEqual({ decision: 'deny', reason: 'credential_revoked' });
  });
});

describe('each result at its own layer', () => {
  it('offline verification succeeds with status unknown, and an admission that needs status is indeterminate', async () => {
    const { v, verify } = setup(null);
    const c = verify();
    expect(decide(v, c, await v.checkStatus(c))).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
  });

  it('a copied, authentic credential verifies as a document, and cannot be admitted without its holder key', async () => {
    const { v, verify } = setup(null);
    const c = verify();
    const status = await v.checkStatus(c);
    // No presentation exists without the holder's signature; nothing else is accepted in its place.
    await expect(v.admit({ presentation: c as never, status, authorize: async () => ({ allowed: true }) })).rejects.toBeInstanceOf(AriaUsageError);
  });
});

describe('time-sensitive evidence is judged when it is used', () => {
  it('a credential verified earlier is expired at admission time', async () => {
    const { v, verify, at } = setup([]);
    const c = verify();
    const status = await v.checkStatus(c);
    at(Date.parse(c.validUntil) + 1);
    expect(decide(v, c, status)).toEqual({ decision: 'deny', reason: 'credential_expired' });
  });

  it('status evidence that was fresh is stale later, and status of another document is no evidence', async () => {
    const { v, verify, at } = setup([]);
    const c = verify();
    const status = await v.checkStatus(c);
    expect(decide(v, c, status)).toEqual({ decision: 'allow' });
    expect(decide(v, verify(), status)).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
    at(NOW + 2 * HOUR);
    expect(decide(v, c, status)).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
  });
});

describe('nothing reaches the rules except through the verifier', () => {
  it('a copied, hand-made or foreign credential or status is refused before any rule runs', async () => {
    const { v, verify } = setup([]);
    const c = verify();
    const status = await v.checkStatus(c);
    const other = setup([]);
    const foreignCredential = other.verify();
    const foreignStatus = await other.v.checkStatus(foreignCredential);
    expect(() => decide(v, { ...c, scopes: ['banking:payment:execute'] } as VerifiedCredential, status)).toThrow(AriaUsageError);
    expect(() => decide(v, foreignCredential, foreignStatus)).toThrow(AriaUsageError);
    expect(() => decide(v, c, foreignStatus)).toThrow(AriaUsageError);
    expect(() => decide(v, c, { ...status, state: 'active' } as StatusEvidence)).toThrow(AriaUsageError);
  });
});
