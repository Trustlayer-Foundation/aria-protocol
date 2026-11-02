// AP1 scope vectors (D5), each against its owner: the AID 1.0 pattern
// through the credential verifier, exact admission and the receiver's policy through
// ARIA AP. The new-grant grammar is issuance's (C2); here only its reuse in policy patterns.
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier } from '@trustlayer-foundation/aria-sdk';
import { scopeAllowed, scopePolicyOf } from '../src/internal/scope-policy';
import { evaluate, type PolicyInput } from '../src/internal/policy';
import { credential, newIssuer, NOW, profile, sign } from './fixtures';
import { load } from './conformance';
import { world } from './world';

const scopes = load('vectors/scopes.json');
const issuer = newIssuer();
const verifier = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW) });

function verifiedWith(scope: string[]) {
  const doc = credential();
  doc.credentialSubject.scope = scope;
  doc.credentialSubject.hitlRequired = [];
  return verifier.verifyCredential(sign(doc, issuer));
}

function policyAnswer(rules: unknown, scope: string): string {
  let policy;
  try {
    policy = scopePolicyOf(rules);
  } catch (e) {
    if (e instanceof AriaUsageError) return 'invalid_policy';
    throw e;
  }
  return scopeAllowed(policy!, scope) ? 'allow' : 'aria.scope_denied';
}

describe('AP1 scope grammar', () => {
  for (const g of scopes.grants) {
    it(`${g.value}: readable in a signed 1.0 document ${g.document10 ? 'yes' : 'no'}, through the credential verifier`, () => {
      const r = verifiedWith([g.value]);
      expect(r.ok).toBe(g.document10);
    });
    it(`${g.value}: an exact policy pattern ${g.newGrant ? 'yes' : 'no'}, as a new grant`, () => {
      const exact = !g.value.endsWith(':*') && policyAnswer([{ effect: 'allow', pattern: g.value }], g.value) === 'allow';
      expect(exact).toBe(g.newGrant);
    });
  }
});

describe('AP1 scope admission: credential scopes compare exactly', () => {
  for (const a of scopes.admission) {
    it(`${a.id}`, () => {
      const r = verifiedWith(a.credentialScopes);
      if (!r.ok) throw new Error(r.reason);
      const input: PolicyInput = {
        credential: verifier.facts(r.credential),
        standing: { kind: 'standing', state: 'good', source: 'status-list', judgedAt: new Date(NOW).toISOString() },
        audienceMatches: true,
        operation: { scope: a.required, minLevel: 'L0', onMissingApproval: 'refuse' },
        operationId: 'op-1',
        fingerprint: 'fp-1',
        approval: null,
        scopePolicy: null,
        now: NOW,
      };
      const out = evaluate(input);
      expect(out.decision === 'allow' ? 'allow' : `aria.${(out as { reason: string }).reason}`).toBe(a.expect);
    });
  }
});

describe('AP1 receiver scope policy', () => {
  for (const p of scopes.policy) {
    it(`${p.id}`, () => {
      expect(policyAnswer(p.rules, p.scope)).toBe(p.expect);
    });
  }
});

describe('the scope policy at admission, through the public API', () => {
  async function presented(w: ReturnType<typeof world>) {
    const id = randomUUID();
    const p = await w.bankAp.verifyPresentation((await w.signTransfer(id)).request, w.context);
    if (!p.ok) throw new Error(p.reason);
    return { presentation: p.presentation, status: await w.bankVerifier.checkStatus(p.presentation.credential) };
  }
  const authorize = async () => ({ allowed: true as const });

  it('a matching deny wins over an allow: a signed aria.scope_denied refusal of the attempt', async () => {
    const w = world();
    const a = await w.bankAp.admit({
      ...(await presented(w)),
      scopePolicy: [{ effect: 'allow', pattern: 'payments:transfer:*' }, { effect: 'deny', pattern: 'payments:transfer:create' }],
      authorize,
    });
    if (a.decision !== 'deny') throw new Error('expected deny');
    expect(a.reason).toBe('scope_denied');
    expect(a.refusal.code).toBe('aria.scope_denied');
    const receipt = await w.bankAp.buildAttemptRefusal(a.refusal, w.self);
    expect(receipt.outcome).toMatchObject({ state: 'rejected', applies: 'attempt', code: 'aria.scope_denied' });
  });

  it('a policy that allows the scope admits; without a policy nothing changes', async () => {
    const w = world();
    expect((await w.bankAp.admit({ ...(await presented(w)), scopePolicy: [{ effect: 'allow', pattern: 'payments:transfer:*' }], authorize })).decision).toBe('allow');
    expect((await w.bankAp.admit({ ...(await presented(w)), authorize })).decision).toBe('allow');
  });

  it('the credential\'s own scopes are judged first: scope_missing before scope_denied', async () => {
    const w = world({ scopes: ['payments:transfer:read'] });
    const a = await w.bankAp.admit({ ...(await presented(w)), scopePolicy: [{ effect: 'deny', pattern: 'payments:transfer:*' }], authorize });
    expect(a.decision === 'deny' && a.reason).toBe('scope_missing');
  });

  it('a rule outside the grammar is a usage error, before anything is judged', async () => {
    const w = world();
    const x = await presented(w);
    await expect(w.bankAp.admit({ ...x, scopePolicy: [{ effect: 'allow', pattern: 'payments:*:create' }], authorize })).rejects.toThrow(AriaUsageError);
    await expect(w.bankAp.admit({ ...x, scopePolicy: [{ effect: 'permit', pattern: 'payments:transfer:create' }] as never, authorize })).rejects.toThrow(AriaUsageError);
  });

  it('the admission keeps the policy it was judged with: changing the caller\'s list afterwards changes nothing', async () => {
    const w = world();
    const rules = [{ effect: 'allow' as const, pattern: 'payments:transfer:create' }];
    const a = await w.bankAp.admit({ ...(await presented(w)), scopePolicy: rules, authorize });
    if (a.decision !== 'allow') throw new Error('expected allow');
    rules.push({ effect: 'deny' as never, pattern: 'payments:transfer:create' });
    expect((await w.ledger.begin(a)).kind).toBe('claimed');
  });
});
