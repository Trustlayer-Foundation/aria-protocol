// The exported level list is a view of the protocol's order, not a setting: no
// consumer change to it may move an issuer's ceiling, in an existing verifier or
// a new one.
import { describe, expect, it } from 'vitest';
import { createVerifier, TRUST_LEVELS, type TrustLevel } from '../src';
import { credential, newIssuer, NOW, profile, sign } from './fixtures';

const issuer = newIssuer();
// The protocol's order, written out here so the test does not read the list it checks.
const RANK: Record<TrustLevel, number> = { L0: 0, L1: 1, L2: 2, L3: 3 };
const ALL = Object.keys(RANK) as TrustLevel[];

const at = (level: TrustLevel) => {
  const doc = credential();
  doc.credentialSubject.trustLevel = level;
  return sign(doc, issuer);
};
const signed = Object.fromEntries(ALL.map((l) => [l, at(l)])) as Record<TrustLevel, Record<string, unknown>>;
const cappedAt = (maxLevel: TrustLevel) => createVerifier({ trust: [profile(issuer, { maxLevel })], clock: () => new Date(NOW) });
const levels = TRUST_LEVELS as TrustLevel[];

const mutations: Record<string, () => unknown> = {
  reverse: () => levels.reverse(),
  sort: () => levels.sort((a, b) => b.localeCompare(a)),
  splice: () => levels.splice(0, levels.length, 'L3', 'L2', 'L1', 'L0'),
  'indexed assignment': () => {
    levels[0] = 'L3';
  },
  push: () => levels.push('L0'),
  'length change': () => {
    levels.length = 1;
  },
  defineProperty: () => Object.defineProperty(levels, 3, { value: 'L0' }),
};

describe('issuer ceilings follow the protocol order', () => {
  for (const cap of ALL) {
    it(`a profile capped at ${cap} accepts levels up to it and refuses those above`, () => {
      const v = cappedAt(cap);
      for (const level of ALL) {
        const r = v.verifyCredential(signed[level]);
        if (RANK[level] <= RANK[cap]) expect(r, `${level} under ${cap}`).toMatchObject({ ok: true });
        else expect(r, `${level} under ${cap}`).toEqual({ ok: false, reason: 'level_not_trusted', path: '/credentialSubject/trustLevel' });
      }
    });
  }
});

describe('TRUST_LEVELS cannot change a decision', () => {
  it('is frozen, lowest first', () => {
    expect(Object.isFrozen(TRUST_LEVELS)).toBe(true);
    expect([...TRUST_LEVELS]).toEqual(['L0', 'L1', 'L2', 'L3']);
  });

  for (const [name, mutate] of Object.entries(mutations)) {
    it(`${name}: existing and new verifiers keep their ceiling`, () => {
      const existing = cappedAt('L0');
      expect(existing.verifyCredential(signed.L1)).toMatchObject({ ok: false, reason: 'level_not_trusted' });
      expect(() => mutate()).toThrow(TypeError);
      expect([...TRUST_LEVELS]).toEqual(['L0', 'L1', 'L2', 'L3']);
      for (const v of [existing, cappedAt('L0')]) {
        expect(v.verifyCredential(signed.L1)).toMatchObject({ ok: false, reason: 'level_not_trusted' });
        expect(v.verifyCredential(signed.L0)).toMatchObject({ ok: true });
      }
      expect(cappedAt('L2').verifyCredential(signed.L3)).toMatchObject({ ok: false, reason: 'level_not_trusted' });
    });
  }
});
