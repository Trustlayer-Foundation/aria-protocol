// The shared holder-key cases (conformance/vectors/holder-keys.json): each key, set
// as a credential's holder key and signed by a trusted issuer, is accepted or
// refused as the protocol says. The authority runs the same cases on what it takes
// from an agent statement.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createVerifier } from '../src';
import { credential, newIssuer, NOW, profile, sign } from './fixtures';

const cases = JSON.parse(readFileSync(new URL('../../../conformance/vectors/holder-keys.json', import.meta.url), 'utf8')) as {
  accept: { label: string; publicKeyMultibase: string; raw: string }[];
  reject: { label: string; publicKeyMultibase: string }[];
};
const issuer = newIssuer();
const verifier = createVerifier({ trust: [profile(issuer)], clock: () => new Date(NOW) });
const withKey = (publicKeyMultibase: string) => {
  const c = credential();
  c.credentialSubject.holderKey.publicKeyMultibase = publicKeyMultibase;
  return verifier.verifyCredential(sign(c, issuer));
};

describe('holder keys, as the shared cases say', () => {
  for (const k of cases.accept) {
    it(`accepts ${k.label}, as its 32 raw bytes`, () => {
      const r = withKey(k.publicKeyMultibase);
      expect(r.ok).toBe(true);
      if (r.ok) expect(Buffer.from(verifier.facts(r.credential).holderKey.publicKey).toString('hex')).toBe(k.raw);
    });
  }
  for (const k of cases.reject) {
    it(`refuses ${k.label}`, () => {
      // An encoding outside the schema's pattern makes the document malformed; a decodable
      // key that is not 32 acceptable bytes fails the holder-key rule.
      const r = withKey(k.publicKeyMultibase);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe(/^z[1-9A-HJ-NP-Za-km-z]+$/.test(k.publicKeyMultibase) ? 'holder_key_invalid' : 'malformed');
    });
  }
});
