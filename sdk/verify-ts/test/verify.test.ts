import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyAgent } from '../src/verify';
import { COMPOSITE_SUITE } from '../src/registry-key';

const FIXTURES = join(import.meta.dirname, 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf-8');
}

describe('verifyAgent', () => {
  it('verifies a valid AID', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(true);
    expect(result.did).toBe('did:aria:example.com:test-agent');
    expect(result.agent).toBe('TestAgent');
    expect(result.version).toBe('1.0.0');
    expect(result.trustLevel).toBe('L2');
    expect(result.expired).toBe(false);
    expect(result.signatures.pqValid).toBe(true);
    expect(result.signatures.classicalValid).toBe(true);
    expect(result.signatures.suite).toBe(COMPOSITE_SUITE);
    expect(result.revocationStatus).toBe('unknown');
    expect(result.principal.name).toBe('Example Corp');
    expect(result.principal.domain).toBe('example.com');
    expect(result.scopes).toContain('data:general:read');
  });

  it('verifies a valid AID passed as object', () => {
    const aid = JSON.parse(loadFixture('valid-aid.json'));
    const result = verifyAgent(aid);

    expect(result.valid).toBe(true);
    expect(result.did).toBe('did:aria:example.com:test-agent');
  });

  it('rejects an expired AID', () => {
    const aid = loadFixture('expired-aid.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('EXPIRED');
    expect(result.expired).toBe(true);
  });

  it('rejects a tampered signature', () => {
    const aid = loadFixture('tampered-aid.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('SIGNATURE');
    expect(result.signatures.pqValid).toBe(false);
  });

  it('rejects tampered content', () => {
    const aid = loadFixture('tampered-content.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(false);
    // Should fail on signature verification since content was changed after signing
    expect(result.reason).toMatch(/SIGNATURE|CONTENT_HASH/);
  });

  it('rejects AID with missing fields', () => {
    const aid = loadFixture('missing-fields.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('MISSING_FIELDS');
  });

  it('rejects oversized input', () => {
    const oversized = 'x'.repeat(101 * 1024);
    const result = verifyAgent(oversized);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('INPUT_TOO_LARGE');
  });

  it('rejects invalid JSON', () => {
    const result = verifyAgent('not json at all');

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('INVALID_FORMAT');
  });

  it('rejects null input', () => {
    const result = verifyAgent(null);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('INVALID_FORMAT');
  });

  it('rejects undefined input', () => {
    const result = verifyAgent(undefined);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('INVALID_FORMAT');
  });

  it('works with skipSignatureCheck option', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, { skipSignatureCheck: true });

    expect(result.valid).toBe(true);
    expect(result.signatures.pqValid).toBe(false);
    expect(result.signatures.classicalValid).toBe(false);
    expect(result.did).toBe('did:aria:example.com:test-agent');
  });

  it('evaluates policy on valid AID', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: {
        maxOfflineAge: null,
        minTrustLevel: 'L1',
      },
    });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });

  it('fails policy when trust level is insufficient', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: {
        maxOfflineAge: null,
        minTrustLevel: 'L3',
      },
    });

    expect(result.valid).toBe(true); // Signature is valid
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toContain('TRUST_LEVEL');
  });

  // ── v1.1 Compatibility Tests ──────────────────────────

  it('verifies a v1.1 AID with credential-instance URL and verificationStatus', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(true);
    expect(result.specVersion).toBe('1.1');
    expect(result.credentialId).toMatch(/^https:\/\/api\.aria\.bar\/v1\/credentials\//);
    expect(result.previousCredentialId).toMatch(/^https:\/\/api\.aria\.bar\/v1\/credentials\//);
    expect(result.principal.verificationStatus).toBe('registry-confirmed');
    expect(result.did).toBe('did:aria:example.com:test-agent');
  });

  it('rejects self-declared principals when requirePrincipalVerified is set', () => {
    const aid = loadFixture('valid-aid-l0-no-dns.json');
    const result = verifyAgent(aid, { policy: { maxOfflineAge: null, requirePrincipalVerified: true } });

    expect(result.valid).toBe(true); // signatures still valid
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toMatch(/PRINCIPAL_NOT_VERIFIED/);
  });

  it('passes requirePrincipalVerified when verificationStatus is registry-confirmed', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, { policy: { maxOfflineAge: null, requirePrincipalVerified: true } });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });

  it('verifies an L0 AID without dnsAnchor', () => {
    const aid = loadFixture('valid-aid-l0-no-dns.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('L0');
    expect(result.did).toContain('l0-agent');
    expect(result.signatures.pqValid).toBe(true);
    expect(result.signatures.classicalValid).toBe(true);
  });

  it('backward compatible with v1.5 @context', () => {
    const aid = loadFixture('valid-aid-v15-compat.json');
    const result = verifyAgent(aid);

    expect(result.valid).toBe(true);
    expect(result.specVersion).toBeNull();
    expect(result.signatures.pqValid).toBe(true);
  });
});
