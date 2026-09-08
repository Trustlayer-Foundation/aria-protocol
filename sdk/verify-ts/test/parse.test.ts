import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseCredential } from '../src/parse';

const FIXTURES = join(import.meta.dirname, 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf-8');
}

describe('parseCredential', () => {
  it('parses a valid AID without verifying', () => {
    const aid = loadFixture('valid-aid.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.did).toBe('did:aria:example.com:test-agent');
    expect(parsed!.agent).toBe('TestAgent');
    expect(parsed!.version).toBe('1.0.0');
    expect(parsed!.principal.name).toBe('Example Corp');
    expect(parsed!.principal.domain).toBe('example.com');
    expect(parsed!.principal.jurisdiction).toBe('US');
    expect(parsed!.principal.type).toBe('organization');
    expect(parsed!.trustLevel).toBe('L2');
    expect(parsed!.scopes).toContain('data:general:read');
    expect(parsed!.expired).toBe(false);
    expect(parsed!.rawVc).toBeDefined();
  });

  it('parses an AID passed as object', () => {
    const aid = JSON.parse(loadFixture('valid-aid.json'));
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.did).toBe('did:aria:example.com:test-agent');
  });

  it('returns null for invalid input', () => {
    expect(parseCredential('garbage')).toBeNull();
    expect(parseCredential('')).toBeNull();
    expect(parseCredential(null)).toBeNull();
    expect(parseCredential(undefined)).toBeNull();
    expect(parseCredential(42)).toBeNull();
    expect(parseCredential([])).toBeNull();
  });

  it('parses an expired AID', () => {
    const aid = loadFixture('expired-aid.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.expired).toBe(true);
    expect(parsed!.did).toBe('did:aria:example.com:test-agent');
  });

  it('returns null for AID with missing required fields', () => {
    const aid = loadFixture('missing-fields.json');
    const parsed = parseCredential(aid);

    // missing agentName → returns null
    expect(parsed).toBeNull();
  });

  it('rejects oversized input', () => {
    const oversized = JSON.stringify({ id: 'x'.repeat(101 * 1024) });
    const parsed = parseCredential(oversized);

    expect(parsed).toBeNull();
  });

  // ── ARIA 1.0 field tests ────────────────────────────────────────

  it('parses spec_version from an issued AID', () => {
    const aid = loadFixture('valid-aid.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.specVersion).toBe('1.0');
  });

  it('parses AID without spec_version (pre-cutover)', () => {
    const aid = loadFixture('valid-aid-pre-cutover.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.specVersion).toBeNull();
  });

  it('parses L0 AID without dnsAnchor', () => {
    const aid = loadFixture('valid-aid-l0-no-dns.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.trustLevel).toBe('L0');
    expect(parsed!.agent).toBe('L0TestAgent');
    expect(parsed!.specVersion).toBe('1.0');
  });

  it('exposes credentialId, previousCredentialId, and verificationStatus on an issued AID', () => {
    const aid = loadFixture('valid-aid.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.credentialId).toMatch(/^https:\/\/api\.aria\.bar\/v1\/credentials\//);
    expect(parsed!.previousCredentialId).toMatch(/^https:\/\/api\.aria\.bar\/v1\/credentials\//);
    expect(parsed!.principal.verificationStatus).toBe('registry-confirmed');
    expect(parsed!.did).toBe('did:aria:example.com:test-agent');
  });

  it('returns null credentialId/verificationStatus for pre-cutover credentials', () => {
    const aid = loadFixture('valid-aid-pre-cutover.json');
    const parsed = parseCredential(aid);

    expect(parsed).not.toBeNull();
    expect(parsed!.credentialId).toBeNull();
    expect(parsed!.previousCredentialId).toBeNull();
    expect(parsed!.principal.verificationStatus).toBeNull();
  });
});
