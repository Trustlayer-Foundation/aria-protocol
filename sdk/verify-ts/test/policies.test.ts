import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyAgent } from '../src/verify';
import { PolicyLevel } from '../src/policies';
import type { PolicyConfig } from '../src/types';

const FIXTURES = join(import.meta.dirname, 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf-8');
}

describe('Policy evaluation', () => {
  it('COMMERCE policy passes with L2 AID', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: PolicyLevel.COMMERCE,
    });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });

  it('FINANCIAL policy passes with L2 AID and recent revocation check', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: {
        ...PolicyLevel.FINANCIAL,
        lastRevocationCheck: Date.now() - 60 * 1000, // 1 minute ago
      },
    });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });

  it('FINANCIAL policy fails when trust level is insufficient', () => {
    // The valid-aid.json has L2, but we'll create a custom policy requiring L3
    const aid = loadFixture('valid-aid.json');
    const policy: PolicyConfig = {
      maxOfflineAge: 24 * 60 * 60 * 1000,
      minTrustLevel: 'L3',
    };

    const result = verifyAgent(aid, { policy });

    expect(result.valid).toBe(true); // Crypto is valid
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toContain('TRUST_LEVEL');
  });

  it('FINANCIAL policy fails when offline too long', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: {
        ...PolicyLevel.FINANCIAL,
        lastRevocationCheck: Date.now() - 25 * 60 * 60 * 1000, // 25 hours ago
      },
    });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toContain('OFFLINE');
  });

  it('SOVEREIGN policy fails without revocation check', () => {
    const aid = loadFixture('valid-aid.json');
    // valid-aid.json has L2, SOVEREIGN requires L3, but let's test revocation first
    const policy: PolicyConfig = {
      maxOfflineAge: 15 * 60 * 1000,
      minTrustLevel: 'L2', // Match the AID's level so trust passes
      requireRevocationCheck: true,
    };

    const result = verifyAgent(aid, { policy });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toContain('REVOCATION_CHECK_REQUIRED');
  });

  it('custom policy with required scopes — passes when all present', () => {
    const aid = loadFixture('valid-aid.json');
    const policy: PolicyConfig = {
      maxOfflineAge: null,
      requiredScopes: ['data:general:read', 'communication:email:send'],
    };

    const result = verifyAgent(aid, { policy });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });

  it('custom policy with required scopes — fails when missing', () => {
    const aid = loadFixture('valid-aid.json');
    const policy: PolicyConfig = {
      maxOfflineAge: null,
      requiredScopes: ['data:general:read', 'financial:invoice:approve'],
    };

    const result = verifyAgent(aid, { policy });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(false);
    expect(result.policyResult?.reason).toContain('MISSING_SCOPES');
    expect(result.policyResult?.reason).toContain('financial:invoice:approve');
  });

  it('HEALTHCARE policy passes with valid L2 AID and recent check', () => {
    const aid = loadFixture('valid-aid.json');
    const result = verifyAgent(aid, {
      policy: {
        ...PolicyLevel.HEALTHCARE,
        lastRevocationCheck: Date.now() - 30 * 60 * 1000, // 30 min ago
      },
    });

    expect(result.valid).toBe(true);
    expect(result.policyResult?.passed).toBe(true);
  });
});
