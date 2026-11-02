// The did:aria grammar against the shared vectors and the authority's rules.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseDid } from '../src';

const cases = JSON.parse(readFileSync(new URL('../../../conformance/vectors/abnf-cases.json', import.meta.url), 'utf8')) as {
  accept: { did: string; shape: string }[];
  reject: { did: string; reason: string }[];
};

describe('parseDid', () => {
  for (const c of cases.accept) {
    it(`accepts ${c.did} as ${c.shape}`, () => {
      expect(parseDid(c.did)?.shape).toBe(c.shape);
    });
  }
  for (const c of cases.reject) {
    it(`rejects ${c.did}: ${c.reason}`, () => {
      expect(parseDid(c.did)).toBeNull();
    });
  }

  it('gives the parts, as the authority does', () => {
    expect(parseDid('did:aria:aria.bar:u-cmDoHhM3:ordering-agent')).toEqual({ shape: 'agent-registry-form', did: 'did:aria:aria.bar:u-cmDoHhM3:ordering-agent', host: 'aria.bar', account: 'u-cmDoHhM3', slug: 'ordering-agent' });
    expect(parseDid('did:aria:example.com:org')).toEqual({ shape: 'principal-domain-form', did: 'did:aria:example.com:org', domain: 'example.com' });
  });

  it('holds the boundaries the authority holds', () => {
    expect(parseDid(`did:aria:example.com:${'a'.repeat(64)}`)).not.toBeNull();
    expect(parseDid(`did:aria:example.com:${'a'.repeat(65)}`)).toBeNull();
    expect(parseDid(`did:aria:${'a'.repeat(63)}.com:agent`)).not.toBeNull();
    expect(parseDid(`did:aria:${'a'.repeat(64)}.com:agent`)).toBeNull();
    // A first part starting with u- is a registry account or nothing, never a domain.
    expect(parseDid('did:aria:u-abc:org')).toBeNull();
    expect(parseDid('did:aria:Example.COM:agent')?.shape).toBe('agent-domain-form');
    expect(parseDid('did:aria:example..com:agent')).toBeNull();
    expect(parseDid('did:aria:example.com:org:x')).toBeNull();
    expect(parseDid(42)).toBeNull();
  });
});
