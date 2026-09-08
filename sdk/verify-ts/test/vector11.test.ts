// ATP/1 conformance vector 11 — composite AND, in the wire format that circulates.
//
// Production credentials carry ONE `proofValue`: unpadded base64url of
// u32be(pq_len) ‖ ml_dsa65_signature ‖ ed25519_signature (spec §5.1). The test
// fixtures carry the two halves as separate fields, which exercises a different
// branch of the verifier. This file builds the production form from the fixture
// halves and proves the AND on that branch: tamper either half → rejected.
// Test keys are injected by test/setup.ts.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyAgent, parseCredential } from '../src/index';

const load = (f: string) => JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', f), 'utf8'));
const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

/** Build the production proofValue from a fixture's separate halves. */
function toComposite(aid: any, mutate?: (pq: Uint8Array, ed: Uint8Array) => void) {
  const pq = hexToBytes(aid.proof.proofValuePq);
  const ed = hexToBytes(aid.proof.proofValueClassical);
  mutate?.(pq, ed);
  const out = new Uint8Array(4 + pq.length + ed.length);
  new DataView(out.buffer).setUint32(0, pq.length, false); // big-endian length prefix
  out.set(pq, 4); out.set(ed, 4 + pq.length);
  const { proofValuePq, proofValueClassical, ...proof } = aid.proof;
  return { ...aid, proof: { ...proof, proofValue: b64url(out) } };
}

describe('ATP/1 vector 11 — composite AND (production proofValue)', () => {
  it('accepts the untampered credential in composite form (control)', () => {
    const r = verifyAgent(toComposite(load('valid-aid.json')));
    expect(r.valid).toBe(true);
  });
  it('rejects when the ML-DSA-65 half is tampered and Ed25519 stays valid', () => {
    const r = verifyAgent(toComposite(load('valid-aid.json'), (pq) => { pq[pq.length - 1] ^= 0x01; }));
    expect(r.valid).toBe(false);
  });
  it('rejects when the Ed25519 half is tampered and ML-DSA-65 stays valid', () => {
    const r = verifyAgent(toComposite(load('valid-aid.json'), (_pq, ed) => { ed[ed.length - 1] ^= 0x01; }));
    expect(r.valid).toBe(false);
  });
  it('rejects a composite whose declared length exceeds the payload (MALFORMED)', () => {
    const aid = toComposite(load('valid-aid.json'));
    const bytes = Buffer.from(aid.proof.proofValue, 'base64url');
    bytes.writeUInt32BE(bytes.length + 1, 0);
    aid.proof.proofValue = bytes.toString('base64url');
    expect(verifyAgent(aid).valid).toBe(false);
  });
});

describe('ATP/1 vector 11 — composite AND (separate-field fixture form)', () => {
  const flip = (hex: string) => hex.slice(0, -2) + (parseInt(hex.slice(-2), 16) ^ 1).toString(16).padStart(2, '0');
  it('rejects a tampered ML-DSA-65 half', () => {
    const aid = load('valid-aid.json'); aid.proof.proofValuePq = flip(aid.proof.proofValuePq);
    expect(verifyAgent(aid).valid).toBe(false);
  });
  it('rejects a tampered Ed25519 half', () => {
    const aid = load('valid-aid.json'); aid.proof.proofValueClassical = flip(aid.proof.proofValueClassical);
    expect(verifyAgent(aid).valid).toBe(false);
  });
});

// The shape the registry issues today: one composite proofValue, spec_version 1.2.
// The suite would otherwise never verify a credential in the form that circulates.
describe('production-form credential', () => {
  const prod = () => load('valid-aid-production-form.json');

  it('verifies a credential in the form the registry issues', () => {
    const r = verifyAgent(prod());
    expect(r.valid).toBe(true);
    expect(r.signatures.pqValid).toBe(true);
    expect(r.signatures.classicalValid).toBe(true);
  });

  it('reports the spec_version production declares, not the one the schema will', () => {
    expect(parseCredential(prod())?.specVersion).toBe('1.2');
  });

  it('says nothing about revocation until a policy asks', () => {
    expect(verifyAgent(prod()).revocationStatus).toBe('unknown');
  });
});
