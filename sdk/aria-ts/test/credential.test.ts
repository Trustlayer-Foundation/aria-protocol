// The 17 observations of the earlier SDK probes, each at its own layer
// (ops/evidence/2026-10-31-aria-1-plan-review/acceptance-map.json): six controls
// kept as they were, nine former defects now refused, two layer distinctions.
import { describe, expect, it } from 'vitest';
import { AriaUsageError, createVerifier, inspectCredential, type VerifiedCredential } from '../src';
import { schemaFailure } from '../src/internal/schema';
import { evaluate } from '../src/internal/policy';
import { recall } from '../src/internal/provenance';
import type { CredentialSnapshot } from '../src/internal/verify-credential';
import { credential, fakeFetch, HOUR, iso, LIST_URL, newIssuer, NOW, profile, sign, statusList } from './fixtures';

const issuer = newIssuer();
const clock = () => new Date(NOW);
const offline = createVerifier({ trust: [profile(issuer)], clock });
const signed = sign(credential(), issuer);

function verified(v = offline, doc: unknown = signed): VerifiedCredential {
  const r = v.verifyCredential(doc);
  if (!r.ok) throw new Error(`expected a verified credential, got ${r.reason}`);
  return r.credential;
}

describe('controls that already held, kept', () => {
  it('the baseline conforms to the AID 1.0 schema', () => {
    expect(schemaFailure(signed)).toBeNull();
  });

  it('a credential with both issuer signatures verifies', () => {
    const c = verified();
    expect(c.did).toBe('did:aria:example.test:probe');
    expect(c.binding.credentialId).toBe(signed.id);
    expect(c.binding.digest).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
  });

  it('either half alone is not enough', () => {
    expect(offline.verifyCredential(sign(credential(), issuer, 'pq'))).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(offline.verifyCredential(sign(credential(), issuer, 'classical'))).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });

  it('altered signed content is refused', () => {
    const c = structuredClone(signed);
    c.credentialSubject.agentName = 'changed';
    expect(offline.verifyCredential(c)).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });

  it('a changed payload (scopes) is refused', () => {
    const c = structuredClone(signed);
    c.credentialSubject.scope = [...c.credentialSubject.scope, 'admin:all:write'];
    expect(offline.verifyCredential(c)).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });

  it('an expired credential is refused', () => {
    expect(offline.verifyCredential(sign({ ...credential(), validFrom: iso(-48 * HOUR), validUntil: iso(-HOUR) }, issuer))).toMatchObject({ ok: false, reason: 'expired' });
  });
});

describe('former defects, now refused', () => {
  it('a credential not valid yet', () => {
    expect(offline.verifyCredential(sign({ ...credential(), validFrom: iso(HOUR) }, issuer))).toMatchObject({ ok: false, reason: 'not_yet_valid' });
  });

  it('an invalid validUntil', () => {
    const r = offline.verifyCredential(sign({ ...credential(), validUntil: 'not-a-date' }, issuer));
    expect(r.ok).toBe(false);
  });

  it('an invalid validFrom', () => {
    const r = offline.verifyCredential(sign({ ...credential(), validFrom: '2026-02-31T00:00:00Z' }, issuer));
    expect(r.ok).toBe(false);
  });

  it('inverted validity bounds', () => {
    expect(offline.verifyCredential(sign({ ...credential(), validFrom: iso(-HOUR), validUntil: iso(-2 * HOUR) }, issuer))).toMatchObject({ ok: false, reason: 'invalid_validity' });
  });

  it('a credential without its holder key', () => {
    const c = credential();
    delete c.credentialSubject.holderKey;
    expect(offline.verifyCredential(sign(c, issuer))).toMatchObject({ ok: false, reason: 'malformed' });
  });

  it('skipping the signature check is not possible: inspection is all that remains, and it is refused as a credential', async () => {
    const c = structuredClone(signed);
    c.credentialSubject.agentName = 'changed';
    const seen = inspectCredential(c);
    expect(seen).toMatchObject({ kind: 'inspection', verified: false, did: 'did:aria:example.test:probe' });
    await expect(offline.checkStatus(seen as unknown as VerifiedCredential)).rejects.toBeInstanceOf(AriaUsageError);
  });

  it('a failed requested scope is a denial, not a valid result', () => {
    const snapshot = recall<CredentialSnapshot>(offline, 'credential', verified());
    const status = { source: 'status-list' as const, state: 'active' as const, credential: snapshot, list: { url: LIST_URL, index: 7, validFrom: NOW - 60_000, validUntil: NOW + HOUR }, fetchedAt: NOW };
    expect(evaluate(policyInput(snapshot, status, { scope: 'banking:payment:execute' }))).toEqual({ decision: 'deny', reason: 'scope_missing' });
  });

  it('a revoked status is refused, however recent the check', async () => {
    const fetch = fakeFetch({ [LIST_URL]: statusList(issuer, [7]) });
    const v = createVerifier({ trust: [profile(issuer)], clock, fetch: { allowedOrigins: ['https://status.example.test'], fetch } });
    const c = verified(v);
    const status = await v.checkStatus(c);
    expect(status).toMatchObject({ source: 'status-list', state: 'revoked' });
    const snapshot = recall<CredentialSnapshot>(v, 'credential', c);
    expect(evaluate(policyInput(snapshot, recall(v, 'status', status)))).toEqual({ decision: 'deny', reason: 'credential_revoked' });
  });

  it('proof metadata that is not the profile is refused, and is still not signed', () => {
    for (const [field, value] of [
      ['verificationMethod', 'did:aria:issuer.example.test#key-9'],
      ['cryptosuite', 'eddsa-rdfc-2022'],
      ['proofPurpose', 'authentication'],
    ] as const) {
      const c = structuredClone(signed);
      c.proof[field] = value;
      const r = offline.verifyCredential(c);
      expect(r.ok, field).toBe(false);
      expect(['unsupported_proof', 'malformed']).toContain((r as { reason: string }).reason);
    }
    // proof.created is outside the signed bytes: changing it does not break the signature, and the SDK exposes no issuance time.
    const c = structuredClone(signed);
    c.proof.created = iso(-30 * 24 * HOUR);
    const r = offline.verifyCredential(c);
    expect(r.ok).toBe(true);
    expect(Object.keys((r as { credential: object }).credential)).not.toContain('issuedAt');
  });
});

describe('each result at its own layer', () => {
  it('a copied, authentic credential verifies as a document, and cannot be admitted without its holder key', async () => {
    const copy = JSON.parse(JSON.stringify(signed));
    const c = verified(offline, copy);
    const status = await offline.checkStatus(c);
    // No presentation exists without the holder's signature; nothing else is accepted in its place.
    await expect(offline.admit({ presentation: c as never, status, authorize: async () => ({ allowed: true }) })).rejects.toBeInstanceOf(AriaUsageError);
  });

  it('offline verification succeeds with status unknown, and an admission that needs status is indeterminate', async () => {
    const c = verified();
    const status = await offline.checkStatus(c);
    expect(status).toMatchObject({ state: 'unavailable', reason: 'offline' });
    const snapshot = recall<CredentialSnapshot>(offline, 'credential', c);
    expect(evaluate(policyInput(snapshot, recall(offline, 'status', status)))).toEqual({ decision: 'indeterminate', reason: 'status_unavailable' });
  });
});

describe('field and rule observations', () => {
  it('verification never fetches a predecessor', () => {
    const fetch = fakeFetch({});
    const v = createVerifier({ trust: [profile(issuer)], clock, fetch: { allowedOrigins: ['https://api.aria.bar'], fetch } });
    const c = credential();
    c.credentialSubject.previousCredentialId = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-000000000000';
    const r = v.verifyCredential(sign(c, issuer));
    expect(r).toMatchObject({ ok: true });
    expect((r as { credential: VerifiedCredential }).credential.previousCredentialId).toBe(c.credentialSubject.previousCredentialId);
    expect(fetch.calls).toEqual([]);
  });

  it('an edited signed predecessor reference fails', () => {
    const c = credential();
    c.credentialSubject.previousCredentialId = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-000000000000';
    const s = sign(c, issuer);
    s.credentialSubject.previousCredentialId = 'https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-00000000000f';
    expect(offline.verifyCredential(s)).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });

  it('the schema accepts hitlRequired outside scope; the SDK refuses it', () => {
    const c = credential();
    c.credentialSubject.hitlRequired = ['payments:refund:create'];
    const s = sign(c, issuer);
    expect(schemaFailure(s)).toBeNull();
    expect(offline.verifyCredential(s)).toMatchObject({ ok: false, reason: 'semantic_invalid' });
  });

  it('a level above the profile, an untrusted issuer and an unpublished status list are refused', () => {
    const high = credential();
    high.credentialSubject.trustLevel = 'L2';
    expect(offline.verifyCredential(sign(high, issuer))).toMatchObject({ ok: false, reason: 'level_not_trusted' });
    expect(createVerifier({ trust: [profile(newIssuer(), { issuer: 'did:aria:other.example.test' })], clock }).verifyCredential(signed)).toMatchObject({ ok: false, reason: 'untrusted_issuer' });
    expect(createVerifier({ trust: [profile(issuer, { statusLists: ['https://status.example.test/v1/status/2'] })], clock }).verifyCredential(signed)).toMatchObject({ ok: false, reason: 'status_list_untrusted' });
  });

  it('a holder key that is not 32 raw bytes is refused', () => {
    const c = credential();
    c.credentialSubject.holderKey.publicKeyMultibase = 'z6Mk' + c.credentialSubject.holderKey.publicKeyMultibase.slice(1);
    expect(offline.verifyCredential(sign(c, issuer))).toMatchObject({ ok: false, reason: 'holder_key_invalid' });
  });

  it('an unsupported spec_version and a non-object are refused', () => {
    const c = credential();
    c.credentialSubject.spec_version = '1.2';
    expect(offline.verifyCredential(sign(c, issuer))).toMatchObject({ ok: false, reason: 'unsupported_version' });
    expect(offline.verifyCredential('[]')).toMatchObject({ ok: false, reason: 'malformed' });
    expect(offline.verifyCredential('x'.repeat(200 * 1024))).toMatchObject({ ok: false, reason: 'malformed' });
  });
});

function policyInput(credential: CredentialSnapshot, status: any, operation: Partial<{ scope: string; minLevel: 'L0' | 'L1' }> = {}) {
  return {
    credential,
    status,
    audienceMatches: true,
    operation: { scope: 'data:documents:read', minLevel: 'L0' as const, onMissingApproval: 'refuse' as const, ...operation },
    operationId: 'op-1',
    fingerprint: 'fp-1',
    approval: null,
    now: NOW,
    skewMs: 5000,
    statusMaxAgeMs: HOUR,
    onlineMaxAgeMs: 60_000,
  };
}
