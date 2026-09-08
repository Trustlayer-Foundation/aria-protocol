# @aria-registry/verify

**Verify an agent's credential offline. Post-quantum cryptography. No dependencies beyond the Noble libraries.**

[ARIA](https://aria.bar) (Agent Registry for Identity & Authorization) gives every AI agent a verifiable, cryptographically signed identity document (AID). This SDK verifies an AID locally, with no network call.

**What it verifies, and what it does not.** It checks the composite signature — ML-DSA-65 and Ed25519, **both** halves must pass — the validity window, the trust level and the provenance of the principal's name. It does **not** check revocation: `revocationStatus` comes back `'unknown'` and the credential passes. Revocation is a separate, networked call (`checkRevocation`), enforced only under a policy that requires it. And it is a credential verifier, not a DID resolver: parsing the identifier, following the DNS pointer, pinning the document against its hash and deriving the DID Document are [specified](https://aria.bar/spec#3-5-2) and not implemented here.

Part of the [ARIA Protocol](https://aria.bar) by [TrustLayer Foundation](https://trustlayer.foundation).

- [Protocol specification](https://aria.bar/spec)
- [Protocol schema](https://github.com/trustlayer-foundation/aria-protocol)
- [Security documentation](https://aria.bar/spec#crypto)

## Install

```bash
npm install @aria-registry/verify
```

## Quick Start

```typescript
import { verifyAgent } from '@aria-registry/verify';

const result = await verifyAgent(credential);

if (result.valid) {
  // `valid` means the signature, the validity window and the schema check out.
  // It says nothing about revocation — see "Check Revocation Online" below.
  console.log(result.did);                          // "did:aria:example.com:my-agent"
  console.log(result.trustLevel);                   // "L1"
  console.log(result.scopes);                       // ["data:general:read", ...]
  console.log(result.credentialId);                 // "https://api.aria.bar/v1/credentials/01906b8f-..."
  console.log(result.previousCredentialId);         // URL of the predecessor, or null
  console.log(result.principal.verificationStatus); // "self-declared" | "registry-confirmed" | "legal-verified" | null
}
```

### What is surfaced from the AID

Every verification result includes the machine-readable fields so a verifier can act
on identity provenance without re-parsing the raw VC:

| Field | Meaning |
|---|---|
| `credentialId` | Unique credential-instance URL — equivalent to a TLS certificate serial number. New on every reissuance. |
| `previousCredentialId` | URL of the credential this one supersedes, enabling explicit chain-of-issuance walks. `null` on first issuance. |
| `principal.verificationStatus` | Machine-readable provenance of the legal name: `self-declared` (L0/L1), `registry-confirmed` (L2), or `legal-verified` (L3). `null` on credentials issued before the field existed. |

Older credentials continue to verify; fields they predate are surfaced as `null`.

## Verify with Policy

Apply industry-specific requirements after signature verification:

```typescript
import { verifyAgent, PolicyLevel } from '@aria-registry/verify';

const result = await verifyAgent(credential, {
  policy: PolicyLevel.FINANCIAL,
});

if (result.policyResult?.passed) {
  // Agent meets financial services requirements (L1+, checked in last 24h)
}
```

### Reject self-declared organizational identity

For verifiers that only accept credentials whose principal name was checked against
an Authoritative Source (the company register of the jurisdiction of incorporation), use the
`requirePrincipalVerified` policy option:

```typescript
import { verifyAgent } from '@aria-registry/verify';

const result = await verifyAgent(credential, {
  // Bound the age of status evidence. `null` means "any age", which lets a
  // revoked credential keep passing from cache; the protocol floor is 60 s.
  policy: { maxOfflineAge: 60 * 60 * 1000, requirePrincipalVerified: true, requireRevocationCheck: true },
});

if (result.policyResult?.passed) {
  // principal.verificationStatus is "registry-confirmed" or "legal-verified"
}
// Otherwise result.policyResult.reason starts with "PRINCIPAL_NOT_VERIFIED:"
```

This closes the L1 brand-impersonation gap: an attacker who registers a well-known
company's name as a self-declared principal, on a look-alike domain, is rejected
before `legalName` is treated as authoritative.

## Parse without Verification

Fast inspection of credential contents without signature verification.
Useful for logging, routing, or UI display — **not for access control**.

```typescript
import { parseCredential } from '@aria-registry/verify';

const parsed = parseCredential(credential);
if (parsed) {
  console.log(parsed.agent);       // "my-agent"
  console.log(parsed.trustLevel);  // "L1"
  console.log(parsed.scopes);      // ["data:general:read", ...]
  console.log(parsed.expired);     // false
}
```

## Check Revocation Online

The **only function** that requires internet access:

This is a **per-DID** call to `/v1/verify/{did}`, not a read of the aggregate Bitstring
Status List the credential points at. It therefore tells the registry which agent you
are asking about. Moving the reference SDK to the aggregate list is
[planned](https://aria.bar/planned); until then both mechanisms are supported and
`INVARIANTS.md` §12 records why.

```typescript
import { checkRevocation } from '@aria-registry/verify';

try {
  const status = await checkRevocation('did:aria:example.com:agent');
  console.log(status.status);    // 'active' | 'revoked'
  console.log(status.checkedAt); // ISO 8601 timestamp
} catch (err) {
  // Network error — handle gracefully
}
```

Custom API endpoint (for local development or private registries):

```typescript
const status = await checkRevocation(did, {
  apiUrl: 'http://localhost:3003',
});
```

## Policy Presets

| Preset | Max offline age | Min trust level | Revocation check | What it asks for |
|--------|----------------|-----------------|-------------------|------------------|
| `COMMERCE` | unlimited | L0 | no | nothing beyond a valid credential |
| `FINANCIAL` | 24 hours | **L2** | no | a confirmed legal entity behind the agent |
| `HEALTHCARE` | 1 hour | L1 | no | a verified person, checked recently |
| `GOVERNMENT` | 1 hour | **L2** | no | a confirmed legal entity, no self-declared principal |
| `SOVEREIGN` | 15 minutes | **L3** | **yes** | a person with power to bind the entity, hardware-held keys |

The presets are convenience defaults, not conformance claims. ARIA maps to selected
frameworks in [Appendix B](https://aria.bar/spec#appendix-b) of the specification and
asserts equivalence to none of them. Only `SOVEREIGN` requires a revocation check; under
every other preset you supply `lastRevocationCheck` yourself or revocation is not
considered.

Only **L0** is issued today. A preset asking for L1 or above will reject every credential
that currently exists — correct as policy, surprising as a first run. See
[what is planned](https://aria.bar/planned#l1-l3).

## Custom Policy

```typescript
import { verifyAgent } from '@aria-registry/verify';
import type { PolicyConfig } from '@aria-registry/verify';

const myPolicy: PolicyConfig = {
  maxOfflineAge: 4 * 60 * 60 * 1000, // 4 hours
  minTrustLevel: 'L1',
  requiredScopes: ['data:general:read', 'communication:email:send'],
  requireRevocationCheck: false,
  lastRevocationCheck: Date.now() - 60 * 1000, // 1 minute ago
};

const result = await verifyAgent(credential, { policy: myPolicy });
```

## Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| L0 | Anchored | Cryptographic existence of the agent. Every declared name is self-declared. |
| L1 | Identified | A verified natural person answers for the agent, which controls its domain. Not automatic. `[PLANNED]` |
| L2 | Certified | Entity confirmed against its Authoritative Source; person linked; sanctions screened. `[PLANNED]` |
| L3 | Sovereign | Binding Officer, keys in certified hardware (MUST), signed accountability. `[PLANNED]` |

L1 to L3 are specified and not yet issued: no registry has been evaluated for them.

## How It Works

The SDK verifies ARIA Agent Identity Documents (AIDs) offline. Aligned with ARIA 1.0
(September 7, 2026); the protocol was filed with NIST in March 2026 under docket
2025-0035.

1. **Parse** the W3C Verifiable Credential and extract the agent metadata
2. **Check expiration** against the credential's `validUntil` timestamp
3. **Verify ML-DSA-65** (FIPS 204) — the post-quantum signature
4. **Verify Ed25519** (RFC 8032) — the classical half of the composite
5. **Evaluate policy** constraints (trust level, scopes, offline age)

Both halves must verify; failing either one fails the credential, and there is no
degraded mode that accepts one. What is *not* in that list is revocation.

Both signatures are verified against the ARIA Registry's public keys, which are embedded in the SDK package. No network calls are made during verification.

The composite proof format encodes both signatures in a single base64url `proofValue` field using a length-prefix binary layout, following the ARIA composite signature specification (`mldsa65-ed25519-2026`).

## Error Handling

```typescript
import { verifyAgent, AriaVerifyError, RevocationCheckError } from '@aria-registry/verify';

const result = await verifyAgent(input);
if (!result.valid) {
  // result.reason contains a machine-readable code + description
  // e.g. "SIGNATURE_INVALID: ML-DSA-65 signature verification failed." — the message
  //      names the half that failed, so tampering can be told from a version mismatch
  // e.g. "EXPIRED: credential has expired"
  // e.g. "MISSING_FIELDS: required fields are missing from credentialSubject."
}
```

## Security

- The SDK is **verification-only** — it never handles private keys
- Cryptographic operations use the [Noble](https://paulmillr.com/noble/) library family
- `@noble/post-quantum` has not yet received an independent security audit — use in production at your own risk assessment
- Input validation: max 100 KB credential size, strict JSON parsing, no `eval` or `Function`
- For the full ARIA security specification, see [aria.bar/spec#crypto](https://aria.bar/spec#crypto)

## Runtime Compatibility

- Node.js 18+
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Deno
- Bun

## License

Apache 2.0 — [TrustLayer Foundation](https://trustlayer.foundation)
