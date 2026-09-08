# @aria-registry/verify

**Verify AI agent identity offline. Post-quantum cryptography. Zero dependencies beyond Noble crypto.**

[ARIA](https://aria.bar) (Agent Registry for Identity & Authorization) gives every AI agent a verifiable, cryptographically-signed identity document (AID). This SDK lets any system verify an AID locally — no internet required.

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
  console.log(result.did);                          // "did:aria:example.com:my-agent"
  console.log(result.trustLevel);                   // "L1"
  console.log(result.scopes);                       // ["data:general:read", ...]
  console.log(result.credentialId);                 // "https://api.aria.bar/v1/credentials/01906b8f-..."
  console.log(result.previousCredentialId);         // URL of the predecessor, or null
  console.log(result.principal.verificationStatus); // "self-declared" | "registry-confirmed" | "legal-verified" | null
}
```

### What's surfaced from AID schema v1.1

Every verification result includes the v1.1 machine-readable fields so a verifier can act
on identity provenance without re-parsing the raw VC:

| Field | Meaning |
|---|---|
| `credentialId` | Unique credential-instance URL — equivalent to a TLS certificate serial number. New on every reissuance. |
| `previousCredentialId` | URL of the credential this one supersedes, enabling explicit chain-of-issuance walks. `null` on first issuance. |
| `principal.verificationStatus` | Machine-readable provenance of the legal name: `self-declared` (L0/L1), `registry-confirmed` (L2), or `legal-verified` (L3). `null` for pre-v1.1 credentials. |

Pre-v1.1 credentials continue to verify; the v1.1 fields are surfaced as `null`.

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
  policy: { maxOfflineAge: null, requirePrincipalVerified: true },
});

if (result.policyResult?.passed) {
  // principal.verificationStatus is "registry-confirmed" or "legal-verified"
}
// Otherwise result.policyResult.reason starts with "PRINCIPAL_NOT_VERIFIED:"
```

This closes the L1 brand-impersonation gap: an attacker registering a self-declared
organization name (e.g. "Goldman Sachs" on a look-alike domain) is rejected before
the `legalName` is treated as authoritative.

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

| Preset | Max Offline Age | Min Trust Level | Revocation Check | Based On |
|--------|----------------|-----------------|-------------------|----------|
| `COMMERCE` | Unlimited | L0 | No | — |
| `FINANCIAL` | 24 hours | L1 | No | NIST SP 800-63-4 / PCI-DSS |
| `HEALTHCARE` | 1 hour | L1 | No | HIPAA §164.312 |
| `GOVERNMENT` | 1 hour | L1 | No | Aligned to NIST SP 800-63A-4 |
| `SOVEREIGN` | 15 minutes | L2 | **Yes** | Aligned to NIST SP 800-63A-4 |

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
| L1 | Identified | A verified natural person answers for the agent, which controls its domain. Not automatic. |
| L2 | Certified | Entity confirmed against its Authoritative Source; person linked; sanctions screened. |
| L3 | Sovereign | Binding Officer, keys in certified hardware (MUST), signed accountability. |

## How It Works

The SDK verifies ARIA Agent Identity Documents (AIDs) entirely offline. Aligned with ARIA Protocol v1.0 (filed with NIST, March 2026).

1. **Parse** the W3C Verifiable Credential and extract agent metadata
2. **Check expiration** against the credential's `validUntil` timestamp
3. **Verify ML-DSA-65** (FIPS 204) — the post-quantum primary signature
4. **Verify Ed25519** (RFC 8032) — the classical transition signature
5. **Evaluate policy** constraints (trust level, scopes, offline age)

Both signatures are verified against the ARIA Registry's public keys, which are embedded in the SDK package. No network calls are made during verification.

The composite proof format encodes both signatures in a single base64url `proofValue` field using a length-prefix binary layout, following the ARIA composite signature specification (`mldsa65-ed25519-2026`).

## Error Handling

```typescript
import { verifyAgent, AriaVerifyError, RevocationCheckError } from '@aria-registry/verify';

const result = await verifyAgent(input);
if (!result.valid) {
  // result.reason contains a machine-readable code + description
  // e.g. "SIGNATURE_INVALID: ML-DSA-65 and Ed25519 signature verification failed."
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
