# From `@aria-registry/verify` 1.x to the ARIA SDK 1.0

The new SDK is a new package in the same repository. `@aria-registry/verify` keeps its
published versions; nothing is unpublished or overwritten.

## The one change that matters

```ts
// 1.x
const result = verifyAgent(credential, { policy });
if (result.valid) execute();
```

`valid` could be `true` with the signature check skipped, with the requested policy
failed, with the status never checked, and with nobody proving the holder key. It was
never a decision to run anything, and there is no compatibility wrapper that keeps it.

```ts
// 1.0: authenticate, then admit; only `allow` runs
const presented = await verifier.verifyPresentation(request, context);
if (!presented.ok) return presented.status;
const status = await verifier.checkStatus(presented.presentation.credential);
const admission = await verifier.admit({ presentation: presented.presentation, status, authorize });
if (admission.decision !== 'allow') return admission.refusal.status;
await execute();
```

An operation that must happen once, or that the caller needs a receipt for, runs
through `OperationLedger` (see `examples/protected-handler.ts`).

## Field by field

| 1.x | 1.0 |
|---|---|
| `verifyAgent(c)` | `createVerifier({ trust }).verifyCredential(c)`; status and admission are separate calls |
| `verifyAgent(c, { skipSignatureCheck: true })` | `inspectCredential(c)`: returns an `Inspection`, never a verified result |
| `setRegistryKeys(...)`, embedded registry keys | `createVerifier({ trust: [profile] })`: explicit, per verifier, nothing global or embedded |
| `result.valid` | `CredentialResult.ok` for the document only; `Admission.decision === 'allow'` to run |
| `result.reason` (free text) | fixed reasons: `CredentialFailure`, `StatusUnavailable`, `PresentationFailure`, `AdmissionReason` |
| `result.signatures.pqValid/classicalValid` | both required; a failure is `signature_invalid` |
| `result.expired` | `not_yet_valid`, `expired` or `invalid_validity`, with strict instants |
| `result.issuedAt` | `validFrom` (signed, RFC 3339 string). There is no issuance time: `proof.created` is not signed |
| `result.expiresAt` | `validUntil` |
| `result.credentialId`, `previousCredentialId` | `credential.binding.credentialId`; `credential.previousCredentialId` as data, never fetched |
| `result.revocationStatus`, `revocationCheckedAt` | `checkStatus(credential)` → `StatusEvidence` with source, signed list times and `fetchedAt` |
| `checkRevocation(did)` | removed: it asked about a DID, not the presented document |
| `checkCredentialStatus(c, { via })` | `checkStatus(credential, { via: 'status-list' \| 'online' })`; the online endpoint is the profile's `onlineStatus` |
| `policy.requiredScopes`, `minTrustLevel` | `OperationDescriptor.scope`, `minLevel`, enforced by `admit` |
| `policy.requireRevocationCheck`, `lastRevocationCheck`, `maxOfflineAge` | `statusMaxAgeSeconds`, from the signed list's `validFrom`; a fresh fetch time is not evidence |
| `result.hitlRequired` | `credential.hitlRequired`, a declaration; the approval is `ApprovalEvidence` at `admit` |
| `PolicyLevel` presets | none: each operation states its level and scope |
| `canonicalJson` | internal; the canonical form stays the ARIA one (INVARIANTS §3) |
| results as plain objects you could copy or edit | frozen views the producing verifier recognises by identity; copies and other verifiers' results throw `AriaUsageError` |

## What the old characterizations become

The 1.x probes recorded behaviors; they are not all defects. In the 1.0 tests:

- **kept as controls**: a valid baseline passes schema and both signatures; altered signed
  content and an expired credential are refused;
- **turned into rejections**: not-yet-valid, invalid or inverted validity bounds, a
  missing holder key, the skipped signature check (now inspection only), a failed
  requested scope (now `deny`), a revoked status discarded by the old recipe (now `deny`),
  unsupported proof metadata (refused, still unsigned);
- **checked at their own layer**: a copied credential still verifies as a document but
  cannot be admitted without its holder key; offline verification succeeds with unknown
  status, while an admission that needs status is `indeterminate`;
- **schema versus rules**: the schema alone accepts `hitlRequired` outside `scope`; the
  SDK refuses it as `semantic_invalid`.
