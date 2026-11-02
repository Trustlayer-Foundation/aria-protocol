# Examples

## ARIA 1.0

| File | What it shows |
|---|---|
| [`aid-example.json`](aid-example.json) | An AID 1.0 credential (illustrative: its proof value is not verifiable) |

Code that uses the two SDKs lives with each package: [`sdk/aria-ts/examples`](../sdk/aria-ts/examples)
(verifying a credential and its status) and [`sdk/aria-ap-ts/examples`](../sdk/aria-ap-ts/examples)
(a receiver's identity endpoint and protected operation, an agent's client with
recovery, the migration from `@aria-registry/verify`).

## Published, not the current workflow

[`enrollment-manifest-example.json`](enrollment-manifest-example.json) follows
[`schema/enrollment-manifest-v1.json`](../schema/enrollment-manifest-v1.json), the contract
of an earlier enrollment workflow that current enrollment does not use; see
[`schema/README.md`](../schema/README.md). Kept unchanged.

## Historical compatibility

Not part of the ARIA 1.0 path; kept unchanged. See [`DEPRECATIONS.md`](../DEPRECATIONS.md).

| File | Why it is historical |
|---|---|
| [`aid-example-v1.2.json`](aid-example-v1.2.json) | A credential under `spec_version: "1.2"`, issued before the cutover |
| [`verify-example.ts`](verify-example.ts) | Uses `@aria-registry/verify` 1.x |
| [`atp-policy-example.txt`](atp-policy-example.txt) | An ATP DNS policy; ATP is deprecated in favour of ARIA AP |
| [`holder-proof-example.json`](holder-proof-example.json) | A standalone holder proof that predates ARIA AP. It binds the method, target, nonce, audience and a time window, but not the request body or an ARIA AP operation, and its comment describes a private key delivered at issuance, which ARIA 1.0 does not do. Under ARIA 1.0 possession is proved by the request ARIA AP signs with the holder key |
