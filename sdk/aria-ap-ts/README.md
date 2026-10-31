# ARIA AP (TypeScript)

ARIA AP for ARIA 1.0: authenticate an agent's request and the receiver it calls, admit
the request, run each operation once, and sign and verify its receipt.

**Not released.** This directory holds the API contract and the admission rules; every
entry point throws `NotYetImplemented('AP2')` until AP2. The package name is provisional
until its owner is confirmed, and `private` prevents publishing it. The wire profile is
provisional too: its vectors in [`conformance/ap`](../../conformance/ap/README.md) encode
recommended options for decisions that are still open.

**It builds on the ARIA SDK.** ARIA AP takes the credential verifier of
[`@aria-registry/sdk`](../aria-ts/README.md) (`createAp({ credentials: verifier })`) and reads
every credential and status result through it; it has no credential verification of its
own. Install both; a service that only checks credentials needs only the ARIA SDK.

- [API contract](API.md): what it builds on and how trust crosses the package boundary,
  its results, operations and receipts, human approval.
- `examples/`: a receiver's protected operation, an agent's client, and the replacement
  for `if (result.valid) execute()`.
- `test-d/`: the boundaries the types enforce.

`pnpm typecheck` compiles the sources, examples, tests and boundary checks against the
ARIA SDK's sources; `pnpm test` runs the admission-rule tests through a real verifier;
`pnpm build` writes `dist/` against the ARIA SDK's built types (build that first).
