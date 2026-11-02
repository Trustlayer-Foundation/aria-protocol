# ARIA AP (TypeScript)

ARIA AP for ARIA 1.0: authenticate the receiver an agent calls and the agent's signed
request, admit the request, run each operation once, sign and verify its receipt, and
check a kept receipt later against retained evidence.

**Version 1.0.0.** Its transport (D3), its receipt format (D4), its scope rules (D5)
and, for now, refusing an attempt whose required human approval is missing or invalid
(D8) are decided, as are retrieval and the other receipt rules (D4). Vectors: [`conformance/ap`](../../conformance/ap/README.md);
schemas: [`schema/`](../../schema/README.md).

**It builds on the ARIA SDK.** ARIA AP takes the credential verifier of
[`@trustlayer-foundation/aria-sdk`](../aria-ts/README.md) (`createAp({ credentials: verifier })`) and reads
every credential and status result through it; it has no credential verification of its
own. Install both; a service that only checks credentials needs only the ARIA SDK.

- [API contract](API.md): the exchange step by step, the request profile, admission,
  operations and receipts, the client's tracker, historical receipts, and what is not
  offered yet.
- `examples/`: a receiver's identity endpoint and protected operation, an agent's client
  with recovery, and the replacement for `if (result.valid) execute()`.
- `schemas/`: byte-identical copies of the protocol's ARIA AP schemas, exported
  as `@trustlayer-foundation/aria-ap/schemas/<name>.json`.
- `test-d/`: the boundaries the types enforce.

`pnpm typecheck` compiles the sources, examples, tests and boundary checks against the
ARIA SDK's sources. `pnpm test` runs the AP1 vectors (requests through the real
challenge store, fingerprints, receipts, historical receipts, receiver identity, scopes,
and the sequences against the real ledger and tracker), the exchange end to end over a real verifier, and
over local HTTP. `pnpm build` writes `dist/` against the ARIA SDK's
built types (build that first).
