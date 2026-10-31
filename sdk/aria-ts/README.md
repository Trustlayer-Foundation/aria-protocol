# ARIA SDK (TypeScript)

The SDK for ARIA 1.0: verify an agent's credential and its exact status, authenticate
the agent and the receiver of an operation, admit it, and sign and verify its receipt.

**Not released.** This directory holds the API contract (increment S0): types,
signatures, examples and the migration guide, with no behavior yet. The package name is
provisional until its owner is confirmed, and `private` prevents publishing it.

- [API contract](API.md): the six results, runtime binding, trust boundary, operations
  and receipts, human approval, the credential profile and runtimes.
- [Migration from `@aria-registry/verify` 1.x](MIGRATION.md).
- `examples/`: a receiver's protected operation, an agent's client, a credential check
  and the replacement for `if (result.valid) execute()`.
- `test-d/`: the boundaries the types enforce.

`pnpm typecheck` compiles the sources, examples and boundary checks.
