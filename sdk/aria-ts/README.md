# ARIA SDK (TypeScript)

The ARIA SDK for ARIA 1.0: inspect and verify an agent's credential, and establish the
status of that exact document.

**Version 1.0.0.** This directory holds the API contract and its implementation:
inspection, per-verifier trust, credential verification, exact-instance status, and the
trust interface packages built on it use. It trusts no issuer by default: each verifier
states the issuers it accepts.

**Which package.** This repository has two SDK packages. A service that only checks
credentials installs this one. A service that authenticates agent requests, admits them
or exchanges receipts also installs [ARIA AP](../aria-ap-ts/README.md), which builds on
this package's verifier and has none of its own. `@aria-registry/verify` 1.x is no
longer served by npm; see the migration guide.

- [API contract](API.md): the results, runtime provenance, `facts` and `standing`, the
  trust boundary, credential and status verification, historical authenticity, the
  credential profile, runtimes.
- [Migration from `@aria-registry/verify` 1.x](MIGRATION.md).
- `examples/verify-credential.ts`: checking a credential and its standing, which is not
  admitting a request.
- `test-d/`: the boundaries the types enforce.

`pnpm typecheck` compiles the sources, examples, tests and boundary checks; `pnpm test`
runs the tests, with synthetic issuer keys made per run; `pnpm build` writes `dist/`.
`node ../scripts/check-pair.mjs` packs this package and ARIA AP and checks both as
installed artifacts, alone and together.
