# Governance of this repository

TrustLayer Foundation A.C. stewards the ARIA protocol. This file records who can
approve a change here, and when that changes. It describes the repository, not
the Foundation: the constitution, the Consejo Directivo and the anti-capture
clauses are published at [aria.bar/governance](https://aria.bar/governance).

## Today: one approver, declared

`CODEOWNERS` names **@ivvmoreno** as the owner of the whole tree, with
**@trustlayer-foundationuser** as backup. No change enters `dev` or `main`
without that approval, and branch rules leave no bypass — administrators
included.

Anyone may contribute. Anyone with write access may open a pull request;
everyone else forks. Every author appears as the author of their own commits.
What is concentrated is authorisation, not participation, and it is written
down rather than exercised quietly.

**This concentration is transitory and stated as such.** A standard whose
changes one person can approve is not yet governed by a community, and saying so
is cheaper than being found out.

## When the Technical Steering Committee is seated (Q4 2026)

Seven members: three from civil society and academia, two from industry, one
from government, one from a developing nation. On the day it is seated:

1. `CODEOWNERS` passes to its members.
2. The approval rule goes from one to two.
3. This section is rewritten to describe what happened, not what is planned.

Composition and process: [aria.bar/governance](https://aria.bar/governance).

## Releases

`main` carries what is published, one tagged release per change, reached only by
a release pull request from `dev`. Tags under `v*` are created by the foundation
account and are signed. The tag and the release notes say what changed and what
it supersedes.

## Licences

Code under Apache 2.0 (`LICENSE-code`), documentation under CC-BY-4.0
(`LICENSE-docs`). Contributions carry a Developer Certificate of Origin sign-off;
there is no contributor licence agreement and no copyright assignment.
