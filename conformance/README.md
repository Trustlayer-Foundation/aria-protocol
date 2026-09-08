# ARIA Conformance

> **Status:** draft, staged for `trustlayer-foundation/aria-protocol`.

A package of **vectors and a harness**, not a CI job.

## Why it is shaped this way

The obvious design is a test suite that runs against the components. That does not
work here: the authority implementation is a private repository, so a public CI can
never reach it. And a conformance suite that only the authority can run is worth
very little to anyone else.

So conformance is published as an artifact that **each implementation runs in its own
CI** — the authority, every SDK, and any registry that wants to federate.

The side benefit is the important one: it turns accreditation from a conversation
into a criterion. A prospective Registration Authority downloads this package, runs
it, and presents the result. Nobody has to take anybody's word for it.

## What is in here

```
vectors/
  canonical-json.json        JCS output that every implementation must match, byte for byte
  abnf-cases.json            did:aria identifiers that must be accepted / rejected, with reasons
  manifest-validation.json   enrollment manifests that must be accepted / rejected, with reasons
harness/                     the runner each implementation embeds
```

## The rule that makes this work

**Implementations share vectors, never code.**

The authority is Rust and the Registration Authority is TypeScript. The manifest
validator will therefore exist twice, and the real risk is not that either one is
wrong — it is that they drift apart, which is precisely how a published protocol
breaks.

There is no bridge between the two implementations, and building one would be worse
than the problem. What is shared is the **case set**: for every input, whether it is
accepted or rejected and for what reason. Both sides test against it. This is the
same pattern that already keeps four independent SDK implementations producing
byte-identical canonical JSON.

## The checks

| # | Check | Who runs it | What it protects |
|---|---|---|---|
| 1 | Canonical JSON matches the vectors byte for byte | every implementation | the cross-implementation contract |
| 2 | A freshly issued AID verifies against the **published, unmodified** verify SDK | the authority | that the protocol did not change by accident |
| 3 | Existing production AIDs still verify | the authority | signing key continuity |
| 4 | ABNF cases accepted and rejected exactly | every implementation | consistency with the W3C registry entry |
| 5 | Manifest validation cases accepted and rejected with the stated reason | authority and RA | drift between the two validators |

**Check 2 is the one that matters most and the easiest to skip.** If the verify SDK
needs *any* modification to accept newly issued credentials, the protocol changed
and the release must stop.

## Fixtures and privacy

Check 3 needs real credentials, and real credentials carry `principal.legalName` and
`registryRef`. **No production credential goes in this repository** — it is public,
and git is forever.

The vectors here are synthetic. The runner points at real credentials through an
environment variable, from outside the repository.

## Running it

Each implementation embeds the harness for its language and points it at
`vectors/`. Exit non-zero on any failure. See the language-specific README under
`harness/`.
