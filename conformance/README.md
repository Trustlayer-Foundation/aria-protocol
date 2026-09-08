# ARIA Conformance

> **Status:** published, and running. `run.mjs` executes on every pull request.

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
run.mjs                          the runner each implementation embeds
package.json                     one dependency, a JSON-LD processor
vectors/
  canonical-json.json            canonical serialisation and identity commitment, byte for byte
  abnf-cases.json                did:aria identifiers that must be accepted / rejected, with reasons
  context-credentials-v2.json     the W3C VC v2 context, pinned so a run is offline and deterministic
```

Run it against an implementation:

```bash
cd conformance && npm install      # a JSON-LD processor, for the expansion check
node run.mjs --sdk path/to/entry.mjs
```

Without the processor the expansion check skips and says so. CI passes `--strict`,
which turns that skip into a failure: a check that quietly skips proves nothing.

`expand-live.mjs` is the same check with nothing pinned — it fetches a credential
and the context over the network, exactly as published, and expands in safe mode.
It is the version a reviewer runs to confirm the claim rather than take it:

```bash
node conformance/expand-live.mjs did:aria:<domain>:<agent>
```

**What is not here yet**, named so nobody assumes otherwise:

```
vectors/manifest-validation.json   enrollment manifests, accepted / rejected with reasons
```

The composite AND — a credential with one half of the signature altered must fail —
lives in the SDK suite as `test/vector11.test.ts` rather than here, because it needs
signing keys to build the tampered cases. Moving it to a vector file, so a second
implementation can run it without the SDK, is the next thing this directory needs.

## The rule that makes this work

**Implementations share vectors, never code.**

The authority is Rust and the Registration Authority is TypeScript. The manifest
validator will therefore exist twice, and the real risk is not that either one is
wrong — it is that they drift apart, which is precisely how a published protocol
breaks.

There is no bridge between the two implementations, and building one would be worse
than the problem. What is shared is the **case set**: for every input, whether it is
accepted or rejected and for what reason. Both sides test against it.

Today there is exactly one published SDK, in TypeScript. The case set is what will make
the second one possible, which is the whole reason it exists before it is needed.

## The checks

| # | Check | Who runs it | What it protects |
|---|---|---|---|
| 1 | Canonical serialisation and identity commitment match the vectors byte for byte | every implementation | the cross-implementation contract |
| 1b | The ARIA context redefines no term the W3C VC v2 context defines | every implementation | that the two contexts compose. Ours is listed second and declares `@protected`: a term redefined here does not shadow the standard one, it makes a conforming processor reject the credential outright |
| 1c | The example and a production-shaped credential expand losslessly | every implementation | that nothing is silently dropped. Run by `jsonld` in safe mode, which throws on a dropped property or a relative IRI — the only version of this claim a reviewer can reproduce |
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

Each implementation embeds the harness for its language and points it at `vectors/`,
exiting non-zero on any failure. `run.mjs` is the JavaScript one; it prints `PASS`,
`FAIL` or `SKIP` per check, and skips rather than passes what it cannot test — today
the `did:aria` cases, because no implementation exports a parser to run them against.
