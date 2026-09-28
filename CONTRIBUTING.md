# Contributing to ARIA Protocol

ARIA is an open standard. Anyone may propose a change; the credit stays with
whoever wrote it. What is concentrated is *authorisation*, not participation —
see [GOVERNANCE.md](GOVERNANCE.md) for who approves today and when that changes.

## The flow

| Branch | What it is |
|---|---|
| `main` | What is published. One tagged release per change. Reached only by a release pull request from `dev`. |
| `dev` | Integration. Every change lands here first, by pull request, reviewed. |
| `spec/…` `sdk/…` `docs/…` `fix/…` `chore/…` | Your work. Branch from `dev`, pull request back to `dev`. |

Branch names must match `(spec|sdk|docs|fix|chore|release)/<topic>`; continuous
integration checks it. External contributors fork and open the pull request the
same way.

### Releasing: why `dev` cannot be merged into `main` directly

`main` accepts squash merges only, and only through a pull request. Squashing
collapses a branch into one new commit, so after a release `main` holds a commit
whose contents `dev` has and whose identity it does not. The two histories
diverge by construction, and every later attempt to merge `dev` into `main`
conflicts over changes that are already there.

A release is therefore a branch off `main` carrying `dev`'s tree, not a merge of
`dev`:

```bash
git fetch origin
git checkout -B release/<topic> origin/main
git read-tree -u --reset origin/dev     # main's history, dev's exact tree
git commit -s -S -m "release: <what is being published>"
gh pr create --base main --head release/<topic>
```

After it merges, open a second pull request to bring the squashed release commit
back into `dev`, so the next release starts from an identity the two branches
share. Rebase-and-merge would avoid the divergence and is not used: it rewrites
commits, which drops their signatures.

## Every commit

```bash
git commit -s -m "sdk: describe the change in the imperative"
```

- **`-s` is required.** It adds `Signed-off-by`, the Developer Certificate of
  Origin: you assert you have the right to contribute this under the repository
  licences. Continuous integration rejects commits without it.
- **No tool trailers.** `Co-Authored-By`, `Generated-By` and `Assisted-By` are
  refused. Contributors are people with names. Use whatever tools you like;
  the commit is yours and you are answerable for it.
- **Conventional prefixes**: `spec:`, `sdk:`, `docs:`, `fix:`, `chore:`.
- **Signing is recommended** on `dev` and **required on `main`** and on tags.
  Requiring signatures from every external contributor would close the door
  that the Developer Certificate of Origin already keeps honest.

Enable the local hook so a bad message never reaches a pull request:

```bash
git config core.hooksPath .githooks
```

## The vectors are the contract

`conformance/vectors/` is what makes a second implementation possible. Where the
deployed behaviour and the specification text disagree on the wire format, the
vectors decide and the text is the bug.

**Any change to a wire format adds a vector in the same pull request.** A new
identifier shape adds accept and reject cases; a serialisation change adds a
canonicalisation vector. A pull request that changes a format without a vector
will be asked for one.

## What a pull request is checked against

- `sdk-tests` — the SDK test suite.
- `identity-guard` — sign-off present, no tool trailers.
- `neutrality` — the Norm defines properties, never vendors or schemes. No
  commercial scheme or laboratory names outside `CHANGELOG.md` and `DEPRECATIONS.md`.
- `conformance` — the vector harness. Advisory until the harness lands, then required.
- `branch-name` — the convention above.

## Proposing a change to the specification

The normative text lives at [aria.bar/spec](https://aria.bar/spec). Open an issue
using the *specification change* template first: say what breaks today, what you
propose, and which requirement or invariant it touches. Changes that affect
credentials already issued run into [INVARIANTS.md](INVARIANTS.md) — read it
before writing the pull request, because most of it cannot move.

## Security

Do not open an issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Dependencies

There is no scheduled dependency bot on this repository. Three runtime
dependencies, one of which implements the signature suite that
[INVARIANTS.md](INVARIANTS.md) fixes and that credentials already signed depend
on: a bot proposing to move them is noise at best and a supply-chain decision at
worst. Security advisories still arrive, through Dependabot alerts, and are
acted on deliberately.

Updating a dependency is a pull request like any other, with a reason in the
message and the SDK test suite green.
