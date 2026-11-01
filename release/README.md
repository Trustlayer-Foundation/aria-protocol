# Release manifest

`aria-1.0.json` is what ARIA 1.0 ships, pinned by hash: the two packages and their
npm integrities, every published schema, the context, the federation contract, the
conformance vectors, and the files of the specification edition on the site. It also
states the capabilities as implemented, the decisions taken and pending, and the
compatibility obligations a release must keep.

```bash
node release/check.mjs                                  # against this repository
node release/check.mjs --archives <sdk.tgz> <ap.tgz>    # and the archives to publish
node release/check.mjs --site <aria-landing checkout>   # and the edition's files
node release/check.mjs --final --archives … --site …   # nothing left pending
```

The state is `candidate` until every decision is taken, the package names are
confirmed and the archives are approved; `--final` refuses anything less. A change to a
pinned file fails the check until the manifest is updated (`--update` rewrites the
repository and edition hashes; package integrities are set when the archives are
approved, never recomputed by the tool).
