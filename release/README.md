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

## Publishing the packages

The packages are `@trustlayer-foundation/aria-sdk` and `@trustlayer-foundation/aria-ap`,
in the npm organization `trustlayer-foundation`. The archives published are the ones the
manifest pins, never a fresh pack: packing again gives other bytes. Each step needs its
own approval, and the issuer's public key set is served before either package is
published.

```bash
openssl dgst -sha512 -binary trustlayer-foundation-aria-sdk-1.0.0.tgz | base64   # equals the manifest's integrity
node release/check.mjs --final --archives trustlayer-foundation-aria-sdk-1.0.0.tgz trustlayer-foundation-aria-ap-1.0.0.tgz --site <aria-landing>
node sdk/scripts/check-pair.mjs --archives trustlayer-foundation-aria-sdk-1.0.0.tgz trustlayer-foundation-aria-ap-1.0.0.tgz
npm publish ./trustlayer-foundation-aria-sdk-1.0.0.tgz --access public                # the SDK first: ARIA AP's peer
npm publish ./trustlayer-foundation-aria-ap-1.0.0.tgz --access public
npm view @trustlayer-foundation/aria-sdk@1.0.0 dist.integrity                         # equals the manifest's, for both
npm view @trustlayer-foundation/aria-ap@1.0.0 dist.integrity
```

A published version is immutable and never reused; a mistake is corrected with a new
version. 1.0.0 was published this way on 2 November 2026. npm refuses to publish from an
account without two-factor authentication.

npm shows the README, description and keywords packed in each version. The repository's
package READMEs and manifests have changed since 1.0.0; npm's pages show them only when a
later version is published, and the 1.0.0 archives and their integrities stay as they are.
