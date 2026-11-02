# ARIA SDK

`@trustlayer-foundation/aria-sdk` verifies an AI agent's ARIA credential (AID 1.0) and the
status of that exact document, under the issuers you choose to trust. It is the
TypeScript SDK of [ARIA 1.0](https://aria.bar/spec), for Node.js 20 or later, published by
TrustLayer Foundation under Apache-2.0.

## Which package do I need?

| You want to | Install |
|---|---|
| Show or record whether an agent's credential is genuine, current and not revoked | `@trustlayer-foundation/aria-sdk` |
| Decide whether an agent's request may run: authenticate it, admit it, run the operation once and sign its receipt; or call such a service as an agent | `@trustlayer-foundation/aria-sdk` and [`@trustlayer-foundation/aria-ap`](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ap-ts#readme) |

```bash
npm install @trustlayer-foundation/aria-sdk
```

[ARIA AP](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ap-ts#readme)
builds on this package's verifier and has no credential verification of its own. It
declares this package as a peer dependency, so a service that uses both installs both:
`npm install @trustlayer-foundation/aria-sdk @trustlayer-foundation/aria-ap`.

## Quick start

The SDK trusts no issuer by default. You state each issuer you accept in a trust profile.
Today's issuer, `did:aria:registry.aria.bar` behind [agent.bar](https://agent.bar), is a
demonstration: its credentials are not a production guarantee, and production ARIA 1.0
will use a new TrustLayer Foundation issuer and keys. It serves its keys at
`https://api.aria.bar/v1/keyset`. Being listed there grants no trust: you pin the anchor
fingerprint you obtained out of band, from the
[release manifest](https://github.com/trustlayer-foundation/aria-protocol/blob/main/release/aria-1.0.json),
and take the key it names. Save this as `quickstart.mjs` and run it with `node
quickstart.mjs`:

```javascript
import { canonicalJson, createVerifier } from '@trustlayer-foundation/aria-sdk';

/** A verifier trusting the key, in an issuer's published key set, that `pinned` names. */
export async function verifierFromKeyset({ keysetUrl, pinned, profile, fetch = globalThis.fetch }) {
  const keyset = await (await fetch(keysetUrl, { redirect: 'error' })).json();
  const entry = keyset.keys.find((k) => k.fingerprint === pinned && k.active_until === null);
  if (!entry) throw new Error('the key set holds no active key with the pinned fingerprint');
  const identity = canonicalJson({
    key_id: entry.key_id,
    suite: entry.suite,
    public_key_mldsa65: entry.public_key_mldsa65,
    public_key_ed25519: entry.public_key_ed25519,
  });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
  if (`sha256:${Buffer.from(digest).toString('hex')}` !== pinned) throw new Error('the pinned key does not match');
  return createVerifier({
    ...profile.verifier, // clock, fetch policy
    trust: [{
      id: profile.id, // 'demo' or 'production': your statement, not the issuer's
      issuer: keyset.issuer,
      verificationMethod: entry.key_id,
      keys: { mldsa65: Buffer.from(entry.public_key_mldsa65, 'hex'), ed25519: Buffer.from(entry.public_key_ed25519, 'hex') },
      maxLevel: profile.maxLevel,
      statusLists: profile.statusLists,
    }],
  });
}

const verifier = await verifierFromKeyset({
  keysetUrl: 'https://api.aria.bar/v1/keyset',
  pinned: 'sha256:4117aaac21272740756d02305a9fa7e2d84398fdd859d390b476539d57ec67b3',
  profile: {
    id: 'demo',
    maxLevel: 'L1',
    statusLists: ['https://api.aria.bar/v1/status/1'],
    verifier: { fetch: { allowedOrigins: ['https://api.aria.bar'] } },
  },
});

const credential = await (await fetch('https://api.aria.bar/v1/aids/did:aria:aria.bar:u-0dhNSrC9:commerce-search')).json();
const result = verifier.verifyCredential(credential);
if (!result.ok) throw new Error(`credential refused: ${result.reason}`);
const status = await verifier.checkStatus(result.credential);
const standing = verifier.standing(result.credential, status);
console.log(result.credential.did, result.credential.trustLevel, status.state, standing.state);
```

It prints the agent's DID, its level, `active` and `good`. Alter one byte of either
signature half and `verifyCredential` refuses it with `signature_invalid`; pin another
fingerprint and the function throws.

## Trust is your configuration

A verifier trusts exactly the profiles it is created with. There is no global setting and
no embedded key. A profile states:

| Field | What you state |
|---|---|
| `id` | Your name for this trust, such as `demo` or `production` |
| `issuer` | The issuer's DID |
| `verificationMethod` | The key id its proofs name, such as `did:aria:registry.aria.bar#key-1` |
| `keys` | Its two public keys, ML-DSA-65 and Ed25519, as bytes |
| `maxLevel` | The highest level you accept from it; a credential claiming more is refused |
| `statusLists` | The status lists it publishes; a credential naming another is refused |
| `onlineStatus` | Optional: an online status endpoint, asked only when you request it |

The fetch policy (`fetch.allowedOrigins`, timeouts, size bounds) bounds everything the SDK
fetches, and redirects are never followed. Without one, the verifier is offline and status
is `unavailable`. Credentials, status lists and online answers are untrusted input: nothing
in them selects a trust anchor or a fetch target.

## What each result tells you

| Call | Establishes | Does not establish |
|---|---|---|
| `verifyCredential(document)` returns `{ ok: true, credential }` or `{ ok: false, reason }` | The AID 1.0 schema; an issuer your profile names; the proof profile; both halves of the composite signature (ML-DSA-65 and Ed25519) over the canonical document; the signed validity window; the holder key; a level within your `maxLevel`; a status list in your `statusLists` | Who presents the credential; its status |
| `checkStatus(credential)` returns status evidence | The status of that exact document: `active` or `revoked` from the signed status list it names, verified under the same profile and fresh enough, or `unavailable` with a reason | Anything about another document of the same DID |
| `standing(credential, status)` | Whether that document stands now: `good`, `revoked`, `superseded`, `not_valid_now` or `unknown` | That anyone presents it, or may do anything with it |
| `inspectCredential(document)` | The fields a document carries, for display; `verified` is always `false` | Anything verified |

None of these results is permission to act. Whether an agent may do something is
decided by ARIA AP's admission, after the agent proves possession of its holder key.
`unknown` is not `good`. The SDK verifies credentials you hold; it is not a DID resolver.

## Documentation

- [API contract](https://github.com/trustlayer-foundation/aria-protocol/blob/main/sdk/aria-ts/API.md):
  every result, failure reason, the trust boundary, status and historical authenticity.
- [Example: checking a credential and its standing](https://github.com/trustlayer-foundation/aria-protocol/blob/main/sdk/aria-ts/examples/verify-credential.ts).
- [Migration from `@aria-registry/verify` 1.x](https://github.com/trustlayer-foundation/aria-protocol/blob/main/sdk/aria-ts/MIGRATION.md),
  which is no longer served by npm.
- [ARIA AP](https://github.com/trustlayer-foundation/aria-protocol/tree/main/sdk/aria-ap-ts#readme),
  for requests, admission and receipts.
- [Developer guide](https://aria.bar/developers) and
  [specification](https://aria.bar/spec).
- [Release manifest](https://github.com/trustlayer-foundation/aria-protocol/blob/main/release/aria-1.0.json):
  the package integrities and the demonstration issuer's anchor.
- [Conformance vectors](https://github.com/trustlayer-foundation/aria-protocol/tree/main/conformance),
  for any implementation.

## Support

- Questions and bugs:
  [GitHub issues](https://github.com/trustlayer-foundation/aria-protocol/issues).
- Security vulnerabilities: security@trustlayer.foundation, never a public issue
  ([security policy](https://github.com/trustlayer-foundation/aria-protocol/blob/main/SECURITY.md)).

## Development

In the [repository](https://github.com/trustlayer-foundation/aria-protocol):
- `pnpm typecheck` compiles the sources, examples, tests and boundary checks.
- `pnpm test` runs the tests, with synthetic issuer keys made per run.
- `pnpm build` writes `dist/`.
- `node ../scripts/check-pair.mjs` packs this package and ARIA AP and checks both as
  installed artifacts, alone and together.

The README that npm shows for a version is the one packed in it; this file is newer than
1.0.0's.
