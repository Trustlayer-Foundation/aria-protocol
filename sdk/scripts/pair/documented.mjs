// The documented code, run as written against the installed package: the protocol
// README's credential example, with the synthetic issuer, list and clock of
// fixtures.mjs standing for the `trust`, `fetch` and `credential` it leaves to the
// reader.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalJson } from '@trustlayer-foundation/aria-sdk';
import { checks, credential, NOW, profile } from './fixtures.mjs';

const c = checks('documented');
const here = new URL('.', import.meta.url);
const readme = readFileSync(new URL('README.protocol.md', here), 'utf8');
const block = /## Verify a credential[\s\S]*?```typescript\n([\s\S]*?)```/.exec(readme)?.[1];
await c.check('the README shows how to verify a credential', () => Boolean(block));

if (block) {
  const lines = block.split('\n');
  const imports = lines.filter((l) => l.startsWith('import '));
  const body = lines.filter((l) => !l.startsWith('import '));
  const source = [
    ...imports.map((l) => l.replace("'@trustlayer-foundation/aria-sdk'", "'./documented-sdk.mjs'")),
    "import { credential as fixture, fetchServing, ORIGIN, profile, statusList } from './fixtures.mjs';",
    'const trust = [profile];',
    'const fetch = { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList([])) };',
    'const credential = fixture;',
    ...body,
  ].join('\n');
  writeFileSync(new URL('documented-example.mjs', here), source);
  // The README's example sets no clock; the fixture's documents are dated.
  writeFileSync(
    new URL('documented-sdk.mjs', here),
    [
      "import * as sdk from '@trustlayer-foundation/aria-sdk';",
      "export * from '@trustlayer-foundation/aria-sdk';",
      `export const createVerifier = (options) => sdk.createVerifier({ clock: () => new Date(${NOW}), ...options });`,
    ].join('\n'),
  );

  const subject = credential.credentialSubject;
  await c.check('it runs, and finds the credential good', async () => {
    const logged = [];
    const log = console.log;
    console.log = (...args) => logged.push(args.join(' '));
    try {
      await import(new URL('documented-example.mjs', here).href);
    } finally {
      console.log = log;
    }
    return logged.join('\n') === `${subject.id} ${subject.trustLevel} good` || logged.join(' | ');
  });
}

// The key-set recipe, as written: its exported function, given a key set built from
// the fixture issuer and served by a stub, must trust exactly the pinned key.
const recipe = /### Trust from a published key set[\s\S]*?```javascript\n([\s\S]*?)```/.exec(readme)?.[1];
await c.check('the README shows how to trust a published key set', () => Boolean(recipe));
await c.check('the ARIA SDK README\'s quick start uses that recipe as written', () =>
  Boolean(recipe) && (/## Quick start[\s\S]*?```javascript\n([\s\S]*?)```/.exec(readFileSync(new URL('README.sdk.md', here), 'utf8'))?.[1] ?? '').includes(recipe));
if (recipe) {
  writeFileSync(new URL('documented-keyset.mjs', here), recipe);
  const { verifierFromKeyset } = await import(new URL('documented-keyset.mjs', here).href);
  const hex = (b) => Buffer.from(b).toString('hex');
  const entry = { key_id: profile.verificationMethod, suite: 'mldsa65-ed25519-2026', public_key_mldsa65: hex(profile.keys.mldsa65), public_key_ed25519: hex(profile.keys.ed25519) };
  const pinned = `sha256:${createHash('sha256').update(canonicalJson(entry)).digest('hex')}`;
  const serve = (keys) => async () => new Response(JSON.stringify({ issuer: profile.issuer, keys }), { headers: { 'content-type': 'application/json' } });
  const published = [{ ...entry, active_from: '2026-01-01T00:00:00Z', active_until: null, fingerprint: pinned }];
  const settings = { id: 'demo', maxLevel: profile.maxLevel, statusLists: profile.statusLists, verifier: { clock: () => new Date(NOW) } };
  const recipeFor = (keys, pin = pinned) => verifierFromKeyset({ keysetUrl: 'https://status.example.test/v1/keyset', pinned: pin, profile: settings, fetch: serve(keys) });
  await c.check('the pinned key verifies the credential', async () => (await recipeFor(published)).verifyCredential(credential).ok === true);
  await c.check('another pin trusts nothing', async () => {
    try { await recipeFor(published, 'sha256:' + '0'.repeat(64)); return 'trusted'; } catch { return true; }
  });
  await c.check('a key set claiming the pinned fingerprint for other keys is refused', async () => {
    const forged = [{ ...published[0], public_key_ed25519: hex(new Uint8Array(32).fill(7)) }];
    try { await recipeFor(forged); return 'trusted'; } catch { return true; }
  });
}

c.done();
