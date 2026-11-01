// The documented code, run as written against the installed package: the protocol
// README's credential example, with the synthetic issuer, list and clock of
// fixtures.mjs standing for the `trust`, `fetch` and `credential` it leaves to the
// reader.
import { readFileSync, writeFileSync } from 'node:fs';
import { checks, credential, NOW } from './fixtures.mjs';

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
    ...imports.map((l) => l.replace("'@aria-registry/sdk'", "'./documented-sdk.mjs'")),
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
      "import * as sdk from '@aria-registry/sdk';",
      "export * from '@aria-registry/sdk';",
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

c.done();
