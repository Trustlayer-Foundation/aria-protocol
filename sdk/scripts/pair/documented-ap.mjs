// ARIA AP's README receiver, run as written against the installed pair: the fixtures
// stand for the inputs it leaves to the reader, and an agent built on the same packages
// calls it, once and then again.
import { readFileSync, writeFileSync } from 'node:fs';
import * as ap from '@trustlayer-foundation/aria-ap';
import { checks, fetchServing, holder, NOW, ORIGIN, profile, statusList } from './fixtures.mjs';

const c = checks('documented-ap');
const here = new URL('.', import.meta.url);
const readme = readFileSync(new URL('README.ap.md', here), 'utf8');
const block = /## Quick start: a receiver[\s\S]*?```javascript\n([\s\S]*?)```/.exec(readme)?.[1];
await c.check('ARIA AP\'s README shows a receiver', () => Boolean(block));

if (block) {
  const BANK = { origin: 'https://bank.example.test', did: 'did:aria:bank.example.test:transfers' };
  const AGENT = 'did:aria:customer.example.test:payments-agent';
  const lines = block.split('\n');
  const imports = lines.filter((l) => l.startsWith('import '));
  const statements = lines.filter((l) => !l.startsWith('import '));
  writeFileSync(
    new URL('documented-receiver.mjs', here),
    [
      ...imports.map((l) => l.replace("'@trustlayer-foundation/aria-sdk'", "'./documented-receiver-sdk.mjs'")),
      "import { fetchServing, holder, ORIGIN, profile, statusList } from './fixtures.mjs';",
      `export const bank = holder('${BANK.did}', 41, { scopes: ['payments:transfer:receive'] });`,
      `export const agent = holder('${AGENT}', 42);`,
      'const trust = [profile];',
      'const fetch = { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList([])) };',
      `const did = '${BANK.did}';`,
      `const origin = '${BANK.origin}';`,
      'const ownDocument = bank.document;',
      'const signer = bank.signer;',
      'const resolveCredential = async (url) => (url === agent.url ? agent.document : null);',
      'export let authorized = 0;',
      'const authorize = async () => (authorized++, { allowed: true });',
      ...statements,
    ].join('\n'),
  );
  // The README sets no clock; the fixture's documents are dated.
  writeFileSync(
    new URL('documented-receiver-sdk.mjs', here),
    [
      "import * as sdk from '@trustlayer-foundation/aria-sdk';",
      "export * from '@trustlayer-foundation/aria-sdk';",
      `export const createVerifier = (options) => sdk.createVerifier({ clock: () => new Date(${NOW}), ...options });`,
    ].join('\n'),
  );

  const receiver = await import(new URL('documented-receiver.mjs', here).href);
  const { createVerifier } = await import(new URL('documented-receiver-sdk.mjs', here).href);
  const agentVerifier = createVerifier({ trust: [profile], fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList([])) } });
  const agentAp = ap.createAp({ credentials: agentVerifier });
  const as = { credential: agentVerifier.verifyCredential(receiver.agent.document).credential, signer: receiver.agent.signer };
  const body = new TextEncoder().encode('{"amount":"10.00","currency":"EUR","to":"acc-2"}');
  let nonces = 0;
  const attempt = async (operationId) => {
    const nonce = `readme-nonce-${String(++nonces).padStart(16, '0')}`;
    const verified = await agentAp.verifyReceiverIdentity(await receiver.identity(nonce, AGENT), BANK, { nonce, audience: AGENT });
    if (!verified.ok) throw new Error(`receiver ${verified.reason}`);
    return agentAp.signRequest({
      request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body },
      class: 'unsafe-body', operationId, receiver: verified.receiver, ...as,
    });
  };
  const OP = '0b9c6f3e-6a51-4d55-9a0e-5d1c3f7b2a10';
  const tracker = new ap.OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
  const first = await attempt(OP);
  tracker.record(first);
  const answered = await receiver.handle(first.request);
  await c.check('it admits a signed request and completes it with a receipt', async () =>
    answered.status === 201 &&
    (await tracker.observe(agentAp, JSON.stringify(answered.receipt), { mode: 'decision', transportStatus: answered.status })).state === 'completed' &&
    receiver.authorized === 1,
  );
  const retry = await attempt(OP);
  tracker.record(retry);
  const again = await receiver.handle(retry.request);
  await c.check('a retry gets the original receipt and runs nothing again', () => again.receipt?.id === answered.receipt.id && receiver.authorized === 2);
  const unsigned = await receiver.handle({ ...first.request, headers: { 'content-type': 'application/json' } });
  await c.check('an unsigned request gets an unsigned 400 or 401', () => [400, 401].includes(unsigned.status) && unsigned.receipt === undefined);
}

c.done();
