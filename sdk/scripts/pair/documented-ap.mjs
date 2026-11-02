// ARIA AP's README receiver, run as written against the installed pair: the fixtures
// stand for the inputs it leaves to the reader, with a transfer that counts its effects,
// and an agent built on the same packages calls it. A completed transfer, its retry, a
// failure proven rolled back and an uncertain one.
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
      // The bank's own state: transfers that took effect, and the failures a check arms.
      'export const bank$ = { effects: 0, authorized: 0, signerDown: false, bankTimeout: false };',
      'const signer = { ...bank.signer, sign: async (bytes) => { if (bank$.signerDown) { bank$.signerDown = false; throw new Error(\'signer unavailable\'); } return bank.signer.sign(bytes); } };',
      'const resolveCredential = async (url) => (url === agent.url ? agent.document : null);',
      'const authorize = async () => (bank$.authorized++, { allowed: true });',
      // A timeout from the bank: the transfer may have happened.
      "const moveMoney = async () => { bank$.effects++; if (bank$.bankTimeout) { bank$.bankTimeout = false; throw Object.assign(new Error('bank timed out'), { unknown: true }); } };",
      // Anything else that fails inside the transaction undoes the transfer with it.
      "const inTransaction = async (work) => { const before = bank$.effects; try { return await work(); } catch (error) { if (error.unknown) throw error; bank$.effects = before; throw Object.assign(new Error('rolled back'), { rolledBack: true, cause: error }); } };",
      'const rolledBack = (error) => error.rolledBack === true;',
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
  const { bank$ } = receiver;
  const OP = '0b9c6f3e-6a51-4d55-9a0e-5d1c3f7b2a10';
  const tracker = new ap.OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
  const first = await attempt(OP);
  tracker.record(first);
  const answered = await receiver.handle(first.request);
  await c.check('it admits a signed request, transfers once and answers with a completed receipt', async () =>
    answered.status === 201 &&
    (await tracker.observe(agentAp, JSON.stringify(answered.receipt), { mode: 'decision', transportStatus: answered.status })).state === 'completed' &&
    bank$.effects === 1,
  );
  const retry = await attempt(OP);
  tracker.record(retry);
  const again = await receiver.handle(retry.request);
  await c.check('a retry gets the original receipt and transfers nothing', () => again.receipt?.id === answered.receipt.id && bank$.effects === 1);

  // The receiver's signer fails while settling: the transaction undoes the transfer.
  const OP2 = '6f1d2c4b-8e7a-4b3c-9d2e-1a5f7c9e0b42';
  const toSettle = await attempt(OP2);
  bank$.signerDown = true;
  const down = await receiver.handle(toSettle.request);
  await c.check('a failure proven rolled back answers 500 without a receipt, and nothing took effect', () => down.status === 500 && down.receipt === undefined && bank$.effects === 1);
  const recovered = await receiver.handle((await attempt(OP2)).request);
  await c.check('the released operation runs on retry, once', () => recovered.status === 201 && recovered.receipt?.outcome.state === 'completed' && bank$.effects === 2);

  // The bank times out: the transfer may have happened, so the operation stays locked.
  const OP3 = '2c8e4a6b-1d3f-4e5a-8b7c-9d0e1f2a3b4c';
  bank$.bankTimeout = true;
  const unknown = await receiver.handle((await attempt(OP3)).request);
  await c.check('an uncertain failure answers 500 without a receipt', () => unknown.status === 500 && unknown.receipt === undefined && bank$.effects === 3);
  const locked = [await receiver.handle((await attempt(OP3)).request), await receiver.handle((await attempt(OP3)).request)];
  await c.check('its retries get 409 aria.operation_in_progress and never transfer again', () =>
    locked.every((r) => r.status === 409 && r.receipt?.outcome.code === 'aria.operation_in_progress') && bank$.effects === 3,
  );

  const unsigned = await receiver.handle({ ...first.request, headers: { 'content-type': 'application/json' } });
  await c.check('an unsigned request gets an unsigned 400 or 401', () => [400, 401].includes(unsigned.status) && unsigned.receipt === undefined);
}

c.done();
