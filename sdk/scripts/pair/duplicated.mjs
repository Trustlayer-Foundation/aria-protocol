// Two copies of the credential package in one process (a duplicated install): each
// verifier trusts only its own results, so duplication fails closed, never open.
import * as a from '@aria-registry/sdk';
import * as ap from '@aria-registry/ap';
import { checks, credential, NOW, profile, rejects } from './fixtures.mjs';

const b = await import(new URL('./second/node_modules/@aria-registry/sdk/dist/index.js', import.meta.url).href);
const c = checks('duplicated');
await c.check('the two copies are distinct modules', () => a.createVerifier !== b.createVerifier);

const va = a.createVerifier({ trust: [profile], clock: () => new Date(NOW) });
const vb = b.createVerifier({ trust: [profile], clock: () => new Date(NOW) });
const ra = va.verifyCredential(credential).credential;
const rb = vb.verifyCredential(credential).credential;
const sa = await va.checkStatus(ra);

await c.check('copy B refuses copy A’s credential', () => rejects(() => vb.facts(ra), b.AriaUsageError));
await c.check('copy A refuses copy B’s credential', () => rejects(() => va.facts(rb), a.AriaUsageError));
await c.check('copy B refuses copy A’s status for its own credential', () => rejects(() => vb.standing(rb, sa), b.AriaUsageError));
await c.check('ARIA AP over copy B’s verifier accepts it and still refuses copy A’s results', async () => {
  const instance = ap.createAp({ credentials: vb });
  return rejects(instance.admit({ presentation: ra, status: sa, authorize: async () => ({ allowed: true }) }), Error);
});
c.done();
