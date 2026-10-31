// Both packages installed from their tarballs: ARIA AP resolves the application's
// copy of the credential package through its peer dependency, and uses its verifier.
import { readdirSync } from 'node:fs';
import * as ap from '@aria-registry/ap';
import * as sdk from '@aria-registry/sdk';
import { checks, credential, fetchServing, NOW, ORIGIN, profile, rejects, statusList } from './fixtures.mjs';

const c = checks('pair');
await c.check('ARIA AP exports its own API only', () => {
  const names = Object.keys(ap).sort().join(',');
  return names === 'NotYetImplemented,OperationLedger,OperationTracker,createAp' || names;
});
await c.check('one copy of the credential package: none nested under ARIA AP', () => {
  let nested = [];
  try {
    nested = readdirSync('node_modules/@aria-registry/ap/node_modules');
  } catch {}
  return nested.length === 0 || nested.join(',');
});

const verifier = sdk.createVerifier({ trust: [profile], clock: () => new Date(NOW), fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList([])) } });
const instance = ap.createAp({ credentials: verifier });
await c.check('createAp takes the application’s verifier', () => typeof instance.admit === 'function');
await c.check('createAp refuses anything that is not a credential verifier, with the application’s AriaUsageError', () => rejects(() => ap.createAp({ credentials: {} }), sdk.AriaUsageError));

const r = verifier.verifyCredential(credential);
const status = await verifier.checkStatus(r.credential);
await c.check('a verified credential is not a presentation: admission refuses it', () => rejects(instance.admit({ presentation: r.credential, status, authorize: async () => ({ allowed: true }) }), sdk.AriaUsageError));
await c.check('a hand-made presentation is refused', () => rejects(instance.admit({ presentation: { kind: 'verified-presentation', credential: r.credential }, status, authorize: async () => ({ allowed: true }) }), sdk.AriaUsageError));
await c.check('the AP2 entry points say so', () => rejects(instance.verifyPresentation({ method: 'GET', target: '/', headers: {} }, {}), ap.NotYetImplemented));

c.done();
