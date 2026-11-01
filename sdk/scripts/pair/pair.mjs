// Both packages installed from their tarballs: ARIA AP resolves the application's
// copy of the credential package through its peer dependency, and uses its verifier.
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import * as ap from '@trustlayer-foundation/aria-ap';
import * as sdk from '@trustlayer-foundation/aria-sdk';
import { checks, credential, fetchServing, NOW, ORIGIN, profile, rejects, statusList } from './fixtures.mjs';

const c = checks('pair');
await c.check('ARIA AP exports its own API only', () => {
  const names = Object.keys(ap).sort().join(',');
  return names === 'AdmissionExpired,InvariantViolation,MemoryChallengeStore,MemoryOperationStorage,OperationLedger,OperationTracker,StaleClaim,createAp' || names;
});
await c.check('one copy of the credential package: none nested under ARIA AP', () => {
  let nested = [];
  try {
    nested = readdirSync('node_modules/@trustlayer-foundation/aria-ap/node_modules');
  } catch {}
  return nested.length === 0 || nested.join(',');
});

await c.check('ARIA AP exports its provisional schemas by path', () => {
  const require = createRequire(import.meta.url);
  const ids = ['receipt', 'identity', 'lookup'].map((n) => JSON.parse(readFileSync(require.resolve(`@trustlayer-foundation/aria-ap/schemas/aria-ap-${n}-1.json`), 'utf8')).$id);
  return ids.join() === ['receipt', 'identity', 'lookup'].map((n) => `https://aria.bar/schema/aria-ap-${n}-1.json`).join() || ids.join();
});

const verifier = sdk.createVerifier({ trust: [profile], clock: () => new Date(NOW), fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList([])) } });
const instance = ap.createAp({ credentials: verifier });
await c.check('createAp takes the application’s verifier', () => typeof instance.admit === 'function');
await c.check('createAp refuses anything that is not a credential verifier, with the application’s AriaUsageError', () => rejects(() => ap.createAp({ credentials: {} }), sdk.AriaUsageError));

const r = verifier.verifyCredential(credential);
const status = await verifier.checkStatus(r.credential);
await c.check('a verified credential is not a presentation: admission refuses it', () => rejects(instance.admit({ presentation: r.credential, status, authorize: async () => ({ allowed: true }) }), sdk.AriaUsageError));
await c.check('a hand-made presentation is refused', () => rejects(instance.admit({ presentation: { kind: 'verified-presentation', credential: r.credential }, status, authorize: async () => ({ allowed: true }) }), sdk.AriaUsageError));
await c.check('a ledger needs this instance’s receiver credential and its holder key', () => rejects(() => new ap.OperationLedger(instance, new ap.MemoryOperationStorage(), { did: r.credential.did, credential: r.credential, signer: { keyId: 'other', algorithm: 'ed25519', sign: async () => new Uint8Array(64) } }), sdk.AriaUsageError));

c.done();
