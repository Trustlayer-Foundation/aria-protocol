// The credential package alone, installed from its tarball: it builds, installs and
// works without ARIA AP, and its trust interface refuses what it did not produce.
import * as sdk from '@aria-registry/sdk';
import { checks, credential, fetchServing, NOW, ORIGIN, profile, rejects, statusList } from './fixtures.mjs';

const { AriaUsageError, createVerifier, inspectCredential } = sdk;
const c = checks('credentials-only');
const make = (revoked = []) => createVerifier({ trust: [profile], clock: () => new Date(NOW), fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(statusList(revoked)) } });

await c.check('exports exactly the credential API', () => {
  const names = Object.keys(sdk).sort().join(',');
  return names === 'AriaUsageError,TRUST_LEVELS,canonicalJson,createVerifier,inspectCredential' || names;
});
await c.check('ARIA AP is not installed, and is not needed', async () => (await rejects(() => import('@aria-registry/ap'), Error)) === true);

const v = make();
const r = v.verifyCredential(credential);
await c.check('verifies a credential with both issuer signatures', () => r.ok === true || r.reason);
const status = await v.checkStatus(r.credential);
await c.check('reads the exact document’s status from the signed list', () => status.state === 'active' || status.state);
await c.check('its standing is good, judged by the verifier', () => v.standing(r.credential, status).state === 'good');
await c.check('facts come from the verifier’s record, holder key as 32 bytes', () => v.facts(r.credential).holderKey.publicKey.length === 32);

const revoked = make([7]);
const rr = revoked.verifyCredential(credential);
await c.check('a revoked document stands revoked', async () => revoked.standing(rr.credential, await revoked.checkStatus(rr.credential)).state === 'revoked');

const other = make();
const foreign = other.verifyCredential(credential).credential;
const foreignStatus = await other.checkStatus(foreign);
const refusals = {
  'a spread copy': () => v.facts({ ...r.credential, scopes: ['admin:all:write'] }),
  'a hand-made object': () => v.facts({ kind: 'verified-credential', did: r.credential.did }),
  'an inspection': () => v.facts(inspectCredential(credential)),
  'another verifier’s credential': () => v.facts(foreign),
  'another verifier’s status': () => v.standing(r.credential, foreignStatus),
  'a copied status': () => v.standing(r.credential, { ...status }),
  'a standing in place of status': () => v.standing(r.credential, v.standing(r.credential, status)),
};
for (const [label, fn] of Object.entries(refusals)) await c.check(`refuses ${label}`, () => rejects(fn, AriaUsageError));

c.done();
