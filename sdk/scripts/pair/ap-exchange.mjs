// ARIA AP over the installed pair: a real admission between the two packages, the
// refusals that must not reach the authorizer or the effect, the operation's
// minimum level through public admission, and the recovery of the original receipt.
import * as ap from '@aria-registry/ap';
import * as sdk from '@aria-registry/sdk';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { checks, fetchServing, holder, NOW, ORIGIN, profile, rejects, statusList } from './fixtures.mjs';

const c = checks('ap-exchange');
const BANK = { origin: 'https://bank.example.test', did: 'did:aria:bank.example.test:transfers' };
const AGENT = 'did:aria:customer.example.test:payments-agent';
const OP = '55ee2e26-ffcc-40ca-b388-d12966453e48';
const OP2 = 'e8f70dd3-bc7b-433f-9518-b08e7c662d2d';
const clock = () => new Date(NOW);
const revoked = [];
const verifier = () => sdk.createVerifier({ trust: [{ ...profile, maxLevel: 'L1' }], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(() => statusList(revoked)) } });

const agentL1 = holder(AGENT, 21);
const agentL0 = holder(AGENT, 22, { level: 'L0' });
const bankHolder = holder(BANK.did, 23, { scopes: ['payments:transfer:receive'] });
const documents = new Map([agentL1, agentL0, bankHolder].map((h) => [h.url, h.document]));

const agentVerifier = verifier();
const agentAp = ap.createAp({ credentials: agentVerifier, clock });
const bankVerifier = verifier();
const bankAp = ap.createAp({ credentials: bankVerifier, clock });
const self = { did: BANK.did, origin: BANK.origin, credential: bankVerifier.verifyCredential(bankHolder.document).credential, document: bankHolder.document, signer: bankHolder.signer };
const challenges = new ap.MemoryChallengeStore(clock);
const ledger = new ap.OperationLedger(bankAp, new ap.MemoryOperationStorage(), self);
const transfer = { name: 'transfer', class: 'unsafe-body', method: 'POST', path: '/v1/transfers', mediaType: 'application/json', scope: 'payments:transfer:create', minLevel: 'L1' };
const lookupOp = { name: 'lookup', class: 'retrieval', method: 'GET', path: '/v1/operations', query: ['operation'] };
const context = { receiver: { did: BANK.did, origin: BANK.origin }, operations: [transfer, lookupOp], challenges, resolveCredential: async (url) => documents.get(url) ?? null };
let effects = 0;
let authorizations = 0;
const authorize = async () => (authorizations++, { allowed: true });

let nonces = 0;
async function receiver() {
  const nonce = `pair-nonce-${String(++nonces).padStart(16, '0')}`;
  const r = await agentAp.verifyReceiverIdentity(await bankAp.identify(self, { nonce, audience: AGENT }, challenges), BANK, { nonce, audience: AGENT });
  if (!r.ok) throw new Error(`receiver ${r.reason}`);
  return r.receiver;
}
const as = (h) => ({ credential: agentVerifier.verifyCredential(h.document).credential, signer: h.signer });
const body = new TextEncoder().encode('{"amount":"10.00","currency":"EUR","to":"acc-2"}');
const signTransfer = async (who, operationId = OP) =>
  agentAp.signRequest({ request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body }, class: 'unsafe-body', operationId, receiver: await receiver(), ...as(who) });

/** The bank: authenticate, admit, claim, run once, sign. */
async function handle(request) {
  const presented = await bankAp.verifyPresentation(request, context);
  if (!presented.ok) return { status: presented.status, problem: presented.reason };
  const { presentation } = presented;
  const status = await bankVerifier.checkStatus(presentation.credential);
  if (presentation.operation.class === 'retrieval') {
    const allowed = await bankAp.admitLookup({ presentation, status });
    if (allowed.decision !== 'allow') return { status: allowed.status, problem: allowed.code };
    const found = await ledger.lookup(allowed);
    return found ? { status: 200, ...found } : { status: 404 };
  }
  const admission = await bankAp.admit({ presentation, status, authorize });
  if (admission.decision !== 'allow') return { status: admission.refusal.status, receipt: await bankAp.buildAttemptRefusal(admission.refusal, self) };
  const begun = await ledger.begin(admission);
  if (begun.kind === 'existing') return { status: begun.status, receipt: begun.governing };
  if (begun.kind === 'refused') return { status: begun.refusal.status, receipt: await bankAp.buildAttemptRefusal(begun.refusal, self) };
  effects++;
  const outcome = await ledger.settle(begun.claim, { state: 'completed', status: 201 });
  return { status: outcome.status, receipt: outcome.receipt };
}

// A legitimate operation, its answer lost, recovered by a retry and by a lookup.
const tracker = new ap.OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
const first = await signTransfer(agentL1);
tracker.record(first);
const original = await handle(first.request);
await c.check('a legitimate request is admitted across the two packages and completes once', () => original.status === 201 && original.receipt.outcome.state === 'completed' && effects === 1 && authorizations === 1);
const retry = await signTransfer(agentL1);
tracker.record(retry);
const again = await handle(retry.request);
await c.check('a retry with a fresh challenge gets the original receipt, bound to the first attempt, and no second effect', () => again.receipt.id === original.receipt.id && again.receipt.request.digest === first.sent.requestDigest && effects === 1);
await c.check('the client verifies it against the kept attempts: completed', async () => (await tracker.observe(agentAp, JSON.stringify(again.receipt), { mode: 'decision', transportStatus: again.status })).state === 'completed');
const lookup = await agentAp.signRequest({ request: { method: 'GET', target: `/v1/operations?operation=${OP}`, headers: {} }, class: 'retrieval', receiver: await receiver(), ...as(agentL1) });
const found = await handle(lookup.request);
await c.check('a signed lookup returns the stored operation receipts and gets none of its own', () => found.status === 200 && found.current.id === original.receipt.id && found.history.length === 1 && lookup.sent === null);

// Substitutions across the package boundary: refused before the authorizer or the effect.
const presented = await bankAp.verifyPresentation((await signTransfer(agentL1, OP2)).request, context);
const before = [authorizations, effects];
await c.check('status evidence from another credential verifier, about the same document, is refused', async () => {
  const foreign = await agentVerifier.checkStatus(agentVerifier.verifyCredential(agentL1.document).credential);
  return rejects(bankAp.admit({ presentation: presented.presentation, status: foreign, authorize }), sdk.AriaUsageError);
});
await c.check('status evidence of another document is indeterminate (503), nothing claimed', async () => {
  const a = await bankAp.admit({ presentation: presented.presentation, status: await bankVerifier.checkStatus(self.credential), authorize });
  return a.decision === 'indeterminate' && a.refusal.status === 503;
});
await c.check('another ARIA AP instance’s presentation is refused', () =>
  rejects(async () => ap.createAp({ credentials: bankVerifier, clock }).admit({ presentation: presented.presentation, status: await bankVerifier.checkStatus(presented.presentation.credential), authorize }), sdk.AriaUsageError),
);
await c.check('a copied presentation is refused', async () =>
  rejects(bankAp.admit({ presentation: { ...presented.presentation }, status: await bankVerifier.checkStatus(presented.presentation.credential), authorize }), sdk.AriaUsageError),
);
await c.check('none of them reached the authorizer or the effect', () => authorizations === before[0] && effects === before[1]);

// The operation's minimum level, through public admission.
const low = await handle((await signTransfer(agentL0, OP2)).request);
await c.check('an L0 credential under an L1 minimum is refused with a signed attempt refusal', () => low.status === 403 && low.receipt.outcome.code === 'aria.level_insufficient' && low.receipt.outcome.applies === 'attempt');
await c.check('the exported level list cannot change that decision', async () => {
  try {
    sdk.TRUST_LEVELS.reverse();
  } catch {}
  const r = await handle((await signTransfer(agentL0, OP2)).request);
  return sdk.TRUST_LEVELS.join() === 'L0,L1,L2,L3' && r.receipt.outcome.code === 'aria.level_insufficient';
});

// The exported schemas compile outside the repository, the AID one from the credential package.
await c.check('the identity response, receipts and lookup answer conform to the schemas the installed packages export', async () => {
  const require = createRequire(import.meta.url);
  const { default: Ajv2020 } = await import('ajv/dist/2020.js');
  const { default: addFormats } = await import('ajv-formats');
  const load = (spec) => JSON.parse(readFileSync(require.resolve(spec), 'utf8'));
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  ajv.addSchema(load('@aria-registry/sdk/schemas/aid-1.0.json'));
  for (const n of ['receipt', 'identity', 'lookup']) ajv.addSchema(load(`@aria-registry/ap/schemas/aria-ap-${n}-1.json`));
  const get = (n) => ajv.getSchema(`https://aria.bar/schema/aria-ap-${n}-1.json`);
  const statement = JSON.parse(JSON.stringify(await bankAp.identify(self, { nonce: 'schema-nonce-0000000001', audience: AGENT }, challenges)));
  return get('identity')(statement) && get('receipt')(JSON.parse(JSON.stringify(original.receipt))) && get('lookup')(JSON.parse(JSON.stringify({ current: found.current, history: found.history })));
});

// A revoked credential reads nothing.
revoked.push(21);
const revokedLookup = await handle((await agentAp.signRequest({ request: { method: 'GET', target: `/v1/operations?operation=${OP}`, headers: {} }, class: 'retrieval', receiver: await receiver(), ...as(agentL1) })).request);
await c.check('a lookup with a revoked credential is refused, unsigned', () => revokedLookup.status === 403 && revokedLookup.problem === 'aria.credential_revoked' && !revokedLookup.receipt);
await c.check('one effect in all', () => effects === 1);

c.done();
