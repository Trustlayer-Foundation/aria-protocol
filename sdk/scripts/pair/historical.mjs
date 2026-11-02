// Historical receipts over the installed pair: a real exchange, its evidence exported
// as plain JSON, then verified in a new process a month later, when the receiver's
// credential has expired. Authenticity holds there; current authorization does not.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import * as ap from '@trustlayer-foundation/aria-ap';
import * as sdk from '@trustlayer-foundation/aria-sdk';
import { checks, fetchServing, holder, HOUR, NOW, ORIGIN, profile, statusList } from './fixtures.mjs';

const c = checks('historical');
const BANK = { origin: 'https://bank.example.test', did: 'did:aria:bank.example.test:transfers' };
const AGENT = 'did:aria:customer.example.test:payments-agent';
const OP = '55ee2e26-ffcc-40ca-b388-d12966453e48';
const clock = () => new Date(NOW);
const verifier = () => sdk.createVerifier({ trust: [profile], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fetchServing(() => statusList([])) } });

const agent = holder(AGENT, 31);
const bankHolder = holder(BANK.did, 32, { scopes: ['payments:transfer:receive'] });
const documents = new Map([agent, bankHolder].map((h) => [h.url, h.document]));
const agentVerifier = verifier();
const agentAp = ap.createAp({ credentials: agentVerifier, clock });
const bankVerifier = verifier();
const bankAp = ap.createAp({ credentials: bankVerifier, clock });
const self = { did: BANK.did, origin: BANK.origin, credential: bankVerifier.verifyCredential(bankHolder.document).credential, document: bankHolder.document, signer: bankHolder.signer };
const challenges = new ap.MemoryChallengeStore(clock);
const ledger = new ap.OperationLedger(bankAp, new ap.MemoryOperationStorage(), self);
const transfer = { name: 'transfer', class: 'unsafe-body', method: 'POST', path: '/v1/transfers', mediaType: 'application/json', scope: 'payments:transfer:create', minLevel: 'L1' };
const context = { receiver: { did: BANK.did, origin: BANK.origin }, operations: [transfer], challenges, resolveCredential: async (url) => documents.get(url) ?? null };

// The exchange, now.
const nonce = 'historical-nonce-0000000001';
const identified = await agentAp.verifyReceiverIdentity(await bankAp.identify(self, { nonce, audience: AGENT }, challenges), BANK, { nonce, audience: AGENT });
const signed = await agentAp.signRequest({
  request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode('{"amount":"10.00"}') },
  class: 'unsafe-body',
  operationId: OP,
  receiver: identified.receiver,
  credential: agentVerifier.verifyCredential(agent.document).credential,
  signer: agent.signer,
});
const presented = await bankAp.verifyPresentation(signed.request, context);
const admission = await bankAp.admit({ presentation: presented.presentation, status: await bankVerifier.checkStatus(presented.presentation.credential), authorize: async () => ({ allowed: true }) });
const begun = await ledger.begin(admission);
const settled = await ledger.settle(begun.claim, { state: 'completed', status: 201 });
await c.check('the exchange completes and the client verifies its receipt now', async () => {
  const r = await agentAp.verifyReceipt(JSON.stringify(settled.receipt), { receiver: identified.receiver, attempts: [signed.sent], mode: 'decision', transportStatus: 201 });
  return r.ok && r.statement.state === 'completed';
});

// What the client keeps: plain JSON, no object of this process. The bank is later revoked.
const evidence = {
  trust: { ...profile, keys: { mldsa65: Buffer.from(profile.keys.mldsa65).toString('base64'), ed25519: Buffer.from(profile.keys.ed25519).toString('base64') } },
  receipt: JSON.stringify(settled.receipt),
  attempts: [signed.sent],
  receiverDocument: bankHolder.document,
  statusList: statusList([32]),
};
writeFileSync('historical-evidence.json', JSON.stringify(evidence));
const later = new Date(NOW + 30 * 24 * HOUR).toISOString();
let out;
await c.check('a new process verifies the exported evidence', () => {
  out = JSON.parse(execFileSync(process.execPath, ['historical-verify.mjs', 'historical-evidence.json', later], { encoding: 'utf8' }).trim());
  return true;
});
await c.check('there the receiver credential has expired: verifyCredential refuses it', () => out?.current === 'expired');
await c.check('its authenticity holds, and the receipt verifies against it as completed', () => out?.authentic === true && out?.historical?.ok === true && out.historical.state === 'completed');
await c.check('findings: issued within validity, revoked by the retained list, signing time the receiver\'s claim', () =>
  out?.historical?.findings?.issuedAtWithinValidity === true && out.historical.findings.retainedStatus === 'revoked' && out.historical.findings.signingTime === 'receiver_claim');
await c.check('the authentic credential is not a current one: facts, standing and checkStatus refuse it', () => out?.refusedNow?.facts === 'AriaUsageError' && out.refusedNow.standing === 'AriaUsageError' && out.refusedNow.checkStatus === 'AriaUsageError');
await c.check('one altered byte of the exported receipt fails it', () => out?.altered === 'signature_invalid');
c.done();
