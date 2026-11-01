// An agent and a bank, each with its own credential verifier and ARIA AP instance,
// over one synthetic issuer. Real AID 1.0 documents, real status lists, real
// signatures; keys are made per process and never written.
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { createVerifier, type Did, type TrustLevel, type VerifiedCredential, type Verifier } from '@aria-registry/sdk';
import {
  createAp,
  MemoryChallengeStore,
  MemoryOperationStorage,
  OperationLedger,
  type Ap,
  type ApprovalEvidence,
  type HttpRequestLike,
  type OperationDescriptor,
  type Receipt,
  type ReceiverPin,
  type ReceiverSelf,
  type Signer,
  type VerifiedReceiver,
} from '../src';
import { credential as baseCredential, fakeFetch, LIST_URL, newIssuer, NOW, profile, sign, statusList } from './fixtures';

export { NOW };
export const BANK: ReceiverPin = { origin: 'https://bank.example.test', did: 'did:aria:bank.example.test:transfers' };
export const AGENT: Did = 'did:aria:customer.example.test:payments-agent';
export const ORIGIN = 'https://status.example.test';

export const transfer: OperationDescriptor = {
  name: 'transfers.create',
  class: 'unsafe-body',
  method: 'POST',
  path: '/v1/transfers',
  mediaType: 'application/json',
  scope: 'payments:transfer:create',
  minLevel: 'L1',
  onMissingApproval: 'refuse',
};
export const lookupOp: OperationDescriptor = { name: 'operations.lookup', class: 'retrieval', method: 'GET', path: '/v1/operations', query: ['operation'] };
export const OPERATIONS = [transfer, lookupOp];

function signer(secret: Uint8Array, keyId: string): Signer {
  return { keyId, algorithm: 'ed25519', sign: async (bytes) => ed25519.sign(bytes, secret) };
}

const base58 = (bytes: Uint8Array): string => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  let out = '';
  while (n) {
    out = alphabet[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
};

export interface Holder {
  readonly document: Record<string, any>;
  readonly signer: Signer;
  readonly url: string;
}

/** A signed AID for `did` with its own holder key and status index. */
function holder(issuer: ReturnType<typeof newIssuer>, did: string, n: number, over: { level?: TrustLevel; scopes?: string[]; hitl?: string[] } = {}): Holder {
  const secret = randomBytes(32);
  const doc = baseCredential();
  doc.id = `https://api.aria.bar/v1/credentials/019a0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const s = doc.credentialSubject;
  s.id = did;
  s.trustLevel = over.level ?? 'L1';
  s.scope = over.scopes ?? ['payments:transfer:create', 'payments:transfer:receive'];
  s.hitlRequired = over.hitl ?? [];
  s.holderKey = { id: `${did}#holder-key-${n}`, type: 'Ed25519VerificationKey2020', publicKeyMultibase: 'z' + base58(ed25519.getPublicKey(secret)) };
  doc.credentialStatus = { ...doc.credentialStatus, id: `${LIST_URL}#${n}`, statusListIndex: String(n) };
  return { document: sign(doc, issuer), signer: signer(secret, `${did}#holder-key-${n}`), url: doc.id };
}

export function world(options: { level?: TrustLevel; hitl?: string[]; statusMaxAgeSeconds?: number } = {}) {
  let t = NOW;
  const clock = () => new Date(t);
  const issuer = newIssuer();
  const revoked: number[] = [];
  let statusUp = true;
  const routes = { [LIST_URL]: () => (statusUp ? new Response(JSON.stringify(statusList(issuer, revoked, { ageMs: 60_000 })), { status: 200 }) : new Response('unavailable', { status: 503 })) };
  const verifier = (): Verifier =>
    createVerifier({ trust: [profile(issuer, { maxLevel: 'L3' })], clock, fetch: { allowedOrigins: [ORIGIN], fetch: fakeFetch(routes) }, ...(options.statusMaxAgeSeconds ? { statusMaxAgeSeconds: options.statusMaxAgeSeconds } : {}) });

  const agent = holder(issuer, AGENT, 11, options);
  const bankHolder = holder(issuer, BANK.did, 12, { scopes: ['payments:transfer:receive'] });
  const documents = new Map<string, unknown>([agent, bankHolder].map((h) => [h.url, h.document]));

  // The agent's side.
  const agentVerifier = verifier();
  const agentAp = createAp({ credentials: agentVerifier, clock });
  const verified = (v: Verifier, doc: unknown): VerifiedCredential => {
    const r = v.verifyCredential(doc);
    if (!r.ok) throw new Error(r.reason);
    return r.credential;
  };
  let agentCredential = verified(agentVerifier, agent.document);
  let agentSigner = agent.signer;

  // The bank's side.
  const bankVerifier = verifier();
  const bankAp = createAp({ credentials: bankVerifier, clock });
  const self: ReceiverSelf = { did: BANK.did, origin: BANK.origin, credential: verified(bankVerifier, bankHolder.document), document: bankHolder.document, signer: bankHolder.signer };
  const challenges = new MemoryChallengeStore(clock);
  const storage = new MemoryOperationStorage();
  const ledger = new OperationLedger(bankAp, storage, self);
  const context = { receiver: { did: BANK.did, origin: BANK.origin }, operations: OPERATIONS, challenges, resolveCredential: async (url: string) => documents.get(url) ?? null };
  let effects = 0;
  let authorizations = 0;

  type Answer = { status: number; receipt?: Receipt; problem?: string; current?: Receipt | null; history?: readonly Receipt[] };

  /** The bank's handler: authenticate, admit, claim, run once, sign. */
  async function handle(request: HttpRequestLike, approval?: ApprovalEvidence, effect: () => Promise<'ok' | string> = async () => 'ok'): Promise<Answer> {
    const presented = await bankAp.verifyPresentation(request, context);
    if (!presented.ok) return { status: presented.status, problem: `${presented.code}/${presented.reason}` };
    const { presentation } = presented;
    const status = await bankVerifier.checkStatus(presentation.credential);
    if (presentation.operation.class === 'retrieval') {
      const allowed = await bankAp.admitLookup({ presentation, status });
      if (allowed.decision !== 'allow') return { status: allowed.status, problem: allowed.code };
      const found = await ledger.lookup(allowed);
      return found ? { status: 200, current: found.current, history: found.history } : { status: 404, problem: 'aria.operation_unknown' };
    }
    const admission = await bankAp.admit({
      presentation,
      status,
      ...(approval ? { approval } : {}),
      authorize: async () => {
        authorizations++;
        return { allowed: true };
      },
    });
    if (admission.decision !== 'allow') return { status: admission.refusal.status, receipt: await bankAp.buildAttemptRefusal(admission.refusal, self) };
    const begun = await ledger.begin(admission);
    if (begun.kind === 'existing') return { status: begun.status, receipt: begun.governing };
    if (begun.kind === 'refused') return { status: begun.refusal.status, receipt: await bankAp.buildAttemptRefusal(begun.refusal, self) };
    const result = await effect();
    if (result === 'ok') effects++;
    const outcome = await ledger.settle(begun.claim, result === 'ok' ? { state: 'completed', status: 201 } : { state: 'rejected', status: 422, code: result });
    return { status: outcome.status, receipt: outcome.receipt };
  }

  let nonces = 0;
  /** A freshly authenticated bank, with a new single-use challenge. */
  async function receiver(): Promise<VerifiedReceiver> {
    const nonce = `nonce-${String(++nonces).padStart(20, '0')}`;
    const r = await agentAp.verifyReceiverIdentity(await bankAp.identify(self, { nonce, audience: AGENT }, challenges), BANK, { nonce, audience: AGENT });
    if (!r.ok) throw new Error(`receiver ${r.reason}`);
    return r.receiver;
  }

  const body = (amount: string) => new TextEncoder().encode(JSON.stringify({ amount, currency: 'EUR', to: 'acc-2' }));

  async function signTransfer(operationId: string, amount = '10.00', receiverOverride?: VerifiedReceiver) {
    return agentAp.signRequest({
      request: { method: 'POST', target: '/v1/transfers', headers: { 'content-type': 'application/json' }, body: body(amount) },
      class: 'unsafe-body',
      operationId,
      receiver: receiverOverride ?? (await receiver()),
      credential: agentCredential,
      signer: agentSigner,
    });
  }

  async function signLookup(operationId: string) {
    return agentAp.signRequest({ request: { method: 'GET', target: `/v1/operations?operation=${operationId}`, headers: {} }, class: 'retrieval', receiver: await receiver(), credential: agentCredential, signer: agentSigner });
  }

  return {
    issuer,
    agentAp,
    agentVerifier,
    bankAp,
    bankVerifier,
    self,
    ledger,
    storage,
    challenges,
    context,
    documents,
    handle,
    receiver,
    signTransfer,
    signLookup,
    holder: (did: string, n: number, over?: Parameters<typeof holder>[3]) => {
      const h = holder(issuer, did, n, over);
      documents.set(h.url, h.document);
      return h;
    },
    /** The agent switches to another credential of its own (a renewal, or another level). */
    useCredential(h: Holder) {
      agentCredential = verified(agentVerifier, h.document);
      agentSigner = h.signer;
    },
    get agentCredential() {
      return agentCredential;
    },
    get agentSigner() {
      return agentSigner;
    },
    revoke: (index: number) => revoked.push(index),
    /** Whether the status list can be fetched. */
    statusAvailable: (up: boolean) => (statusUp = up),
    at: (ms: number) => (t = ms),
    get now() {
      return t;
    },
    get effects() {
      return effects;
    },
    get authorizations() {
      return authorizations;
    },
  };
}
