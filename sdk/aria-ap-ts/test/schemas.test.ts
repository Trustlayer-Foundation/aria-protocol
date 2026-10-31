// The provisional ARIA AP schemas (schema/aria-ap-*.json): the package ships them
// byte for byte, they agree with the implementation and the AP1 vectors, and
// conforming to them is not authenticity: signatures and bindings are checked apart.
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { AriaUsageError, canonicalJson } from '@aria-registry/sdk';
import { isProfileOrigin } from '../src/internal/bytes';
import { readReceipt } from '../src/internal/receipt';
import { load } from './conformance';
import { AGENT, BANK, world } from './world';

const NAMES = ['aria-ap-receipt-1.json', 'aria-ap-identity-1.json', 'aria-ap-lookup-1.json'];
const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);
const packaged = (name: string) => new URL(`../schemas/${name}`, import.meta.url);
const OP = '55ee2e26-ffcc-40ca-b388-d12966453e48';
const OP2 = 'e8f70dd3-bc7b-433f-9518-b08e7c662d2d';

const addFormats = ((addFormatsModule as unknown as { default?: typeof addFormatsModule }).default ?? addFormatsModule);
const ajv = new Ajv2020({ strict: false, allErrors: false });
addFormats(ajv);
ajv.addSchema(JSON.parse(readFileSync(repo('schema/aid-1.0.json'), 'utf8')));
for (const name of NAMES) ajv.addSchema(JSON.parse(readFileSync(packaged(name), 'utf8')));
const schema = (name: string) => ajv.getSchema(`https://aria.bar/schema/${name}`)!;
const receipt = schema('aria-ap-receipt-1.json');
const identity = schema('aria-ap-identity-1.json');
const lookup = schema('aria-ap-lookup-1.json');
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));

describe('the packaged copies', () => {
  for (const name of NAMES) {
    it(`${name} is byte-identical to the protocol's schema/${name}`, () => {
      expect(readFileSync(packaged(name)).equals(readFileSync(repo(`schema/${name}`)))).toBe(true);
    });
  }

  it('each says it is provisional and that conforming to it proves no signature or authorization', () => {
    for (const name of NAMES) {
      const s = JSON.parse(readFileSync(packaged(name), 'utf8'));
      expect(s.title, name).toMatch(/provisional/);
      expect(s.description, name).toMatch(/Provisional/);
    }
  });
});

describe('aria-ap-receipt-1 against the AP1 receipt vectors', () => {
  it('accepts exactly what the implementation accepts as a well-formed receipt, but for the rules JSON Schema cannot express', () => {
    const differ: string[] = [];
    for (const v of load('vectors/receipts.json').vectors) {
      if (receipt(JSON.parse(v.receipt)) !== readReceipt(v.receipt).ok) differ.push(v.id);
    }
    // A duplicate key, a number with a fraction and more than 4 KiB: refused before parsing, documented in $comment.
    expect(differ).toEqual(['RCP-10a', 'RCP-10c', 'RCP-10d']);
  });
});

describe('documents the implementation produces conform', () => {
  it('operation receipts, attempt refusals, the identity response and retrieval answers', async () => {
    const w = world({ level: 'L0' });
    const refused = await w.handle((await w.signTransfer(OP)).request);
    expect(refused.status).toBe(403);
    w.useCredential(w.holder(AGENT, 21));
    const completed = await w.handle((await w.signTransfer(OP2)).request);
    const conflict = await w.handle((await w.signTransfer(OP2, '99.00')).request);
    const rejected = await w.handle((await w.signTransfer('aaab8d50-8485-4497-ae7f-b44d257fc8d8')).request, undefined, async () => 'bank.insufficient_funds');
    for (const r of [refused, completed, conflict, rejected]) expect(receipt(json(r.receipt)), JSON.stringify(receipt.errors)).toBe(true);
    expect([refused, completed, conflict, rejected].map((r) => r.receipt!.outcome.status)).toEqual([403, 201, 409, 422]);

    expect(identity(json(await w.bankAp.identify(w.self, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges))), JSON.stringify(identity.errors)).toBe(true);

    const found = await w.handle((await w.signLookup(OP2)).request);
    expect(lookup(json({ current: found.current, history: found.history })), JSON.stringify(lookup.errors)).toBe(true);
    expect(lookup({ current: null, history: [] })).toBe(true);
  });
});

describe('documents that do not conform, refused by the implementation too', () => {
  async function valid() {
    const w = world();
    return { w, r: json((await w.handle((await w.signTransfer(OP)).request)).receipt!) as any };
  }

  it('receipts', async () => {
    const { r } = await valid();
    const variants: Record<string, (x: any) => void> = {
      'missing proof': (x) => delete x.proof,
      'an unknown member': (x) => (x.note = 'x'),
      'another algorithm': (x) => (x.proof.alg = 'es256'),
      'an id that is not a urn:uuid': (x) => (x.id = 'receipt-1'),
      'completed for an attempt': (x) => (x.outcome.applies = 'attempt'),
      'an operation rejected with a protocol code': (x) => Object.assign(x.outcome, { state: 'rejected', status: 422, code: 'aria.scope_missing' }),
      'an attempt rejected with 422': (x) => Object.assign(x.outcome, { state: 'rejected', applies: 'attempt', status: 422, code: 'bank.insufficient_funds' }),
      'an unregistered protocol code': (x) => Object.assign(x.outcome, { state: 'rejected', applies: 'attempt', status: 403, code: 'aria.not_a_reason' }),
      'a result digest of another form': (x) => (x.outcome.result = { digest: 'md5=abc' }),
      'a credential with a query': (x) => (x.receiver.credential += '?v=2'),
      'an instant with fractions of a second': (x) => (x.issuedAt = '2026-11-01T12:00:00.000Z'),
    };
    for (const [label, mutate] of Object.entries(variants)) {
      const x = structuredClone(r);
      mutate(x);
      expect(receipt(x), label).toBe(false);
      expect(readReceipt(JSON.stringify(x)).ok, label).toBe(false);
    }
  });

  it('identity responses', async () => {
    const { w } = await valid();
    const base = json(await w.bankAp.identify(w.self, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges)) as any;
    const variants: Record<string, (x: any) => void> = {
      'no challenge': (x) => delete x.statement.challenge,
      'an unknown member': (x) => (x.statement.note = 'x'),
      'another type': (x) => (x.statement.type = 'aria-identity/0.1'),
      'a created time with fractions': (x) => (x.statement.created = '2026-11-01T12:00:00.000Z'),
      'a nonce that is not base64url': (x) => (x.statement.nonce = 'not a nonce!'),
      'a credential that is not an AID': (x) => (x.credential = { id: 'x' }),
    };
    for (const [label, mutate] of Object.entries(variants)) {
      const x = structuredClone(base);
      mutate(x);
      expect(identity(x), label).toBe(false);
      const r = await w.agentAp.verifyReceiverIdentity(x, BANK, { nonce: x.statement?.nonce ?? 'n'.repeat(22), audience: AGENT });
      expect(r.ok, label).toBe(false);
    }
  });

  it('retrieval answers: an attempt refusal is never part of an operation history', async () => {
    const w = world({ level: 'L0' });
    const refusal = json((await w.handle((await w.signTransfer(OP)).request)).receipt);
    expect(lookup({ current: refusal, history: [refusal] })).toBe(false);
    expect(lookup({ current: null, history: [], extra: 1 })).toBe(false);
    expect(lookup({ current: 'r1', history: [] })).toBe(false);
  });
});

describe('conforming is not authenticity', () => {
  it('a conforming receipt with an altered outcome fails its signature', async () => {
    const w = world();
    const attempt = await w.signTransfer(OP);
    const r = json((await w.handle(attempt.request)).receipt!) as any;
    r.outcome.status = 200;
    expect(receipt(r)).toBe(true);
    expect(await w.agentAp.verifyReceipt(r, { receiver: attempt.receiver, attempts: [attempt.sent!], mode: 'decision', transportStatus: 200 })).toEqual({ ok: false, reason: 'signature_invalid' });
  });

  it('a conforming identity response altered after signing fails its signature', async () => {
    const w = world();
    const x = json(await w.bankAp.identify(w.self, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges)) as any;
    x.statement.challenge = 'another-challenge-0001';
    expect(identity(x)).toBe(true);
    expect(await w.agentAp.verifyReceiverIdentity(x, BANK, { nonce: 'n'.repeat(22), audience: AGENT })).toEqual({ ok: false, reason: 'signature' });
  });
});

const VALID_ORIGINS = ['https://bank.example.test', 'https://bank.example.test:8443', 'https://127.0.0.1', 'https://localhost', 'https://xn--bnk-sna.example', 'http://localhost:3000', 'http://127.0.0.1', 'http://[::1]:8080'];
const INVALID_ORIGINS = [
  'ftp://bank.example.test', 'wss://bank.example.test', 'https://bank.example.test/api', 'https://bank.example.test/', 'https://user@bank.example.test',
  'https://bank.example.test?x=1', 'https://bank.example.test#f', 'https://Bank.example.test', 'https://bank.example.test:443', 'https://bank.example.test:0443',
  'https://bank.example.test:0', 'https://bank.example.test:65536', 'http://bank.example.test', 'http://localhost:80', 'https://1.2.3', 'https://bank.123',
  'https://-bank.example.test', 'https://bank..example.test', 'https://[::1]', 'not a url', '',
];
const VALID_INSTANTS = ['2028-02-29T00:00:00Z', '2026-12-31T23:59:59Z', '2026-01-01T00:00:00Z', '2000-02-29T12:30:45Z'];
const INVALID_INSTANTS = [
  '2026-02-29T00:00:00Z', '2026-02-31T00:00:00Z', '2026-04-31T00:00:00Z', '2100-02-29T00:00:00Z', '2026-13-01T00:00:00Z', '2026-00-10T00:00:00Z',
  '2026-01-00T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T23:60:00Z', '2026-01-01T23:59:60Z', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00+00:00', '2026-01-01t00:00:00z',
];

async function resigned(w: ReturnType<typeof world>, response: any, change: (s: any) => void) {
  const x = json(response) as any;
  change(x.statement);
  const { proof, ...unsigned } = x.statement;
  const bytes = new TextEncoder().encode(canonicalJson({ ...unsigned, proof: { alg: proof.alg, keyid: proof.keyid } }));
  x.statement.proof.value = Buffer.from(await w.self.signer.sign(bytes)).toString('base64url');
  return x;
}

describe('one origin rule for the identity statement (RL review F1)', () => {
  const originSchema = ajv.compile({ $ref: 'https://aria.bar/schema/aria-ap-identity-1.json#/properties/statement/properties/origin' });

  it('the SDK and the schema agree on every origin', () => {
    for (const o of [...VALID_ORIGINS, ...INVALID_ORIGINS]) expect([o, isProfileOrigin(o)], o).toEqual([o, originSchema(o)]);
    expect(VALID_ORIGINS.every(isProfileOrigin)).toBe(true);
    expect(INVALID_ORIGINS.some(isProfileOrigin)).toBe(false);
  });

  it('identify emits conforming responses for valid origins and refuses the rest', async () => {
    const w = world();
    for (const origin of VALID_ORIGINS) {
      const response = await w.bankAp.identify({ ...w.self, origin }, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges);
      expect(identity(json(response)), origin).toBe(true);
    }
    for (const origin of INVALID_ORIGINS) {
      await expect(w.bankAp.identify({ ...w.self, origin }, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges), origin).rejects.toThrow(AriaUsageError);
    }
  });

  it('verification accepts a valid origin, local HTTP included, and refuses a signed statement or a pin outside the rule', async () => {
    const w = world();
    const expected = { nonce: 'n'.repeat(22), audience: AGENT };
    for (const origin of ['https://bank.example.test', 'http://localhost:3000']) {
      const response = await w.bankAp.identify({ ...w.self, origin }, expected, w.challenges);
      expect((await w.agentAp.verifyReceiverIdentity(response, { ...BANK, origin }, expected)).ok, origin).toBe(true);
    }
    const base = await w.bankAp.identify(w.self, expected, w.challenges);
    for (const origin of ['https://bank.example.test/api', 'ftp://bank.example.test', 'https://user@bank.example.test', 'https://bank.example.test?x=1', 'https://Bank.example.test']) {
      const signed = await resigned(w, base, (st) => (st.origin = origin));
      expect(identity(signed), origin).toBe(false);
      expect(await w.agentAp.verifyReceiverIdentity(signed, { ...BANK, origin }, expected), origin).toEqual({ ok: false, reason: 'malformed' });
    }
    for (const origin of ['https://bank.example.test/api', 'wss://bank.example.test', 'not a url']) {
      expect(await w.agentAp.verifyReceiverIdentity(base, { ...BANK, origin }, expected), origin).toEqual({ ok: false, reason: 'origin' });
    }
  });

  it('the receiver context takes the same rule', async () => {
    const w = world();
    const request = (await w.signTransfer('55ee2e26-ffcc-40ca-b388-d12966453e48')).request;
    await expect(w.bankAp.verifyPresentation(request, { ...w.context, receiver: { did: BANK.did, origin: 'ftp://bank.example.test' } })).rejects.toThrow(AriaUsageError);
  });
});

describe('instants that exist, on both sides (RL review F2)', () => {
  it('a receipt\'s issuedAt: the schema and the strict reader agree', async () => {
    const w = world();
    const r = json((await w.handle((await w.signTransfer(OP)).request)).receipt!) as any;
    for (const t of [...VALID_INSTANTS, ...INVALID_INSTANTS]) {
      const x = { ...r, issuedAt: t };
      expect([t, receipt(x)], t).toEqual([t, readReceipt(JSON.stringify(x)).ok]);
    }
    expect(VALID_INSTANTS.every((t) => receipt({ ...r, issuedAt: t }))).toBe(true);
    expect(INVALID_INSTANTS.some((t) => receipt({ ...r, issuedAt: t }))).toBe(false);
  });

  it('an identity statement\'s created: the schema and verifyReceiverIdentity agree on what is well formed', async () => {
    const w = world();
    const base = json(await w.bankAp.identify(w.self, { nonce: 'n'.repeat(22), audience: AGENT }, w.challenges)) as any;
    for (const t of [...VALID_INSTANTS, ...INVALID_INSTANTS]) {
      const x = structuredClone(base);
      x.statement.created = t;
      const r = await w.agentAp.verifyReceiverIdentity(x, BANK, { nonce: 'n'.repeat(22), audience: AGENT });
      // Valid instants are far from now: well formed, then stale. Invalid ones are malformed.
      expect([t, identity(x), r], t).toEqual([t, VALID_INSTANTS.includes(t), { ok: false, reason: VALID_INSTANTS.includes(t) ? 'stale' : 'malformed' }]);
    }
  });
});
