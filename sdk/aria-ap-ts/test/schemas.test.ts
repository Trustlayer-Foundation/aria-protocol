// The provisional ARIA AP schemas (schema/aria-ap-*.json): the package ships them
// byte for byte, they agree with the implementation and the AP1 vectors, and
// conforming to them is not authenticity: signatures and bindings are checked apart.
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import { describe, expect, it } from 'vitest';
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
