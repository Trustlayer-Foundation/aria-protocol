// The exchange over local HTTP: a node:http receiver on 127.0.0.1 and a fetch
// client. The receiver's origin is its configured one (TLS terminates before it in
// a deployment); the bytes on the wire are the ones signed and verified.
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { OperationTracker, type HttpRequestLike } from '../src';
import { AGENT, BANK, world } from './world';

const OP = '55ee2e26-ffcc-40ca-b388-d12966453e48';
let server: Server | undefined;
afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())));

async function readBody(req: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return new Uint8Array(Buffer.concat(chunks));
}

/** The bank behind node:http. `drop` loses the next answer after the bank has acted. */
async function serve(w: ReturnType<typeof world>) {
  const state = { drop: false };
  server = createServer(async (req, res) => {
    const url = new URL(req.url!, 'http://local');
    if (url.pathname === '/.well-known/aria/identity') {
      const identity = await w.bankAp.identify(w.self, { nonce: url.searchParams.get('nonce') ?? '', audience: url.searchParams.get('audience') ?? '' }, w.challenges);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(identity));
      return;
    }
    const body = await readBody(req);
    const request: HttpRequestLike = { method: req.method!, target: req.url!, headers: req.headersDistinct as Record<string, string[]>, ...(body.length ? { body } : {}) };
    const answer = await w.handle(request);
    if (state.drop) {
      state.drop = false;
      req.socket.destroy();
      return;
    }
    res.writeHead(answer.status, { 'content-type': 'application/json' }).end(JSON.stringify(answer));
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return { base: `http://127.0.0.1:${(server!.address() as AddressInfo).port}`, state };
}

describe('over local HTTP', () => {
  it('a transfer whose answer is lost is recovered by a signed lookup, with one effect', async () => {
    const w = world();
    const { base, state } = await serve(w);

    let n = 0;
    const receiver = async () => {
      const nonce = `http-nonce-${String(++n).padStart(16, '0')}`;
      const res = await fetch(`${base}/.well-known/aria/identity?nonce=${nonce}&audience=${encodeURIComponent(AGENT)}`);
      const r = await w.agentAp.verifyReceiverIdentity(await res.json(), BANK, { nonce, audience: AGENT });
      if (!r.ok) throw new Error(r.reason);
      return r.receiver;
    };
    const send = (r: HttpRequestLike) =>
      fetch(base + r.target, { method: r.method, headers: r.headers as Record<string, string>, ...(r.body ? { body: r.body } : {}) });

    const tracker = new OperationTracker({ operationId: OP, sender: AGENT, receiver: BANK });
    const attempt = await w.signTransfer(OP, '10.00', await receiver());
    tracker.record(attempt);
    state.drop = true;
    await expect(send(attempt.request)).rejects.toThrow();
    expect([tracker.state, tracker.everSent, w.effects]).toEqual(['unknown', true, 1]);

    const found = await send((await w.signLookup(OP)).request);
    expect(found.status).toBe(200);
    const { history } = (await found.json()) as { history: unknown[] };
    expect(await tracker.observeLookup(w.agentAp, { history })).toBe('completed');

    // A retry now gets the original receipt over the wire, as text, still bound to the first attempt.
    const retry = await w.signTransfer(OP, '10.00', await receiver());
    tracker.record(retry);
    const res = await send(retry.request);
    const text = await res.text();
    const receipt = JSON.stringify(JSON.parse(text).receipt);
    expect(await tracker.observe(w.agentAp, receipt, { mode: 'decision', transportStatus: res.status })).toEqual({ applied: 'operation', state: 'completed' });
    expect(w.effects).toBe(1);
  });
});
