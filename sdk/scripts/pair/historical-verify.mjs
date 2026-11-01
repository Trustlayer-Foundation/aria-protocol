// The second process of historical.mjs: reads exported evidence, verifies it at a later
// time with a new verifier, and prints what it found as one JSON line.
import { readFileSync } from 'node:fs';
import * as ap from '@trustlayer-foundation/aria-ap';
import * as sdk from '@trustlayer-foundation/aria-sdk';

const [file, at] = process.argv.slice(2);
const e = JSON.parse(readFileSync(file, 'utf8'));
const clock = () => new Date(at);
const trust = { ...e.trust, keys: { mldsa65: new Uint8Array(Buffer.from(e.trust.keys.mldsa65, 'base64')), ed25519: new Uint8Array(Buffer.from(e.trust.keys.ed25519, 'base64')) } };
const verifier = sdk.createVerifier({ trust: [trust], clock });
const client = ap.createAp({ credentials: verifier, clock });
const errorName = (fn) => {
  try {
    fn();
    return 'none';
  } catch (error) {
    return error?.name;
  }
};

const current = verifier.verifyCredential(e.receiverDocument);
const authentic = verifier.verifyAuthenticity(e.receiverDocument);
const out = { current: current.ok ? 'valid' : current.reason, authentic: authentic.ok };
if (authentic.ok) {
  const credential = authentic.credential;
  const read = await verifier.readRetainedStatus(credential, e.statusList);
  const evidence = { credential, ...(read.ok ? { status: read.status } : {}) };
  const r = await client.verifyHistoricalReceipt(e.receipt, { attempts: e.attempts, evidence });
  out.historical = r.ok ? { ok: true, state: r.statement.state, findings: r.findings } : { ok: false, reason: r.reason };
  const altered = JSON.parse(e.receipt);
  altered.issuedAt = altered.issuedAt.replace(/(\d)Z$/, (_, d) => `${(Number(d) + 1) % 10}Z`);
  const a = await client.verifyHistoricalReceipt(JSON.stringify(altered), { attempts: e.attempts, evidence });
  out.altered = a.ok ? 'accepted' : a.reason;
  let status = 'none';
  try {
    await verifier.checkStatus(credential);
  } catch (error) {
    status = error?.name;
  }
  out.refusedNow = { facts: errorName(() => verifier.facts(credential)), standing: errorName(() => verifier.standing(credential, read.status)), checkStatus: status };
}
console.log(JSON.stringify(out));
