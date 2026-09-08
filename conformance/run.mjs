#!/usr/bin/env node
/**
 * ARIA conformance harness.
 *
 * Each implementation embeds this and points it at `vectors/`. It exits non-zero on
 * any failure and prints one line per check, so a Registration Authority can run it
 * and present the output rather than being taken at its word.
 *
 * Offline by design: the W3C context is pinned in `vectors/context-credentials-v2.json`
 * rather than fetched, so a run is deterministic and a network outage is not a failure.
 *
 * Usage: node conformance/run.mjs [--sdk <path to the verify SDK entry>]
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, 'vectors');
const load = (f) => JSON.parse(readFileSync(join(vectors, f), 'utf8'));
const root = join(here, '..');

let failures = 0;
const report = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
};
const skip = (name, why) => console.log(`SKIP  ${name} — ${why}`);

// ── 1 · canonical serialisation, byte for byte ────────────────────────────────
async function canonicalJsonCheck(sdkEntry) {
  const name = 'canonical serialisation matches the vectors byte for byte';
  if (!sdkEntry) return skip(name, 'no SDK entry point given (--sdk)');
  const { canonicalJson } = await import(pathToFileURL(sdkEntry).href);
  if (typeof canonicalJson !== 'function') return skip(name, 'the SDK does not export canonicalJson');
  const { vectors: cases } = load('canonical-json.json');
  const bad = cases.filter((c) => canonicalJson(c.input) !== c.expected_canonical_json);
  report(name, bad.length === 0, `${cases.length - bad.length}/${cases.length}`);
  for (const c of bad) {
    console.log(`        ${c.name}`);
    console.log(`          expected ${c.expected_canonical_json}`);
    console.log(`          got      ${canonicalJson(c.input)}`);
  }

  // The identity commitment is SHA-256 over those exact bytes: the vectors fix the
  // hash as well as the serialisation, so a divergence shows up even if two
  // implementations disagree only in a byte nobody looks at.
  const cname = 'identity commitments match the vectors';
  const { createHash } = await import('node:crypto');
  const badHash = cases.filter(
    (c) => createHash('sha256').update(canonicalJson(c.input), 'utf8').digest('hex') !== c.expected_identity_commitment,
  );
  report(cname, badHash.length === 0, `${cases.length - badHash.length}/${cases.length}`);
  for (const c of badHash) console.log(`        ${c.name} — expected ${c.expected_identity_commitment}`);
}

// ── 2 · did:aria syntax ───────────────────────────────────────────────────────
async function abnfCheck(sdkEntry) {
  const name = 'did:aria identifiers accepted and rejected exactly';
  const cases = load('abnf-cases.json');
  const total = cases.accept.length + cases.reject.length;
  let parse = null;
  if (sdkEntry) {
    const sdk = await import(pathToFileURL(sdkEntry).href);
    parse = sdk.parseDid ?? sdk.isValidDid ?? null;
  }
  if (!parse) {
    return skip(name, `${total} cases ready; no implementation exports a did:aria parser yet`);
  }
  const wrong = [
    ...cases.accept.filter((c) => !parse(c.did)),
    ...cases.reject.filter((c) => parse(c.did)),
  ];
  report(name, wrong.length === 0, `${total - wrong.length}/${total}`);
  for (const c of wrong) console.log(`        ${c.did} — ${c.note ?? c.reason ?? ''}`);
}

// ── 3 · JSON-LD expansion loses nothing ───────────────────────────────────────
// A term with no definition is dropped when the document is expanded. A credential
// whose holder key or proof value disappears is not a Verifiable Credential in any
// useful sense, so this checks every property against the contexts the credential
// actually declares — no more, no less.
function expansionCheck() {
  const name = 'every property of the example credential has a term definition';
  const vc2 = load('context-credentials-v2.json')['@context'];
  const aria = JSON.parse(readFileSync(join(root, 'context', 'v1.jsonld'), 'utf8'))['@context'];
  const example = join(root, 'examples', 'aid-example.json');
  if (!existsSync(example)) return skip(name, 'examples/aid-example.json not found');
  const cred = JSON.parse(readFileSync(example, 'utf8'));

  const plain = (ctx) => new Set(Object.keys(ctx).filter((k) => !k.startsWith('@')));
  const scoped = Object.fromEntries(
    Object.entries(vc2)
      .filter(([, v]) => v && typeof v === 'object' && v['@context'])
      .map(([k, v]) => [k, plain(v['@context'])]),
  );

  const dropped = [];
  const walk = (node, path, allowed) => {
    if (Array.isArray(node)) return node.forEach((n) => walk(n, path, allowed));
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      if (k.startsWith('@')) continue;
      if (!allowed.has(k)) dropped.push(`${path}/${k}`);
      let next = new Set([...allowed, ...(scoped[k] ?? [])]);
      if (k === 'type') for (const t of [].concat(v)) next = new Set([...next, ...(scoped[t] ?? [])]);
      walk(v, `${path}/${k}`, next);
    }
  };
  let base = new Set([...plain(vc2), ...plain(aria)]);
  for (const t of [].concat(cred.type ?? [])) base = new Set([...base, ...(scoped[t] ?? [])]);
  walk(cred, '', base);

  report(name, dropped.length === 0, dropped.length ? `${dropped.length} dropped` : 'none dropped');
  for (const d of dropped) console.log(`        ${d}`);
}

// ── run ───────────────────────────────────────────────────────────────────────
const argSdk = process.argv.indexOf('--sdk');
let sdkEntry = argSdk > -1 ? process.argv[argSdk + 1] : null;
if (!sdkEntry) {
  for (const guess of ['sdk/verify-ts/dist/index.mjs', 'sdk/verify-ts/dist/index.js']) {
    if (existsSync(join(root, guess))) { sdkEntry = join(root, guess); break; }
  }
}

console.log(`ARIA conformance — vectors in ${vectors}`);
console.log(sdkEntry ? `SDK under test: ${sdkEntry}\n` : 'No SDK under test; SDK-dependent checks are skipped.\n');
await canonicalJsonCheck(sdkEntry);
await abnfCheck(sdkEntry);
expansionCheck();
console.log(`\n${failures === 0 ? 'All checks passed.' : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
