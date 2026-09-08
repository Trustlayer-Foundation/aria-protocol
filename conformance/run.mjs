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
import { join, dirname, basename } from 'node:path';
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

// ── 3 · the context redefines nothing the W3C context already defines ────────
// Our context is listed after the VC v2 one and declares @protected, so a term we
// redefine here is not merely redundant: it stops the standard definition from
// applying, and a conforming processor refuses the document outright. This ran
// once by hand and found nine, statusListIndex and proofValue among them.
function redefinitionCheck() {
  const name = 'the ARIA context redefines no term the W3C VC v2 context defines';
  const vc2 = load('context-credentials-v2.json')['@context'];
  const aria = JSON.parse(readFileSync(join(root, 'context', 'v1.jsonld'), 'utf8'))['@context'];

  const terms = (ctx, out = new Set()) => {
    for (const [k, v] of Object.entries(ctx)) {
      if (!k.startsWith('@')) out.add(k);
      if (v && typeof v === 'object' && v['@context']) terms(v['@context'], out);
    }
    return out;
  };
  const standard = terms(vc2);
  const clashes = Object.keys(aria).filter(
    (k) => !k.startsWith('@') && standard.has(k) && aria[k]?.['@protected'] !== false,
  );
  report(name, clashes.length === 0, clashes.length ? clashes.join(', ') : 'none');
}

// ── 4 · a real processor expands the documents without losing anything ────────
// jsonld.js in safe mode throws on any dropped property or relative IRI, which is
// the only version of this claim a reviewer can reproduce. The loader refuses the
// network: both contexts are pinned in vectors/, so a run is deterministic and
// offline. Install the processor with `npm install` inside conformance/.
async function expansionCheck(strict) {
  const name = 'the example and a production-shaped credential expand losslessly';
  let jsonld;
  try {
    jsonld = (await import('jsonld')).default;
  } catch {
    const why = 'jsonld not installed — run `npm install` in conformance/';
    if (strict) return report(name, false, why);
    return skip(name, why);
  }

  const pinned = new Map([
    ['https://www.w3.org/ns/credentials/v2', load('context-credentials-v2.json')],
    ['https://aria.bar/ns/v1', JSON.parse(readFileSync(join(root, 'context', 'v1.jsonld'), 'utf8'))],
  ]);
  const documentLoader = async (url) => {
    if (!pinned.has(url)) throw new Error(`refused to fetch ${url}: a conformance run is offline`);
    return { contextUrl: null, documentUrl: url, document: pinned.get(url) };
  };

  const documents = [
    join(root, 'examples', 'aid-example.json'),
    join(root, 'sdk', 'verify-ts', 'test', 'fixtures', 'valid-aid-production-form.json'),
  ].filter(existsSync);
  if (documents.length === 0) return skip(name, 'no credential documents found');

  const failed = [];
  for (const file of documents) {
    try {
      await jsonld.expand(JSON.parse(readFileSync(file, 'utf8')), { documentLoader, safe: true });
    } catch (err) {
      failed.push(`${basename(file)}: ${err.details?.code ?? err.message}`);
    }
  }
  report(name, failed.length === 0, failed.length ? failed.join(' · ') : `${documents.length}/${documents.length}`);
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
redefinitionCheck();
await expansionCheck(process.argv.includes('--strict'));
console.log(`\n${failures === 0 ? 'All checks passed.' : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
