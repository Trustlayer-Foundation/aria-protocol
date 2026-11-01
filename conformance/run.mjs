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
 * Usage: node conformance/run.mjs [--sdk <path to the SDK entry>] [--strict]
 * Without --sdk it tests the ARIA SDK's build (`sdk/aria-ts/dist`) when present.
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
// Under --strict a check that cannot run fails: a release gate cannot rest on a skip.
const strict = process.argv.includes('--strict');
const unavailable = (name, why) => (strict ? report(name, false, why) : skip(name, why));

// ── 1 · canonical serialisation, byte for byte ────────────────────────────────
async function canonicalJsonCheck(sdkEntry) {
  const name = 'canonical serialisation matches the vectors byte for byte';
  if (!sdkEntry) return unavailable(name, 'no SDK entry point given (--sdk)');
  const { canonicalJson } = await import(pathToFileURL(sdkEntry).href);
  if (typeof canonicalJson !== 'function') return unavailable(name, 'the SDK does not export canonicalJson');
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
    return unavailable(name, `${total} cases ready; no implementation exports a did:aria parser yet`);
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
  const name = 'the example, a production-shaped credential and a Person principal expand losslessly';
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

  // Plus the example with a natural-person principal: `type` is JSON-LD's @type,
  // so the value has to be a defined term. schema:Person expands; a bare literal
  // such as "individual" is a relative @type and a conforming processor refuses it.
  const person = JSON.parse(readFileSync(documents[0], 'utf8'));
  person.credentialSubject.principal.type = 'Person';
  delete person.credentialSubject.principal.legalName;
  const inputs = [
    ...documents.map((file) => [basename(file), JSON.parse(readFileSync(file, 'utf8'))]),
    ['aid-example.json with a Person principal', person],
  ];

  const failed = [];
  for (const [label, doc] of inputs) {
    try {
      await jsonld.expand(doc, { documentLoader, safe: true });
    } catch (err) {
      failed.push(`${label}: ${err.details?.event?.code ?? err.details?.code ?? err.message}`);
    }
  }
  report(name, failed.length === 0, failed.length ? failed.join(' · ') : `${inputs.length}/${inputs.length}`);
}

// ── 5 · a natural person is never named, and the schemas say so ────────────────
// COM-09: the public AID never carries a natural person's name. The schemas used
// to require legalName of every principal and could not tell a person from an
// organization, so a person's credential was either schema-valid and in breach, or
// conformant and rejected. Each case below is built from a real document shape and
// checked against the schema that governs it, in both directions: what must pass,
// and what must now be refused.
async function principalKindCheck(strict) {
  const name = 'a Person principal carries no legalName, in every schema that is in force';
  let Ajv2020, addFormats;
  try {
    Ajv2020 = (await import('ajv/dist/2020.js')).default;
    addFormats = (await import('ajv-formats')).default;
  } catch {
    const why = 'ajv not installed — run `npm install` in conformance/';
    return strict ? report(name, false, why) : skip(name, why);
  }

  const schema = (f) => JSON.parse(readFileSync(join(root, 'schema', f), 'utf8'));
  const bases = [
    ['aid-1.0.json', JSON.parse(readFileSync(join(root, 'examples', 'aid-example.json'), 'utf8'))],
    ['aid-v1.2.json', load('aid-v1.2-shape.json').document],
  ];
  const cases = [
    ['no type, with legalName — as issued before the field existed', () => {}, true],
    ['Organization with legalName', (p) => { p.type = 'Organization'; }, true],
    ['Person without legalName', (p) => { p.type = 'Person'; delete p.legalName; }, true],
    ['Person WITH legalName', (p) => { p.type = 'Person'; }, false],
    ['Organization WITHOUT legalName', (p) => { p.type = 'Organization'; delete p.legalName; }, false],
    ['no type and no legalName', (p) => { delete p.legalName; }, false],
  ];

  const wrong = [];
  let total = 0;
  for (const [file, base] of bases) {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(schema(file));
    for (const [label, mutate, mustPass] of cases) {
      const doc = structuredClone(base);
      mutate(doc.credentialSubject.principal);
      total += 1;
      if (validate(doc) !== mustPass) wrong.push(`${file}: ${label} should ${mustPass ? 'pass' : 'be refused'}`);
    }
  }
  report(name, wrong.length === 0, wrong.length ? wrong.join(' · ') : `${total}/${total}`);
}

// ── 6 · scopes and holder keys, as issued and as read ──────────────────────────
// The shared cases of vectors/scopes.json and vectors/holder-keys.json, against the
// schemas that state them. The authority and the SDK run the same cases against
// their own code: what a schema cannot say (a key's length, order and torsion) is
// judged there.
async function scopeAndHolderKeyCheck(strict) {
  const name = 'scopes and holder keys are accepted and refused as the shared cases say';
  let Ajv2020, addFormats;
  try {
    Ajv2020 = (await import('ajv/dist/2020.js')).default;
    addFormats = (await import('ajv-formats')).default;
  } catch {
    const why = 'ajv not installed — run `npm install` in conformance/';
    return strict ? report(name, false, why) : skip(name, why);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const aid = JSON.parse(readFileSync(join(root, 'schema', 'aid-1.0.json'), 'utf8'));
  const exchange = JSON.parse(readFileSync(join(root, 'federation', 'exchange.schema.json'), 'utf8'));
  ajv.addSchema(aid);
  ajv.addSchema(exchange);
  const subject = aid.properties.credentialSubject.properties;
  const judges = {
    issued: ajv.getSchema(`${exchange.$id}#/$defs/scope`),
    credential: ajv.compile(subject.scope.items),
  };
  const wrong = [];
  let total = 0;
  const scopes = load('scopes.json');
  for (const [context, judge] of Object.entries(judges)) {
    for (const [list, expected] of [['accept', true], ['reject', false]]) {
      for (const s of scopes[context][list]) {
        total += 1;
        if (Boolean(judge(s)) !== expected) wrong.push(`${context}: ${s} should be ${expected ? 'accepted' : 'refused'}`);
      }
    }
  }
  const keys = load('holder-keys.json');
  const encoding = ajv.compile(subject.holderKey.properties.publicKeyMultibase);
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const base58 = (bytes) => {
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let out = '';
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
    return out;
  };
  for (const k of keys.accept) {
    total += 1;
    const raw = Buffer.from(k.raw, 'hex');
    if (raw.length !== 32 || k.publicKeyMultibase !== 'z' + base58(raw) || k.multikey !== 'z' + base58(Buffer.concat([Buffer.from([0xed, 0x01]), raw])) || !encoding(k.publicKeyMultibase)) {
      wrong.push(`holder key: ${k.label} is not the z-base58btc of its 32 raw bytes`);
    }
  }
  total += keys.reject.length; // judged by the authority and the SDK, which decode keys
  report(name, wrong.length === 0, wrong.length ? wrong.join(' · ') : `${total}/${total}`);
}

// ── 7 · the published key set ───────────────────────────────────────────────
// vectors/keyset.json: the published form passes its schema and every fingerprint
// is the SHA-256 of its key's canonical identity. Introductions and the refused
// sets are judged by the publishing authority, which verifies composite signatures.
async function keysetCheck(strict) {
  const name = 'the published key set has its schema and its fingerprints';
  let Ajv2020;
  try {
    Ajv2020 = (await import('ajv/dist/2020.js')).default;
  } catch {
    const why = 'ajv not installed — run `npm install` in conformance/';
    return strict ? report(name, false, why) : skip(name, why);
  }
  const { createHash } = await import('node:crypto');
  const doc = load('keyset.json');
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(JSON.parse(readFileSync(join(root, 'schema', 'aria-keyset-1.json'), 'utf8')));
  const wrong = [];
  if (!validate(doc.valid.published)) wrong.push(`schema: ${JSON.stringify(validate.errors)}`);
  // The identity holds four plain strings: sorted keys are its canonical JSON.
  const canonical = (o) => `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${JSON.stringify(o[k])}`).join(',')}}`;
  for (const k of doc.valid.published.keys) {
    const identity = { key_id: k.key_id, suite: k.suite, public_key_mldsa65: k.public_key_mldsa65, public_key_ed25519: k.public_key_ed25519 };
    const expected = `sha256:${createHash('sha256').update(canonical(identity)).digest('hex')}`;
    if (k.fingerprint !== expected) wrong.push(`${k.key_id}: fingerprint`);
  }
  // A set the publisher refuses for its spelling would also fail the schema once
  // published: the two agree on the key-ID alphabet and the timestamp form.
  const spelling = doc.refused.filter((c) => /fragment|fractional/.test(c.label));
  for (const c of spelling) {
    const asPublished = { ...c.configured, keys: c.configured.keys.map((k) => ({ ...k, fingerprint: `sha256:${'0'.repeat(64)}` })) };
    if (validate(asPublished)) wrong.push(`${c.label}: passes the schema`);
  }
  if (spelling.length !== 2) wrong.push(`expected 2 spelling cases, found ${spelling.length}`);
  const total = 1 + doc.valid.published.keys.length + spelling.length;
  report(name, wrong.length === 0, wrong.length ? wrong.join(' · ') : `${total}/${total}`);
}

// ── run ───────────────────────────────────────────────────────────────────────
const argSdk = process.argv.indexOf('--sdk');
let sdkEntry = argSdk > -1 ? process.argv[argSdk + 1] : null;
if (!sdkEntry) {
  for (const guess of ['sdk/aria-ts/dist/index.js']) {
    if (existsSync(join(root, guess))) { sdkEntry = join(root, guess); break; }
  }
}

console.log(`ARIA conformance — vectors in ${vectors}`);
console.log(sdkEntry ? `SDK under test: ${sdkEntry}\n` : 'No SDK under test; SDK-dependent checks are skipped.\n');
await canonicalJsonCheck(sdkEntry);
await abnfCheck(sdkEntry);
redefinitionCheck();
await expansionCheck(process.argv.includes('--strict'));
await principalKindCheck(process.argv.includes('--strict'));
await scopeAndHolderKeyCheck(process.argv.includes('--strict'));
await keysetCheck(process.argv.includes('--strict'));
console.log(`\n${failures === 0 ? 'All checks passed.' : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
