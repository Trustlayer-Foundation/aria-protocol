#!/usr/bin/env node
// Checks the federation contract against itself and the shared exchanges against
// the contract:
//
//   node conformance/federation/check.mjs
//
// The contract is federation/openapi.yaml with the shapes of
// federation/exchange.schema.json. The exchanges are exchanges/vectors/vectors.json:
// requests and the authority's expected answers. This script does not run an
// authority; the authority replays the same exchanges in its own tests.
//
// A request refused for its shape must fail the schema where the refusal points.
// A request refused for anything else must pass it: as far as its payload when
// the payload is judged, as far as its envelope when the refusal comes before
// the payload is read. Every answer must match the schema of its status, and every
// refusal code must travel with the status the contract gives it.
//
// Exit 0 when everything holds, 1 otherwise.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse as parseYaml } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const json = (path) => JSON.parse(readFileSync(path, 'utf8'));

const openapi = parseYaml(readFileSync(join(root, 'federation/openapi.yaml'), 'utf8'));
const exchange = json(join(root, 'federation/exchange.schema.json'));
const aid = json(join(root, 'schema/aid-1.0.json'));
const exchanges = json(join(here, 'exchanges/vectors/vectors.json'));

const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(aid);
ajv.addSchema(exchange);

const PREFIX = '/v1/authority/';
const FILE = 'exchange.schema.json#/$defs/';
// Refused before the payload is read: transport and authentication.
const BEFORE_PAYLOAD = new Set([400, 401, 413]);
// Refused for the request's shape.
const SHAPE = new Set(['field_not_allowed', 'field_missing', 'invalid_value']);

let failures = 0;
let passes = 0;
const fail = (what) => {
  failures += 1;
  console.log(`FAIL ${what}`);
};
const pass = () => {
  passes += 1;
};

const validator = (name) => {
  const v = ajv.getSchema(`${exchange.$id}#/$defs/${name}`);
  if (!v) throw new Error(`no definition ${name}`);
  return v;
};
const defOf = (ref) => (ref?.startsWith(FILE) ? ref.slice(FILE.length) : null);
const camel = (op) => op.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

// ── The contract ────────────────────────────────────────────────────────────

const ops = exchange.$defs.assertion.properties.op.enum;
const paths = Object.keys(openapi.paths);
const expected = ops.map((op) => PREFIX + op);
if (JSON.stringify([...paths].sort()) !== JSON.stringify([...expected].sort())) {
  fail(`paths ${paths.join(', ')} are not the operations ${ops.join(', ')}`);
} else pass();

const allCodes = exchange.$defs.error.properties.code.enum;
const statusOf = new Map();
for (const [name, def] of Object.entries(exchange.$defs)) {
  const m = /^refusal(\d{3})$/.exec(name);
  if (!m) continue;
  for (const code of def.properties.code.enum) {
    if (statusOf.has(code)) fail(`${code} travels with ${statusOf.get(code)} and ${m[1]}`);
    statusOf.set(code, Number(m[1]));
  }
}
const missing = allCodes.filter((c) => !statusOf.has(c));
const extra = [...statusOf.keys()].filter((c) => !allCodes.includes(c));
if (missing.length || extra.length) fail(`refusal codes without a status: ${missing}; outside the enum: ${extra}`);
else pass();

const answers = {}; // op → status → definition name
for (const op of ops) {
  const operation = openapi.paths[PREFIX + op];
  if (!operation) continue;
  if (Object.keys(operation).join() !== 'post') fail(`${op}: methods other than POST`);
  const request = defOf(operation.post?.requestBody?.content?.['application/json']?.schema?.$ref);
  if (request !== `${camel(op)}Request`) fail(`${op}: request schema ${request}`);
  else if (exchange.$defs[request].properties.assertion.properties.op.const !== op) fail(`${request}: op`);
  else pass();
  answers[op] = {};
  for (const [status, response] of Object.entries(operation.post.responses)) {
    const resolved = response.$ref
      ? openapi.components.responses[response.$ref.split('/').pop()]
      : response;
    const ref = resolved?.content?.['application/json']?.schema?.$ref;
    if (status === '504') {
      if (resolved?.content) fail(`${op} 504: an answer that never arrives has no body`);
      continue;
    }
    const name = defOf(ref);
    if (!name || !exchange.$defs[name]) {
      fail(`${op} ${status}: schema ${ref}`);
      continue;
    }
    if (status !== '200' && name !== `refusal${status}`) fail(`${op} ${status}: refers to ${name}`);
    validator(name); // compiles, and every $ref inside it resolves
    answers[op][status] = name;
    pass();
  }
  for (const s of new Set(statusOf.values())) {
    if (s === 404) continue; // only operations on a binding have it
    if (!answers[op][String(s)]) fail(`${op}: no ${s} response`);
  }
}

// ── The exchanges ───────────────────────────────────────────────────────────

/** The schema errors of `instance` against definition `name`. */
function errors(name, instance) {
  const v = validator(name);
  return v(instance) ? [] : v.errors;
}

/** Whether some error lies at `path` or above it: an unknown member is reported at its parent. */
const pointsAt = (errs, path) =>
  errs.some((e) => path === e.instancePath || path.startsWith(`${e.instancePath}/`));

const kinds = { accepted: 0, unreadable: 0, shape: 0, beforePayload: 0, judged: 0 };

function checkStep(id, i, step) {
  const at = `${id} step ${i} (${step.endpoint})`;
  const op = step.endpoint;
  const expect = step.expect;
  if (!answers[op]) return fail(`${at}: no such operation in the contract`);
  const status = expect.status;
  if (status !== 200) {
    if (statusOf.get(expect.code) !== status) {
      return fail(`${at}: ${expect.code} with ${status}, the contract gives ${statusOf.get(expect.code)}`);
    }
    if (!answers[op][String(status)]) return fail(`${at}: ${op} has no ${status} response`);
  }

  if (step.body_raw !== undefined) {
    let parsed = true;
    try {
      JSON.parse(step.body_raw);
    } catch {
      parsed = false;
    }
    if (parsed || expect.code !== 'malformed_json') return fail(`${at}: a raw body must be unreadable JSON`);
    kinds.unreadable += 1;
    return pass();
  }

  const request = `${camel(op)}Request`;
  if (status === 200) {
    const errs = errors(request, step.body);
    if (errs.length) return fail(`${at}: accepted request fails ${request}: ${ajv.errorsText(errs)}`);
    if (expect.body) {
      const answer = answers[op]['200'];
      const bad = errors(answer, expect.body);
      if (bad.length) return fail(`${at}: answer fails ${answer}: ${ajv.errorsText(bad)}`);
    }
    kinds.accepted += 1;
    return pass();
  }

  if (SHAPE.has(expect.code)) {
    const errs = errors(request, step.body);
    if (!errs.length) return fail(`${at}: ${expect.code} at ${expect.path}, but the request passes ${request}`);
    if (!pointsAt(errs, expect.path)) {
      return fail(`${at}: ${expect.code} at ${expect.path}; the schema points elsewhere: ${ajv.errorsText(errs)}`);
    }
    kinds.shape += 1;
    return pass();
  }

  const scope = BEFORE_PAYLOAD.has(status) ? 'envelope' : request;
  const errs = errors(scope, step.body);
  if (errs.length) return fail(`${at}: ${expect.code}, yet the request fails ${scope}: ${ajv.errorsText(errs)}`);
  kinds[scope === 'envelope' ? 'beforePayload' : 'judged'] += 1;
  return pass();
}

let steps = 0;
for (const vector of exchanges.vectors) {
  vector.steps.forEach((step, i) => {
    if (step.endpoint === 'owner') return; // an operator action between requests
    steps += 1;
    checkStep(vector.id, i, step);
  });
}

// ── Controls: the checks above can fail ─────────────────────────────────────

const positive = exchanges.vectors.find((v) => v.id.startsWith('P01-'));
const mint = positive.steps.find((s) => s.endpoint === 'mint');
const controls = [
  ['an unknown member in an accepted payload', () => {
    const body = structuredClone(mint.body);
    body.payload.attestation.note = 'x';
    return errors('mintRequest', body).length > 0;
  }],
  ['one signature half missing from an accepted request', () => {
    const body = structuredClone(mint.body);
    body.signature.value = body.signature.value.slice(0, 4400);
    return errors('mintRequest', body).length > 0;
  }],
  ['a mint payload under the reserve operation', () => errors('reserveRequest', mint.body).length > 0],
  ['an answer without its credential', () => {
    const answer = structuredClone(mint.expect.body);
    delete answer.credential;
    return errors('mintResponse', answer).length > 0;
  }],
  ['an issued credential with a member AID 1.0 does not define', () => {
    const answer = structuredClone(mint.expect.body);
    answer.credential.credentialSubject.email = 'x';
    return errors('mintResponse', answer).length > 0;
  }],
  ['a refusal code outside the contract', () => errors('refusal422', {
    code: 'not_a_code',
    path: '',
    correlation_id: '6f0c1c8e-7d8a-4f36-9a51-0b6b8c3e2d10',
  }).length > 0],
  ['a refusal code under another status', () => errors('refusal422', {
    code: 'signature_invalid',
    path: '',
    correlation_id: '6f0c1c8e-7d8a-4f36-9a51-0b6b8c3e2d10',
  }).length > 0],
];
for (const [name, rejected] of controls) {
  if (rejected()) pass();
  else fail(`control: ${name} is accepted`);
}

console.log(
  `${ops.length} operations, ${allCodes.length} refusal codes; ` +
    `${exchanges.vectors.length} exchanges, ${steps} requests; ${controls.length} controls`,
);
console.log(
  `requests: ${kinds.accepted} accepted, ${kinds.unreadable} unreadable, ${kinds.shape} refused for shape, ` +
    `${kinds.beforePayload} refused before the payload, ${kinds.judged} refused on judgement`,
);
console.log(failures ? `${failures} failed, ${passes} passed` : `all ${passes} checks passed`);
process.exit(failures ? 1 : 0);
