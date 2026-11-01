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
// the payload is read. Every answer must match the schema of its status, refusals
// included, and every refusal code must travel with the status the contract gives
// it. The identifier cases of identifiers.json must be accepted and rejected by the
// schema exactly as listed; the authority checks the same cases with its parser.
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
const identifiers = json(join(here, 'identifiers.json'));

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

const kinds = { accepted: 0, unreadable: 0, shape: 0, beforePayload: 0, judged: 0, refusals: 0, echoed: 0 };

// A refusal's correlation ID is drawn at random; any UUID stands for it here.
const CORRELATION_ID = '6f0c1c8e-7d8a-4f36-9a51-0b6b8c3e2d10';

/**
 * The body the authority sends for a refused step, by the contract's rule: its code
 * and path, a correlation ID, and the request's own request_id once the request
 * signature has verified. Null when the step cannot be answered that way.
 */
function refusalBody(step) {
  const { code, path, request_id_echo: echoed } = step.expect;
  if (typeof path !== 'string' || typeof echoed !== 'boolean') return null;
  const body = { code, path, correlation_id: CORRELATION_ID };
  if (echoed) {
    const id = step.body_raw === undefined ? step.body?.assertion?.request_id : undefined;
    if (id === undefined) return null;
    body.request_id = id;
  }
  return body;
}

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
    const body = refusalBody(step);
    if (!body) return fail(`${at}: a refusal needs its path, and a request_id to echo when it says so`);
    const bad = errors(`refusal${status}`, body);
    if (bad.length) return fail(`${at}: refusal body fails refusal${status}: ${ajv.errorsText(bad)}`);
    kinds.refusals += 1;
    if (body.request_id) kinds.echoed += 1;
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

// ── Identifiers ─────────────────────────────────────────────────────────────

let cases = 0;
for (const [definition, { accept, reject }] of Object.entries(identifiers.cases)) {
  for (const [list, expected] of [[accept, true], [reject, false]]) {
    for (const value of list) {
      cases += 1;
      const ok = errors(definition, value).length === 0;
      if (ok === expected) pass();
      else fail(`${definition}: ${value} is ${ok ? 'accepted' : 'rejected'} by the schema`);
    }
  }
}

// ── Controls: the checks above can fail ─────────────────────────────────────

const positive = exchanges.vectors.find((v) => v.id.startsWith('P01-'));
const mint = positive.steps.find((s) => s.endpoint === 'mint');
const refusal = (extra) => ({
  code: 'signature_invalid',
  path: '/signature/value',
  correlation_id: CORRELATION_ID,
  ...extra,
});
// Each control names what the schema must do with it.
const accepted = (name, check) => [name, false, check];
const controls = [
  accepted('a refusal before the signature has verified', () => errors('refusal401', refusal()).length > 0),
  accepted('a refusal echoing the request_id', () =>
    errors('refusal401', refusal({ code: 'assertion_expired', request_id: CORRELATION_ID })).length > 0),
  ['a refusal with a member the authority never sends', true, () => errors('refusal401', refusal({ detail: 'x' })).length > 0],
  ['a refusal without its correlation ID', true, () => {
    const body = refusal();
    delete body.correlation_id;
    return errors('refusal401', body).length > 0;
  }],
  ['a refusal whose correlation ID is a number', true, () => errors('refusal401', refusal({ correlation_id: 7 })).length > 0],
  ['an unknown member in an accepted payload', true, () => {
    const body = structuredClone(mint.body);
    body.payload.attestation.note = 'x';
    return errors('mintRequest', body).length > 0;
  }],
  ['one signature half missing from an accepted request', true, () => {
    const body = structuredClone(mint.body);
    body.signature.value = body.signature.value.slice(0, 4400);
    return errors('mintRequest', body).length > 0;
  }],
  ['a mint payload under the reserve operation', true, () => errors('reserveRequest', mint.body).length > 0],
  ['an answer without its credential', true, () => {
    const answer = structuredClone(mint.expect.body);
    delete answer.credential;
    return errors('mintResponse', answer).length > 0;
  }],
  ['an issued credential with a member AID 1.0 does not define', true, () => {
    const answer = structuredClone(mint.expect.body);
    answer.credential.credentialSubject.email = 'x';
    return errors('mintResponse', answer).length > 0;
  }],
  ['a refusal code outside the contract', true, () => errors('refusal422', {
    code: 'not_a_code',
    path: '',
    correlation_id: '6f0c1c8e-7d8a-4f36-9a51-0b6b8c3e2d10',
  }).length > 0],
  ['a refusal code under another status', true, () => errors('refusal422', {
    code: 'signature_invalid',
    path: '',
    correlation_id: '6f0c1c8e-7d8a-4f36-9a51-0b6b8c3e2d10',
  }).length > 0],
];
for (const [name, mustReject, rejected] of controls) {
  if (rejected() === mustReject) pass();
  else fail(`control: ${name} is ${mustReject ? 'accepted' : 'rejected'}`);
}

console.log(
  `${ops.length} operations, ${allCodes.length} refusal codes; ` +
    `${exchanges.vectors.length} exchanges, ${steps} requests; ${cases} identifier cases; ${controls.length} controls`,
);
console.log(
  `requests: ${kinds.accepted} accepted, ${kinds.unreadable} unreadable, ${kinds.shape} refused for shape, ` +
    `${kinds.beforePayload} refused before the payload, ${kinds.judged} refused on judgement; ` +
    `${kinds.refusals} refusal bodies checked, ${kinds.echoed} echoing request_id`,
);
console.log(failures ? `${failures} failed, ${passes} passed` : `all ${passes} checks passed`);
process.exit(failures ? 1 : 0);
