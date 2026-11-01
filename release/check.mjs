#!/usr/bin/env node
// Checks the release manifest, release/aria-1.0.json, against this repository and,
// when given, against the archives to publish and the site that holds the text.
//
//   node release/check.mjs                         the manifest matches the repository
//   node release/check.mjs --archives <sdk> <ap>   ... and the two package archives
//   node release/check.mjs --site <aria-landing>   ... and the edition's files
//   node release/check.mjs --final ...             ... and nothing is left pending
//   node release/check.mjs --update                rewrite the repository hashes
//
// The manifest must have its whole shape: every decision the release depends on,
// every published schema and every conformance file, so that evidence cannot
// disappear instead of being resolved. Every pinned file is compared by SHA-256.
// Each archive is opened: its integrity, and the name, version, peer range and
// publication metadata of the package.json it carries. A candidate may leave
// decisions pending and carry private packages; --final refuses both, and refuses
// to run without the archives and the site. Exit 0 when it holds, 1 when it does not.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const manifestPath = join(root, 'release', 'aria-1.0.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const args = process.argv.slice(2);
const after = (flag, n = 1) => (args.includes(flag) ? args.slice(args.indexOf(flag) + 1, args.indexOf(flag) + 1 + n) : null);
const archives = after('--archives', 2);
const site = after('--site')?.[0];
const final = args.includes('--final');
const update = args.includes('--update');

// What the release depends on: each decision must be recorded, decided or pending.
const DECISIONS = ['D1', 'D2', 'D3', 'D4-format', 'D4-rest', 'D5', 'D6', 'D7', 'D8', 'D9', 'D10', 'D11', 'D12'];
// The two packages, in publication order.
const PACKAGES = [{ path: 'sdk/aria-ts' }, { path: 'sdk/aria-ap-ts', peerOf: 0 }];
// Every JSON file under these is conformance evidence and must be pinned.
const CONFORMANCE = ['conformance/vectors', 'conformance/federation', 'conformance/ap/vectors', 'conformance/ap/profile.json'];

const sha256 = (file) => `sha256:${createHash('sha256').update(readFileSync(file)).digest('hex')}`;
const integrity = (file) => `sha512-${createHash('sha512').update(readFileSync(file)).digest('base64')}`;
const problems = [];
const notes = [];
let checked = 0;

// ── The manifest's shape ────────────────────────────────────────────────────
const isText = (v) => typeof v === 'string' && v.length > 0;
const isHash = (v) => typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v);
const need = (ok, what) => ok || problems.push(`manifest: ${what}`);
need(manifest.release === 'ARIA 1.0', 'release is "ARIA 1.0"');
need(['candidate', 'final'].includes(manifest.state), 'state is candidate or final');
need(isText(manifest.edition?.label) && isText(manifest.edition?.url) && Array.isArray(manifest.edition?.files) && manifest.edition.files.length > 0, 'an edition with its files');
need(Array.isArray(manifest.schemas) && manifest.schemas.length > 0, 'schemas');
need(isText(manifest.context?.path) && isText(manifest.context?.url), 'the context');
need(isText(manifest.federation?.files?.openapi?.path) && isText(manifest.federation?.files?.schema?.path), 'the federation contract');
need(Array.isArray(manifest.conformance) && manifest.conformance.length > 0, 'conformance files');
need(Array.isArray(manifest.compatibility) && manifest.compatibility.length > 0, 'compatibility obligations');
const levels = manifest.capabilities?.levels ?? {};
need(['L0', 'L1', 'L2', 'L3'].every((l) => isText(levels[l])) && isText(manifest.capabilities?.trust) && Array.isArray(manifest.capabilities?.ariaAp?.offered), 'capabilities for every level, trust and ARIA AP');
const recorded = new Map();
for (const d of manifest.decisions ?? []) {
  if (recorded.has(d.id)) problems.push(`manifest: decision ${d.id} recorded twice`);
  if (!['decided', 'pending'].includes(d.state)) problems.push(`manifest: decision ${d.id} is ${d.state}`);
  recorded.set(d.id, d);
}
for (const id of DECISIONS) if (!recorded.has(id)) problems.push(`manifest: decision ${id} is not recorded`);
need(Array.isArray(manifest.packages) && manifest.packages.length === PACKAGES.length && PACKAGES.every((p, i) => manifest.packages[i]?.path === p.path), `the packages, in order: ${PACKAGES.map((p) => p.path).join(', ')}`);

// ── Files of this repository ────────────────────────────────────────────────
const pinned = [
  ...(manifest.schemas ?? []).map((s) => ['schema', s]),
  ['context', manifest.context ?? {}],
  ...Object.values(manifest.federation?.files ?? {}).map((f) => ['federation', f]),
  ...(manifest.conformance ?? []).map((c) => ['conformance', c]),
];
for (const [kind, entry] of pinned) {
  const file = join(root, entry.path ?? '');
  if (!entry.path || !existsSync(file)) {
    problems.push(`${kind} ${entry.path}: missing`);
    continue;
  }
  const actual = sha256(file);
  if (update) entry.sha256 = actual;
  else if (!isHash(entry.sha256) || entry.sha256 !== actual) problems.push(`${kind} ${entry.path}: ${actual}, the manifest says ${entry.sha256}`);
  checked += 1;
}

// Every published schema is listed, and each one's $id is the one it declares.
const listed = new Map((manifest.schemas ?? []).map((s) => [s.path, s]));
for (const f of readdirSync(join(root, 'schema')).filter((n) => n.endsWith('.json'))) {
  const id = JSON.parse(readFileSync(join(root, 'schema', f), 'utf8')).$id;
  const entry = listed.get(`schema/${f}`);
  if (!entry) problems.push(`schema/${f}: published ($id ${id}) but not in the manifest`);
  else if (entry.id !== id) problems.push(`schema/${f}: $id ${id}, the manifest says ${entry.id}`);
}
const exchange = manifest.federation?.files?.schema;
if (exchange?.path && existsSync(join(root, exchange.path))) {
  const id = JSON.parse(readFileSync(join(root, exchange.path), 'utf8')).$id;
  if (exchange.id !== id) problems.push(`federation schema: $id ${id}`);
}

// Every conformance file is pinned: evidence cannot drop out of the manifest unnoticed.
const jsonFiles = (path) => {
  const full = join(root, path);
  if (!existsSync(full)) return [];
  if (!statSync(full).isDirectory()) return [path];
  return readdirSync(full).flatMap((n) => (n === 'node_modules' ? [] : jsonFiles(join(path, n)))).filter((p) => p.endsWith('.json'));
};
const pinnedConformance = new Set((manifest.conformance ?? []).map((c) => c.path));
for (const path of CONFORMANCE.flatMap(jsonFiles)) {
  if (!pinnedConformance.has(path)) problems.push(`${path}: conformance evidence not in the manifest`);
}

// ── Packages: the checkout, and each archive as it would be published ───────
const archived = (file) => JSON.parse(execFileSync('tar', ['-xzOf', file, 'package/package.json'], { encoding: 'utf8' }));
for (const [i, pkg] of (manifest.packages ?? []).entries()) {
  const own = JSON.parse(readFileSync(join(root, pkg.path, 'package.json'), 'utf8'));
  if (own.name !== pkg.name || own.version !== pkg.version) problems.push(`${pkg.path}: ${own.name}@${own.version}, the manifest says ${pkg.name}@${pkg.version}`);
  const peerOf = PACKAGES[i]?.peerOf;
  const expectedPeers = peerOf === undefined ? {} : { [manifest.packages[peerOf]?.name]: `^${manifest.packages[peerOf]?.version}` };
  if (JSON.stringify(pkg.peerDependencies ?? {}) !== JSON.stringify(expectedPeers)) problems.push(`${pkg.name}: peerDependencies must be ${JSON.stringify(expectedPeers)}`);
  if (!archives) {
    notes.push(`${pkg.name}: archive not compared (no --archives)`);
    continue;
  }
  const actual = integrity(archives[i]);
  if (actual !== pkg.integrity) problems.push(`${pkg.name}: archive ${actual}, the manifest says ${pkg.integrity}`);
  const packed = archived(archives[i]);
  if (packed.name !== pkg.name || packed.version !== pkg.version) problems.push(`${archives[i]}: holds ${packed.name}@${packed.version}, not ${pkg.name}@${pkg.version}`);
  if (JSON.stringify(packed.peerDependencies ?? {}) !== JSON.stringify(pkg.peerDependencies ?? {})) problems.push(`${pkg.name}: the archive's peerDependencies are ${JSON.stringify(packed.peerDependencies ?? {})}`);
  if (packed.private === true) {
    if (final) problems.push(`${pkg.name}: the archive is private and cannot be published`);
    else notes.push(`${pkg.name}: private archive (a candidate)`);
  }
  if (final && packed.publishConfig?.access !== 'public') problems.push(`${pkg.name}: the archive does not declare publishConfig.access public`);
  checked += 1;
}

// ── The edition, held by the site ───────────────────────────────────────────
if (site) {
  for (const f of manifest.edition?.files ?? []) {
    const actual = sha256(join(site, f.path));
    if (update) f.sha256 = actual;
    else if (!isHash(f.sha256) || f.sha256 !== actual) problems.push(`edition ${f.path}: ${actual}, the manifest says ${f.sha256}`);
    checked += 1;
  }
} else {
  notes.push('edition: not compared (no --site)');
}

// ── What a final release may not leave open ─────────────────────────────────
const pending = [...recorded.values()].filter((d) => d.state !== 'decided');
if (pending.length) notes.push(`decisions pending: ${pending.map((d) => d.id).join(', ')}`);
if (final) {
  if (manifest.state !== 'final') problems.push(`state is ${manifest.state}, not final`);
  if (pending.length) problems.push(`decisions pending: ${pending.map((d) => d.id).join(', ')}`);
  if (!archives) problems.push('a final check compares the archives (--archives)');
  if (!site) problems.push('a final check compares the edition (--site)');
  if ((manifest.packages ?? []).some((p) => p.nameStatus !== 'confirmed')) problems.push('package names not confirmed (D9)');
}

if (update) {
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`release: ${checked} hashes written`);
  process.exit(0);
}
for (const n of notes) console.log(`note  ${n}`);
for (const p of problems) console.log(`FAIL  ${p}`);
console.log(problems.length ? `\n${problems.length} problem(s)` : `\nthe manifest holds: ${checked} hashes, ${manifest.state}`);
process.exit(problems.length ? 1 : 0);
