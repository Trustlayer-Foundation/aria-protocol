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
// Every pinned file is compared by SHA-256; every package archive by its npm
// integrity. A candidate manifest may leave decisions pending and integrities
// unverified; --final refuses both. Exit 0 when it holds, 1 when it does not.

import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
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

const sha256 = (file) => `sha256:${createHash('sha256').update(readFileSync(file)).digest('hex')}`;
const integrity = (file) => `sha512-${createHash('sha512').update(readFileSync(file)).digest('base64')}`;
const problems = [];
const notes = [];
let checked = 0;

// ── Files of this repository ────────────────────────────────────────────────
const pinned = [
  ...manifest.schemas.map((s) => ['schema', s]),
  ['context', manifest.context],
  ...Object.values(manifest.federation.files).map((f) => ['federation', f]),
  ...manifest.conformance.map((c) => ['conformance', c]),
];
for (const [kind, entry] of pinned) {
  const file = join(root, entry.path);
  if (!existsSync(file)) {
    problems.push(`${kind} ${entry.path}: missing`);
    continue;
  }
  const actual = sha256(file);
  if (update) entry.sha256 = actual;
  else if (entry.sha256 !== actual) problems.push(`${kind} ${entry.path}: ${actual}, the manifest says ${entry.sha256}`);
  checked += 1;
}

// Every published schema is listed, and each one's $id is the one it declares.
const listed = new Map(manifest.schemas.map((s) => [s.path, s]));
for (const f of readdirSync(join(root, 'schema')).filter((n) => n.endsWith('.json'))) {
  const id = JSON.parse(readFileSync(join(root, 'schema', f), 'utf8')).$id;
  const entry = listed.get(`schema/${f}`);
  if (!entry) problems.push(`schema/${f}: published ($id ${id}) but not in the manifest`);
  else if (entry.id !== id) problems.push(`schema/${f}: $id ${id}, the manifest says ${entry.id}`);
}
const exchangeId = JSON.parse(readFileSync(join(root, manifest.federation.files.schema.path), 'utf8')).$id;
if (manifest.federation.files.schema.id !== exchangeId) problems.push(`federation schema: $id ${exchangeId}`);

// ── Packages ────────────────────────────────────────────────────────────────
for (const [i, pkg] of manifest.packages.entries()) {
  const own = JSON.parse(readFileSync(join(root, pkg.path, 'package.json'), 'utf8'));
  if (own.name !== pkg.name || own.version !== pkg.version) problems.push(`${pkg.path}: ${own.name}@${own.version}, the manifest says ${pkg.name}@${pkg.version}`);
  for (const [dep, range] of Object.entries(pkg.peerDependencies ?? {})) {
    if (own.peerDependencies?.[dep] !== range) problems.push(`${pkg.name}: peer ${dep} ${own.peerDependencies?.[dep]}, the manifest says ${range}`);
  }
  if (archives) {
    const actual = integrity(archives[i]);
    if (actual !== pkg.integrity) problems.push(`${pkg.name}: archive ${actual}, the manifest says ${pkg.integrity}`);
    checked += 1;
  } else {
    notes.push(`${pkg.name}: integrity ${pkg.integrity?.slice(0, 19) ?? 'none'}… not compared (no --archives)`);
  }
}

// ── The edition, held by the site ───────────────────────────────────────────
if (site) {
  for (const f of manifest.edition.files) {
    const actual = sha256(join(site, f.path));
    if (update) f.sha256 = actual;
    else if (f.sha256 !== actual) problems.push(`edition ${f.path}: ${actual}, the manifest says ${f.sha256}`);
    checked += 1;
  }
} else {
  notes.push('edition: not compared (no --site)');
}

// ── What a final release may not leave open ─────────────────────────────────
const pending = manifest.decisions.filter((d) => d.state !== 'decided');
if (pending.length) notes.push(`decisions pending: ${pending.map((d) => d.id).join(', ')}`);
if (final) {
  if (manifest.state !== 'final') problems.push(`state is ${manifest.state}, not final`);
  if (pending.length) problems.push(`decisions pending: ${pending.map((d) => d.id).join(', ')}`);
  if (!archives) problems.push('a final check compares the archives (--archives)');
  if (!site) problems.push('a final check compares the edition (--site)');
  if (manifest.packages.some((p) => p.nameStatus !== 'confirmed')) problems.push('package names not confirmed (D9)');
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
