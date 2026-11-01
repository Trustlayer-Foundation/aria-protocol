#!/usr/bin/env node
// Acceptance of the two SDK packages as distribution artifacts, alone and as a pair.
//
// Builds and packs @aria-registry/sdk and @aria-registry/ap, or takes two archives
// already packed, then installs them with npm in fresh directories outside the
// repository: no workspace link, no source alias, nothing from ops/ or a sibling
// repository. Runs the consumer scenarios in scripts/pair/ against them. Exits 1 on
// any failure.
//
//   node sdk/scripts/check-pair.mjs [--archives <sdk.tgz> <ap.tgz>] [--report <file>]
//
// With --archives nothing is built or packed: the checks run on exactly those files,
// which is how a release accepts the archives it then publishes.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SDK = fileURLToPath(new URL('..', import.meta.url));
const PACKAGES = [
  { dir: 'aria-ts', name: '@aria-registry/sdk' },
  { dir: 'aria-ap-ts', name: '@aria-registry/ap' },
];
// Only for the synthetic issuer in scripts/pair/fixtures.mjs.
const FIXTURE_DEPS = ['@noble/curves@2.4.0', '@noble/post-quantum@0.5.4'];
const args = process.argv.slice(2);
const reportPath = args.includes('--report') ? args[args.indexOf('--report') + 1] : null;
const given = args.includes('--archives') ? args.slice(args.indexOf('--archives') + 1, args.indexOf('--archives') + 3).map((f) => resolve(f)) : null;
if (given && (given.length !== 2 || given.some((f) => !f.endsWith('.tgz')))) {
  console.error('--archives takes the credential package archive, then the ARIA AP archive');
  process.exit(2);
}

const run = (cmd, argv, cwd, options = {}) => execFileSync(cmd, argv, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
const digest = (file, algorithm, encoding) => createHash(algorithm).update(readFileSync(file)).digest(encoding);
const failures = [];
const fail = (what, detail) => failures.push({ what, ...detail });

function pack(pkg, into) {
  mkdirSync(into, { recursive: true });
  const before = new Set(readdirSync(into));
  run('pnpm', ['pack', '--pack-destination', into], join(SDK, pkg.dir));
  const made = readdirSync(into).filter((f) => f.endsWith('.tgz') && !before.has(f));
  if (made.length !== 1) throw new Error(`pnpm pack ${pkg.name}: expected one tarball, got ${made.join(', ')}`);
  return join(into, made[0]);
}

const work = mkdtempSync(join(tmpdir(), 'aria-sdk-pair-'));
const artifacts = {};

// Build, then pack twice: the same sources must give the same bytes. Given archives
// are taken as they are.
for (const [i, pkg] of PACKAGES.entries()) {
  let first;
  let reproducible = null;
  if (given) {
    first = given[i];
  } else {
    run('pnpm', ['build'], join(SDK, pkg.dir));
    first = pack(pkg, join(work, 'pack-1'));
    const second = pack(pkg, join(work, 'pack-2'));
    reproducible = digest(first, 'sha512', 'base64') === digest(second, 'sha512', 'base64');
    if (!reproducible) fail('pack is not reproducible', { package: pkg.name });
  }
  const manifest = JSON.parse(run('tar', ['-xzOf', first, 'package/package.json'], work));
  if (manifest.name !== pkg.name) fail('an archive is not the package expected in its place', { expected: pkg.name, got: manifest.name });
  const files = run('tar', ['-tzf', first], work).trim().split('\n').sort();
  artifacts[pkg.name] = {
    version: manifest.version,
    tarball: first,
    integrity: `sha512-${digest(first, 'sha512', 'base64')}`,
    sha256: digest(first, 'sha256', 'hex'),
    reproducible,
    files,
  };
  const unexpected = files.filter((f) => !/^package\/(dist\/index\.(js|js\.map|d\.ts)|schemas\/(?:aria-ap-[a-z]+-1|aid-1\.0)\.json|README\.md|API\.md|MIGRATION\.md|LICENSE|package\.json)$/.test(f));
  if (unexpected.length) fail('unexpected files in the tarball', { package: pkg.name, unexpected });
  // A packed manifest names registry versions, ranges or tags only: no path, link,
  // workspace, git, alias or URL, which all need a ':', '/' or '@'.
  const packed = JSON.parse(run('tar', ['-xzOf', first, 'package/package.json'], work));
  const local = ['dependencies', 'peerDependencies', 'optionalDependencies', 'devDependencies'].flatMap((field) =>
    Object.entries(packed[field] ?? {})
      .filter(([, spec]) => !/^[0-9A-Za-z.^~<>=|*+ -]+$/.test(String(spec)))
      .map(([name, spec]) => `${field}.${name}: ${spec}`),
  );
  if (local.length) fail('the packed manifest references a development location', { package: pkg.name, local });
}

// ARIA AP's built code imports the credential package by its public name only, and
// carries none of it; its other imports are its own declared dependencies.
const apTar = artifacts['@aria-registry/ap'].tarball;
const apCode = run('tar', ['-xzOf', apTar, 'package/dist/index.js'], work);
const apManifest = JSON.parse(run('tar', ['-xzOf', apTar, 'package/package.json'], work));
const apDependencies = Object.keys(apManifest.dependencies ?? {});
const allowedImport = (s) => s === '@aria-registry/sdk' || apDependencies.some((d) => d !== '@aria-registry/sdk' && (s === d || s.startsWith(`${d}/`)));
const apImports = [...apCode.matchAll(/from ['"]([^'"]+)['"]/g)].map((m) => m[1]);
if (!apImports.includes('@aria-registry/sdk') || apImports.some((s) => !allowedImport(s))) fail('ARIA AP imports something other than the credential package entry and its own dependencies', { apImports });
for (const marker of ['mldsa65-ed25519-2026', 'BitstringStatusList', 'createVerifier(']) {
  if (apCode.includes(marker)) fail('ARIA AP carries credential-package code', { marker });
}
// The schemas it ships are the protocol's, byte for byte, and all of them.
const shipped = artifacts['@aria-registry/ap'].files.filter((f) => f.startsWith('package/schemas/')).map((f) => f.slice('package/schemas/'.length));
const protocolSchemas = readdirSync(join(SDK, '..', 'schema')).filter((f) => /^aria-ap-[a-z]+-1\.json$/.test(f));
if (shipped.sort().join() !== protocolSchemas.sort().join()) fail('ARIA AP does not ship exactly the protocol\'s ARIA AP schemas', { shipped, protocolSchemas });
for (const name of shipped) {
  const packed = execFileSync('tar', ['-xzOf', apTar, `package/schemas/${name}`], { cwd: work });
  if (!packed.equals(readFileSync(join(SDK, '..', 'schema', name)))) fail('a packaged schema differs from the protocol\'s', { name });
}
// The credential package exports the AID 1.0 schema those schemas refer to, byte for byte.
const sdkTarFile = artifacts['@aria-registry/sdk'].tarball;
if (!artifacts['@aria-registry/sdk'].files.includes('package/schemas/aid-1.0.json') || !execFileSync('tar', ['-xzOf', sdkTarFile, 'package/schemas/aid-1.0.json'], { cwd: work }).equals(readFileSync(join(SDK, '..', 'schema', 'aid-1.0.json')))) {
  fail('the credential package does not export the protocol\'s aid-1.0.json byte for byte');
}
// Its declarations, likewise: the credential package's types come from the peer, not a copy.
const apTypes = run('tar', ['-xzOf', apTar, 'package/dist/index.d.ts'], work);
const apTypeImports = [...apTypes.matchAll(/from ['"]([^'"]+)['"]/g)].map((m) => m[1]);
if (apTypeImports.some((s) => !allowedImport(s))) fail('ARIA AP types import something other than the credential package entry and its own dependencies', { apTypeImports });
for (const marker of ['interface CredentialFacts', 'declare function createVerifier', 'type StandingState']) {
  if (apTypes.includes(marker)) fail('ARIA AP declares credential-package types itself', { marker });
}
if (!apManifest.peerDependencies?.['@aria-registry/sdk'] || apManifest.dependencies?.['@aria-registry/sdk']) {
  fail('ARIA AP must declare the credential package as a peer dependency, not bundle or pin its own copy', { peer: apManifest.peerDependencies, deps: apManifest.dependencies });
}

function consumer(name, tarballs, extra = []) {
  const dir = join(work, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `consumer-${name}`, private: true, type: 'module' }));
  run('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', ...extra, ...tarballs, ...FIXTURE_DEPS], dir);
  for (const f of readdirSync(join(SDK, 'scripts', 'pair'))) copyFileSync(join(SDK, 'scripts', 'pair', f), join(dir, f));
  return dir;
}

function installFailed(name, error) {
  return { scenario: name, passed: 0, failed: 1, results: [{ label: 'installs', ok: false, error: String(error.stderr ?? error.message).split('\n').slice(0, 4).join(' ') }] };
}

function scenario(dir, script) {
  try {
    return JSON.parse(run('node', [script], dir).trim().split('\n').at(-1));
  } catch (error) {
    const out = String(error.stdout ?? '').trim().split('\n').at(-1);
    try {
      return JSON.parse(out);
    } catch {
      return { scenario: script, passed: 0, failed: 1, results: [{ label: 'ran', ok: false, error: String(error.stderr ?? error.message).slice(0, 2000) }] };
    }
  }
}

const sdkTar = artifacts['@aria-registry/sdk'].tarball;
const scenarios = [];

// 1. The credential package alone.
try {
  scenarios.push(scenario(consumer('credentials-only', [sdkTar]), 'credentials-only.mjs'));
} catch (error) {
  scenarios.push(installFailed('credentials-only', error));
}

// 2. Both, the supported configuration: the application installs the credential package; AP resolves it as its peer.
// 3. A duplicated credential package next to the first: it must fail closed.
try {
  const pairDir = consumer('pair', [sdkTar, apTar]);
  scenarios.push(scenario(pairDir, 'pair.mjs'));
  scenarios.push(scenario(pairDir, 'ap-exchange.mjs'));
  scenarios.push(scenario(pairDir, 'historical.mjs'));
  const second = join(pairDir, 'second');
  mkdirSync(second);
  writeFileSync(join(second, 'package.json'), JSON.stringify({ name: 'second-copy', private: true, type: 'module' }));
  run('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', sdkTar], second);
  scenarios.push(scenario(pairDir, 'duplicated.mjs'));
} catch (error) {
  scenarios.push(installFailed('pair', error));
}

// 4. ARIA AP without its peer does not work on its own: it carries no credential verifier.
const aloneLabel = 'importing ARIA AP without the credential package fails';
let aloneResult;
try {
  const alone = join(work, 'ap-without-peer');
  mkdirSync(alone);
  writeFileSync(join(alone, 'package.json'), JSON.stringify({ name: 'consumer-ap-alone', private: true, type: 'module' }));
  run('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', '--legacy-peer-deps', apTar], alone);
  try {
    run('node', ['--input-type=module', '-e', "await import('@aria-registry/ap')"], alone);
    aloneResult = { label: aloneLabel, ok: false, got: 'imported' };
  } catch (error) {
    const missing = /Cannot find package '@aria-registry\/sdk'/.test(String(error.stderr));
    aloneResult = { label: aloneLabel, ok: missing, ...(missing ? {} : { got: String(error.stderr).slice(0, 500) }) };
  }
} catch (error) {
  aloneResult = { label: aloneLabel, ok: false, error: String(error.stderr ?? error.message).split('\n').slice(0, 4).join(' ') };
}
scenarios.push({ scenario: 'ap-without-peer', passed: aloneResult.ok ? 1 : 0, failed: aloneResult.ok ? 0 : 1, results: [aloneResult] });

for (const s of scenarios) if (s.failed) fail(`scenario ${s.scenario}`, { results: s.results.filter((r) => !r.ok) });

let revision = null;
let dirty = null;
try {
  revision = run('git', ['rev-parse', 'HEAD'], SDK).trim();
  dirty = run('git', ['status', '--porcelain', '--', '.'], SDK).trim() !== '';
} catch {
  // Not a git checkout: the report says so instead of naming a revision.
}
const report = {
  checked: 'the two SDK packages as packed artifacts, installed with npm outside the repository',
  source: { repository: 'aria-protocol', revision, uncommittedChangesUnderSdk: dirty, archives: given ? 'given' : 'packed here' },
  runtime: { node: process.version, npm: run('npm', ['--version'], work).trim(), pnpm: run('pnpm', ['--version'], work).trim() },
  pair: Object.fromEntries(Object.entries(artifacts).map(([name, a]) => [name, { version: a.version, integrity: a.integrity, sha256: a.sha256, reproducible: a.reproducible, files: a.files }])),
  compatibility: { '@aria-registry/ap': { peerDependencies: apManifest.peerDependencies } },
  scenarios: scenarios.map(({ scenario: name, passed, failed }) => ({ name, passed, failed })),
  failures,
};
if (reportPath) writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
for (const s of scenarios) console.log(`${s.failed ? 'FAIL' : 'ok  '} ${s.scenario}: ${s.passed} passed, ${s.failed} failed`);
for (const [name, a] of Object.entries(artifacts)) {
  const how = a.reproducible === null ? 'given' : a.reproducible ? 'reproducible' : 'not reproducible';
  console.log(`${a.reproducible === false ? 'FAIL' : 'ok  '} ${name}@${a.version} ${a.integrity} (${how})`);
}
for (const f of failures) console.log(`FAIL ${f.what}\n${JSON.stringify(f, null, 2)}`);
console.log(failures.length ? `\n${failures.length} failure(s)` : '\nboth packages hold, alone and as a pair');
process.exit(failures.length ? 1 : 0);
