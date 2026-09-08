/**
 * Expand a live credential against the live context, in jsonld safe mode.
 *
 * Nothing is pinned here on purpose: this is the check a reviewer would run,
 * fetching both the credential and the context over the network exactly as
 * published. Safe mode throws on any dropped property or relative IRI.
 *
 * Usage: node conformance/expand-live.mjs <did>
 */
import jsonld from 'jsonld';

const did = process.argv[2] ?? 'did:aria:aria.bar:u-cmDoHhM3:prod-smoke-test-py';
const response = await fetch(`https://api.aria.bar/v1/aids/${encodeURIComponent(did)}`);
if (!response.ok) {
  console.log(`  FALLA  ${did} → HTTP ${response.status}`);
  process.exit(1);
}
const body = await response.json();
const credential = body.data ?? body;

try {
  const expanded = await jsonld.expand(credential, { safe: true });
  const iris = new Set();
  (function walk(node) {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === 'object')
      for (const [key, value] of Object.entries(node)) {
        if (key.startsWith('http')) iris.add(key);
        walk(value);
      }
  })(expanded);
  console.log(`  OK     ${did}`);
  console.log(`         expande en modo safe, ${iris.size} IRIs, ninguna propiedad perdida`);
  console.log(`         contexto: ${JSON.stringify(credential['@context'])}`);
} catch (err) {
  const event = err.details?.event;
  console.log(`  FALLA  ${did}`);
  console.log(`         ${event?.message ?? err.message}`);
  if (event?.details) console.log(`         ${JSON.stringify(event.details)}`);
  process.exit(1);
}
