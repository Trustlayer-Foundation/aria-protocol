import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// During development the credential package is its source in this repository.
// The packed artifacts are tested together by sdk/scripts/check-pair.mjs.
export default defineConfig({
  resolve: {
    alias: { '@aria-registry/sdk': fileURLToPath(new URL('../aria-ts/src/index.ts', import.meta.url)) },
  },
});
