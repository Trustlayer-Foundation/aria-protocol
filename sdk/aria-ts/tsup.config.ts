import { defineConfig } from 'tsup';

// ESM only; dependencies and peer dependencies stay external.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  minify: false,
  target: 'node20',
  tsconfig: 'tsconfig.build.json',
});
