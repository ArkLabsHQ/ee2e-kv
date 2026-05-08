import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node22",
  outDir: "dist",
  clean: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  bundle: true,
  // Bundle every dep into a single self-contained ESM file so the EIF
  // doesn't need to ship node_modules. v13's @simplewebauthn/server dropped
  // its node-fetch transitive (the only CJS pkg with a dynamic require()
  // that broke ESM bundling), so [/.*/] is safe again. If a future dep
  // pulls dynamic require() back in, narrow this regex rather than
  // re-introducing the workspace-wide node_modules ship.
  noExternal: [/.*/],
  platform: "node",
});
