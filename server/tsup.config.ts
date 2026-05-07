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
  // Bundle our own protocol workspace + tsup's own helpers, but leave
  // node_modules deps external. Inlining everything breaks packages with
  // dynamic require() (e.g. @simplewebauthn/server -> node-fetch -> punycode)
  // because the ESM bundle has no real CommonJS loader.
  noExternal: ["@e2ee-kv/protocol"],
  platform: "node",
});
