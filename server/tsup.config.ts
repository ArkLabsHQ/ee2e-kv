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
  // doesn't need to ship node_modules.
  noExternal: [/.*/],
  platform: "node",
  // The OpenTelemetry packages are CommonJS and dynamically require() Node
  // built-ins (async_hooks, perf_hooks, ...). esbuild can't statically bundle
  // those, so it emits a __require shim that throws at runtime. Defining a real
  // `require` via createRequire — ahead of that shim — makes the shim delegate
  // to it, so the dynamic requires resolve against Node's built-in modules.
  banner: {
    js: [
      "import { createRequire as __nodeCreateRequire } from 'node:module';",
      "const require = __nodeCreateRequire(import.meta.url);",
    ].join("\n"),
  },
});
