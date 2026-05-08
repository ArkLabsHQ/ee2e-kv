import { defineConfig } from "vite";

// Fixture page for the QEMU regtest. Built into ./dist/ and served by a
// host-side static server (python3 -m http.server) on port 5174. Playwright
// loads it, attaches a CDP virtual authenticator, then calls window.runFlow().
export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
  },
});
