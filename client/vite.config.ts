import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:7074",
      "/enclave": "http://localhost:7074",
    },
  },
});
