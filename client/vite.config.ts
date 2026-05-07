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
      // Mirror the production routing: in the enclave the supervisor (port 7073)
      // owns /v1/* and /enclave/*, and reverse-proxies everything else to the
      // user-app on port 7074. The mock-runtime in test/ stands in for the
      // supervisor for local dev.
      "/api": "http://localhost:7074",
      "/enclave": "http://localhost:7073",
      "/v1": "http://localhost:7073",
    },
  },
});
