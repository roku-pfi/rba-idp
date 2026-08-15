import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/admin/",
  build: {
    outDir: "../src/rba_idp/web/admin",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/login": "http://localhost:8001",
      "/session": "http://localhost:8001",
      "/logout": "http://localhost:8001",
      "/mfa": "http://localhost:8001",
      "/admin/api": "http://localhost:8001",
    },
  },
});
