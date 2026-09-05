import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": {
        target: process.env["PERIAPSIS_DEV_API_URL"] ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
      "/docs": {
        target: process.env["PERIAPSIS_DEV_API_URL"] ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
      "/openapi.json": {
        target: process.env["PERIAPSIS_DEV_API_URL"] ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: "jsdom",
    // Bound concurrent DOM environments so large mounted suites retain CPU headroom.
    maxWorkers: 4,
    exclude: ["**/node_modules/**", "**/dist/**", "**/dist-server/**"],
    setupFiles: ["./src/test-setup.ts"],
  },
});
