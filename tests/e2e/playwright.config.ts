import { defineConfig, devices } from "@playwright/test";

const webPort = 4173;
const browserChannel =
  process.env["PERIAPSIS_E2E_BROWSER_CHANNEL"] ??
  (process.platform === "win32" ? "msedge" : undefined);

export default defineConfig({
  testDir: ".",
  testMatch: "phase-three-ticketing.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env["CI"]),
  retries: process.env["CI"] ? 1 : 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: `http://127.0.0.1:${webPort}`,
    ...(browserChannel ? { channel: browserChannel } : {}),
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: `corepack pnpm --filter @periapsis/web exec vite --host 127.0.0.1 --port ${webPort} --strictPort`,
    url: `http://127.0.0.1:${webPort}`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
