import { defineConfig, devices } from "@playwright/test";

const baseURL =
  process.env["PERIAPSIS_LIVE_E2E_BASE_URL"] ?? "https://localhost:18081";

export default defineConfig({
  testDir: ".",
  testMatch: "phase-three-live.spec.ts",
  expect: { timeout: 15_000 },
  outputDir:
    process.env["PERIAPSIS_LIVE_E2E_OUTPUT_DIR"] ??
    "test-results/live-acceptance",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  timeout: 120_000,
  workers: 1,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    ignoreHTTPSErrors: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    // The live journey handles passwords, session cookies, a client secret, and
    // a one-time TOTP seed. Never persist those values in Playwright artifacts.
    screenshot: "off",
    trace: "off",
    video: "off",
  },
});
