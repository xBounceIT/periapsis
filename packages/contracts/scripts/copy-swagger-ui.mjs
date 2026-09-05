import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const packageDirectory = dirname(
  require.resolve("swagger-ui-dist/package.json"),
);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const targetDirectory = resolve(
  scriptDirectory,
  "../../../services/api/internal/httpserver/swagger-ui",
);

mkdirSync(targetDirectory, { recursive: true });
for (const asset of [
  "swagger-ui.css",
  "swagger-ui-bundle.js",
  "swagger-ui-standalone-preset.js",
]) {
  copyFileSync(join(packageDirectory, asset), join(targetDirectory, asset));
}
