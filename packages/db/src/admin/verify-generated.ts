import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, relative, resolve } from "node:path";
import { createRequire } from "node:module";

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationDirectory = resolve(packageRoot, "migrations");
const drizzlePath = (path: string) => path.replaceAll("\\", "/");

// Evaluate the canonical schema before copying any migration inventory. Some
// drizzle-kit releases print schema evaluation failures but still exit zero;
// an explicit import makes those failures fatal to this parity gate.
await import("../schema/index.js");

async function inventory(directory: string): Promise<Map<string, string>> {
  const result = new Map<string, string>();

  async function visit(currentDirectory: string): Promise<void> {
    const entries = await readdir(currentDirectory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    await Promise.all(
      entries.map(async (entry) => {
        const absolutePath = resolve(currentDirectory, entry.name);
        if (entry.isDirectory()) {
          await visit(absolutePath);
          return;
        }

        const content = await readFile(absolutePath);
        result.set(
          relative(directory, absolutePath).replaceAll("\\", "/"),
          createHash("sha256").update(content).digest("hex"),
        );
      }),
    );
  }

  await visit(directory);
  return result;
}

const scratchRoot = await mkdtemp(resolve(tmpdir(), "periapsis-db-drift-"));
const scratchMigrations = resolve(scratchRoot, "migrations");
const scratchConfig = resolve(scratchRoot, "drizzle.config.mjs");

try {
  await cp(migrationDirectory, scratchMigrations, { recursive: true });
  await writeFile(
    scratchConfig,
    `export default ${JSON.stringify(
      {
        dialect: "postgresql",
        schema: drizzlePath(resolve(packageRoot, "src/schema/index.ts")),
        // drizzle-kit 0.31 resolves even absolute Windows output paths against
        // the process working directory. Keep the scratch output relative and
        // run the generator from scratchRoot so an exit-zero ENOENT cannot turn
        // this drift check into a no-op.
        out: "./migrations",
        strict: true,
        verbose: false,
      },
      null,
      2,
    )};\n`,
    "utf8",
  );

  const require = createRequire(import.meta.url);
  const drizzleKitEntry = require.resolve("drizzle-kit");
  const drizzleKitCli = resolve(dirname(drizzleKitEntry), "bin.cjs");
  const generated = spawnSync(
    process.execPath,
    [drizzleKitCli, "generate", `--config=${scratchConfig}`],
    {
      cwd: scratchRoot,
      encoding: "utf8",
      stdio: "pipe",
    },
  );

  const generatorOutput = `${generated.stdout}\n${generated.stderr}`;
  const reportedRuntimeFailure =
    /\b(?:(?:Reference|Type|Syntax|Range)?Error|Exception):|\bENOENT\b|\bERR_[A-Z_]+\b|UnhandledPromiseRejection/i.test(
      generatorOutput,
    );
  if (generated.error || generated.status !== 0 || reportedRuntimeFailure) {
    process.stderr.write(generated.stdout);
    process.stderr.write(generated.stderr);
    throw new Error(
      "Drizzle schema-drift check could not generate a comparison migration",
    );
  }

  const [expected, actual] = await Promise.all([
    inventory(migrationDirectory),
    inventory(scratchMigrations),
  ]);

  const expectedEntries = [...expected].toSorted(([left], [right]) =>
    left.localeCompare(right),
  );
  const actualEntries = [...actual].toSorted(([left], [right]) =>
    left.localeCompare(right),
  );

  if (JSON.stringify(expectedEntries) !== JSON.stringify(actualEntries)) {
    throw new Error(
      "Drizzle schema and committed migration snapshot differ; run pnpm db:generate and commit the result",
    );
  }
} finally {
  await rm(scratchRoot, { recursive: true, force: true });
}
