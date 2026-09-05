import { resolve } from "node:path";
import postgres from "postgres";

import { requireDatabaseUrl } from "./database-url.js";
import { executeWithCleanup, migrateSchema } from "./schema-migration.js";

const client = postgres(requireDatabaseUrl(), {
  max: 1,
  onnotice: () => undefined,
});

await executeWithCleanup(
  () => migrateSchema(client, resolve(import.meta.dirname, "../../migrations")),
  () => client.end(),
  "schema migration and database client cleanup both failed",
);
