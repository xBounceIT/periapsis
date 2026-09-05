import { defineConfig } from "drizzle-kit";

const databaseUrl = process.env.DATABASE_URL;

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/schema/index.ts",
  out: "./migrations",
  strict: true,
  verbose: true,
  ...(databaseUrl === undefined
    ? {}
    : {
        dbCredentials: {
          url: databaseUrl,
        },
      }),
});
