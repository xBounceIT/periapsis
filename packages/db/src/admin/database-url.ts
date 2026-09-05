import { readFileSync } from "node:fs";

export function requireDatabaseUrl(): string {
  const databaseUrl = process.env.DATABASE_URL;

  const databaseUrlFile = process.env.DATABASE_URL_FILE;
  if (databaseUrlFile !== undefined && databaseUrlFile.trim() !== "") {
    const value = readFileSync(databaseUrlFile, "utf8").trim();
    if (value === "") {
      throw new Error("DATABASE_URL_FILE contains an empty value");
    }
    return value;
  }

  if (databaseUrl === undefined || databaseUrl.trim() === "") {
    throw new Error("DATABASE_URL or DATABASE_URL_FILE is required");
  }

  return databaseUrl;
}
