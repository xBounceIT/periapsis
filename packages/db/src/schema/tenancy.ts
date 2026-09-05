import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { tenantStatus } from "./enums.js";

export const tenants = pgTable(
  "tenants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    status: tenantStatus("status").notNull().default("active"),
    timezone: text("timezone").notNull().default("UTC"),
    locale: text("locale").notNull().default("en"),
    version: integer("version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenants_slug_key").on(table.slug),
    index("tenants_status_idx").on(table.status),
    check(
      "tenants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenants_slug_canonical_check",
      sql`${table.slug} = lower(${table.slug})`,
    ),
    check(
      "tenants_slug_shape_check",
      sql`${table.slug} ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'`,
    ),
    check(
      "tenants_name_shape_check",
      sql`btrim(${table.name}) <> '' and char_length(${table.name}) <= 160 and ${table.name} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenants_timezone_shape_check",
      sql`char_length(${table.timezone}) between 1 and 64 and ${table.timezone} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenants_locale_shape_check",
      sql`char_length(${table.locale}) <= 35
        and ${table.locale} ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
        and lower(split_part(${table.locale}, '-', 1)) <> 'und'`,
    ),
    check("tenants_version_positive_check", sql`${table.version} > 0`),
    check(
      "tenants_updated_after_created_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();
