import { sql } from "drizzle-orm";
import {
  char,
  check,
  foreignKey,
  integer,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

import { tenantMemberships } from "./identity.js";
import { tenantSettingsOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

/**
 * Safe tenant-facing visual and regional settings. Email, identity, SLA,
 * workflow, custom-field, contact, and retention configuration stay in their
 * dedicated versioned aggregates rather than becoming an untyped JSON bag.
 */
export const tenantSettings = pgTable(
  "tenant_settings",
  {
    tenantId: uuid("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "restrict" }),
    brandName: text("brand_name").notNull(),
    brandMark: text("brand_mark").notNull(),
    primaryColor: char("primary_color", { length: 7 }).notNull(),
    accentColor: char("accent_color", { length: 7 }).notNull(),
    version: integer("version").notNull().default(1),
    updatedByMembershipId: uuid("updated_by_membership_id"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "tenant_settings_updater_membership_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_settings_brand_name_check",
      sql`${table.brandName} = btrim(${table.brandName})
        and char_length(${table.brandName}) between 1 and 80
        and ${table.brandName} !~ '[[:cntrl:]]'
        and ${table.brandName} !~ U&'[\\00AD\\061C\\180E\\200B-\\200F\\202A-\\202E\\2060-\\206F\\FEFF]'`,
    ),
    check(
      "tenant_settings_brand_mark_check",
      sql`${table.brandMark} ~ '^[A-Z0-9]{1,4}$'`,
    ),
    check(
      "tenant_settings_primary_color_check",
      sql`${table.primaryColor} ~ '^#[0-9a-f]{6}$'`,
    ),
    check(
      "tenant_settings_accent_color_check",
      sql`${table.accentColor} ~ '^#[0-9a-f]{6}$'`,
    ),
    check(
      "tenant_settings_distinct_colors_check",
      sql`${table.primaryColor} <> ${table.accentColor}`,
    ),
    check(
      "tenant_settings_version_check",
      sql`${table.version} between 1 and 2147483647`,
    ),
    check(
      "tenant_settings_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("tenant_settings_owner_access", {
      as: "permissive",
      for: "all",
      to: tenantSettingsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();
