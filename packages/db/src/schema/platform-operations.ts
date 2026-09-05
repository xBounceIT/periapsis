import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  integer,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

import { users } from "./identity.js";
import { platformOperationsOwnerRole } from "./roles.js";

/**
 * The small, typed platform-wide presentation and regional default surface.
 * Identity, SMTP, retention, secrets, and every tenant setting remain in their
 * dedicated aggregates instead of becoming an untyped global JSON bag.
 */
export const platformGlobalSettings = pgTable(
  "platform_global_settings",
  {
    singleton: boolean("singleton").primaryKey().default(true),
    platformName: text("platform_name").notNull().default("Periapsis"),
    defaultLocale: text("default_locale").notNull().default("en"),
    defaultTimezone: text("default_timezone").notNull().default("UTC"),
    supportUrl: text("support_url"),
    version: integer("version").notNull().default(1),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_global_settings_singleton_check",
      sql`${table.singleton} is true`,
    ),
    check(
      "platform_global_settings_name_check",
      sql`${table.platformName} = btrim(${table.platformName})
        and char_length(${table.platformName}) between 1 and 120
        and ${table.platformName} !~ '[[:cntrl:]]'
        and ${table.platformName} !~ U&'[\\00AD\\061C\\180E\\200B-\\200F\\202A-\\202E\\2060-\\206F\\FEFF]'`,
    ),
    check(
      "platform_global_settings_locale_check",
      sql`${table.defaultLocale} ~ '^[a-z]{2,3}(-[A-Z]{2})?$'`,
    ),
    check(
      "platform_global_settings_timezone_check",
      sql`${table.defaultTimezone} = btrim(${table.defaultTimezone})
        and char_length(${table.defaultTimezone}) between 1 and 64
        and ${table.defaultTimezone} !~ '[[:cntrl:]]'
        and ${table.defaultTimezone} !~ U&'[\\00AD\\061C\\180E\\200B-\\200F\\202A-\\202E\\2060-\\206F\\FEFF]'`,
    ),
    check(
      "platform_global_settings_support_url_check",
      sql`${table.supportUrl} is null or (
        ${table.supportUrl} = btrim(${table.supportUrl})
        and octet_length(${table.supportUrl}) between 9 and 2048
        and ${table.supportUrl} ~ '^https://[^[:space:]/?#@]+(:[0-9]{1,5})?([/?#][^[:space:]]*)?$'
        and ${table.supportUrl} !~ '[[:cntrl:]]'
        and ${table.supportUrl} !~ U&'[\\00AD\\061C\\180E\\200B-\\200F\\202A-\\202E\\2060-\\206F\\FEFF]'
      )`,
    ),
    check(
      "platform_global_settings_version_check",
      sql`${table.version} between 1 and 2147483647`,
    ),
    check(
      "platform_global_settings_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    check(
      "platform_global_settings_updater_check",
      sql`(${table.version} = 1 and ${table.updatedByUserId} is null)
        or (${table.version} > 1 and ${table.updatedByUserId} is not null)`,
    ),
    pgPolicy("platform_global_settings_owner_access", {
      as: "permissive",
      for: "all",
      to: platformOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

/** Closed, non-security-critical platform feature catalog. */
export const platformFeatureFlags = pgTable(
  "platform_feature_flags",
  {
    key: text("key").primaryKey(),
    enabled: boolean("enabled").notNull().default(true),
    version: integer("version").notNull().default(1),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_feature_flags_key_check",
      sql`${table.key} = 'platform_failed_notifications_view'`,
    ),
    check(
      "platform_feature_flags_version_check",
      sql`${table.version} between 1 and 2147483647`,
    ),
    check(
      "platform_feature_flags_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    check(
      "platform_feature_flags_updater_check",
      sql`(${table.version} = 1 and ${table.updatedByUserId} is null)
        or (${table.version} > 1 and ${table.updatedByUserId} is not null)`,
    ),
    pgPolicy("platform_feature_flags_owner_access", {
      as: "permissive",
      for: "all",
      to: platformOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();
