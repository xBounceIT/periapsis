import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import {
  tenantAuthProviderBindings,
  tenantLdapExternalIdentities,
} from "./identity-access.js";
import { tenantLdapJitAuthenticationRuns } from "./identity-jit.js";
import {
  authSessionMfaStates,
  tenantPostPrimaryContinuations,
} from "./identity-mfa.js";
import { tenants } from "./tenancy.js";

/**
 * LDAP primary provenance is physically distinct from OIDC/SAML federation.
 * Passwords, login names, directory attributes, and DNs are absent by design.
 */
export const authSessionLdapProvenance = pgTable(
  "auth_session_ldap_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    jitRunId: uuid("jit_run_id"),
    rootJitRunId: uuid("root_jit_run_id").notNull(),
    sourceSessionId: uuid("source_session_id"),
    sourceSessionFamilyId: uuid("source_session_family_id"),
    sourceSessionVersion: bigint("source_session_version", {
      mode: "bigint",
    }),
    sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    primaryKind: text("primary_kind").notNull().default("tenant_provider"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("ldap"),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    externalIdentityRevision: bigint("external_identity_revision", {
      mode: "bigint",
    }).notNull(),
    providerVersion: integer("provider_version").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    bindingVersion: integer("binding_version").notNull(),
    bindingAuthRevision: integer("binding_auth_revision").notNull(),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_ldap_provenance_pkey",
      columns: [table.tenantId, table.sessionId],
    }),
    unique("auth_session_ldap_provenance_jit_run_key").on(
      table.tenantId,
      table.jitRunId,
    ),
    foreignKey({
      name: "auth_session_ldap_provenance_state_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.primaryKind,
        table.userId,
      ],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
        authSessionMfaStates.primaryKind,
        authSessionMfaStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_ldap_provenance_jit_fk",
      columns: [table.tenantId, table.jitRunId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_ldap_provenance_root_jit_fk",
      columns: [table.tenantId, table.rootJitRunId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_ldap_provenance_source_fk",
      columns: [table.tenantId, table.sourceSessionId],
      foreignColumns: [table.tenantId, table.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_ldap_provenance_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_ldap_provenance_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.providerId,
        tenantLdapExternalIdentities.id,
        tenantLdapExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_ldap_provenance_kind_check",
      sql`${table.primaryKind} = 'tenant_provider' and ${table.authenticationMethod} = 'ldap'`,
    ),
    check(
      "auth_session_ldap_provenance_revision_check",
      sql`${table.externalIdentityRevision} > 0 and ${table.providerVersion} > 0
        and ${table.configurationRevision} > 0 and ${table.bindingVersion} > 0
        and ${table.bindingAuthRevision} > 0 and ${table.ruleSetRevision} > 0
        and ${table.authorizationRevision} > 0`,
    ),
    check(
      "auth_session_ldap_provenance_lineage_check",
      sql`(${table.jitRunId} is not null
          and ${table.rootJitRunId} = ${table.jitRunId}
          and ${table.sourceSessionId} is null
          and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null
          and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.jitRunId} is null
          and ${table.sourceSessionId} is not null
          and ${table.sourceSessionId} <> ${table.sessionId}
          and ${table.sourceSessionFamilyId} is not null
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionVersion} between 1 and 9007199254740991
          and ${table.sourceAbsoluteExpiresAt} > ${table.authenticatedAt})`,
    ),
  ],
).enableRLS();

/** LDAP provenance for a one-use post-primary MFA continuation. */
export const tenantPostPrimaryLdapProvenance = pgTable(
  "tenant_post_primary_ldap_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    jitRunId: uuid("jit_run_id"),
    rootJitRunId: uuid("root_jit_run_id").notNull(),
    sourceSessionId: uuid("source_session_id"),
    sourceSessionFamilyId: uuid("source_session_family_id"),
    sourceSessionVersion: bigint("source_session_version", {
      mode: "bigint",
    }),
    sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    externalIdentityRevision: bigint("external_identity_revision", {
      mode: "bigint",
    }).notNull(),
    providerVersion: integer("provider_version").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    bindingVersion: integer("binding_version").notNull(),
    bindingAuthRevision: integer("binding_auth_revision").notNull(),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_post_primary_ldap_provenance_pkey",
      columns: [table.tenantId, table.continuationId],
    }),
    unique("tenant_post_primary_ldap_provenance_jit_run_key").on(
      table.tenantId,
      table.jitRunId,
    ),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_continuation_fk",
      columns: [table.tenantId, table.continuationId, table.userId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_jit_fk",
      columns: [table.tenantId, table.jitRunId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_root_jit_fk",
      columns: [table.tenantId, table.rootJitRunId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_source_fk",
      columns: [table.tenantId, table.sourceSessionId],
      foreignColumns: [
        authSessionLdapProvenance.tenantId,
        authSessionLdapProvenance.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_ldap_provenance_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.providerId,
        tenantLdapExternalIdentities.id,
        tenantLdapExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_ldap_provenance_revision_check",
      sql`${table.externalIdentityRevision} > 0 and ${table.providerVersion} > 0
        and ${table.configurationRevision} > 0 and ${table.bindingVersion} > 0
        and ${table.bindingAuthRevision} > 0 and ${table.ruleSetRevision} > 0
        and ${table.authorizationRevision} > 0`,
    ),
    check(
      "tenant_post_primary_ldap_provenance_lineage_check",
      sql`(${table.jitRunId} is not null
          and ${table.rootJitRunId} = ${table.jitRunId}
          and ${table.sourceSessionId} is null
          and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null
          and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.jitRunId} is null
          and ${table.sourceSessionId} is not null
          and ${table.sourceSessionFamilyId} is not null
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionVersion} between 2 and 9007199254740991
          and ${table.sourceAbsoluteExpiresAt} > ${table.authenticatedAt})`,
    ),
  ],
).enableRLS();
