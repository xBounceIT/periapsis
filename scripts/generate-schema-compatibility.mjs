import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import prettier from "prettier";

const repositoryRoot = resolve(import.meta.dirname, "..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const journalPath = resolve(migrationsRoot, "meta/_journal.json");
const journal = JSON.parse(readFileSync(journalPath, "utf8"));

if (!Array.isArray(journal.entries) || journal.entries.length === 0) {
  throw new Error(
    "The Drizzle migration journal must contain at least one entry",
  );
}

for (const [index, entry] of journal.entries.entries()) {
  const previous = journal.entries[index - 1];
  if (
    entry.idx !== index ||
    !Number.isSafeInteger(entry.when) ||
    (previous !== undefined && entry.when <= previous.when) ||
    typeof entry.tag !== "string" ||
    !/^\d{4}_[a-z0-9_]+$/.test(entry.tag)
  ) {
    throw new Error(
      `Invalid Drizzle migration journal entry at index ${index}`,
    );
  }
}

const migrationFiles = readdirSync(migrationsRoot)
  .filter((fileName) => fileName.endsWith(".sql"))
  .toSorted();
const journalFiles = journal.entries.map((entry) => `${entry.tag}.sql`);
if (JSON.stringify(migrationFiles) !== JSON.stringify(journalFiles)) {
  throw new Error("Drizzle migration files and journal entries differ");
}

const latest = journal.entries.at(-1);
const migrationHashes = journal.entries.map((entry) =>
  createHash("sha256")
    .update(readFileSync(resolve(migrationsRoot, `${entry.tag}.sql`)))
    .digest("hex"),
);
const migrationHash = migrationHashes.at(-1);
const migrationFingerprint = journal.entries
  .map((entry, index) => `${entry.when}@${migrationHashes[index]}`)
  .join(":");

const supportedLegacyV45MigrationCount = 199;
const supportedLegacyV45MigrationReplacements = [
  {
    index: 197,
    tag: "0197_ticket_metadata_replace_v1",
    createdAt: 1788128074116,
    legacyHash:
      "0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e",
    canonicalHash:
      "6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4",
  },
  {
    index: 198,
    tag: "0198_v45_compatibility",
    createdAt: 1788128702258,
    legacyHash:
      "0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c",
    canonicalHash:
      "fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea",
  },
];
for (const replacement of supportedLegacyV45MigrationReplacements) {
  const entry = journal.entries[replacement.index];
  if (
    entry?.tag !== replacement.tag ||
    entry.when !== replacement.createdAt ||
    migrationHashes[replacement.index] !== replacement.canonicalHash
  ) {
    throw new Error(
      `The canonical V45 migration changed at ordinal ${replacement.index + 1}`,
    );
  }
}

const representationCompatibilitySource = readFileSync(
  resolve(
    migrationsRoot,
    "0173_platform_identity_account_representation_compatibility.sql",
  ),
  "utf8",
);
const observationCompatibilitySource = readFileSync(
  resolve(
    migrationsRoot,
    "0176_platform_identity_account_observation_compatibility.sql",
  ),
  "utf8",
);
const directCompatibilitySource = readFileSync(
  resolve(migrationsRoot, "0179_platform_oidc_direct_compatibility.sql"),
  "utf8",
);
const directAdministrationCompatibilitySource = readFileSync(
  resolve(
    migrationsRoot,
    "0181_platform_oidc_direct_administration_compatibility.sql",
  ),
  "utf8",
);
function dollarQuotedConstant(source, name, tag = "checks") {
  const escapedTag = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `${name} constant text := \\$${escapedTag}\\$([\\s\\S]*?)\\$${escapedTag}\\$;`,
  );
  const match = source.match(pattern);
  if (match?.[1] === undefined) {
    throw new Error(`Missing derivation constant: ${name}`);
  }
  return match[1];
}

const v37CatalogMarker =
  "  IF EXISTS (\n" +
  "       SELECT 1\n" +
  "       FROM ONLY public.platform_federated_provider_policies AS policy";
const v37FunctionMarker =
  "  SELECT pg_catalog.pg_get_functiondef(\n" +
  "    'app.create_platform_oidc_auth_provider_v2";
const v37FunctionEntryMarker =
  "    ('app.guard_platform_identity_account_command_v1()',";
const v37FunctionEntryReplacement = [
  "    ('app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.guard_platform_federated_external_identity_v3()',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.guard_user_platform_identity_projection_v1()',",
  "      ARRAY['periapsis_migrator']::text[]),",
  v37FunctionEntryMarker,
].join("\n");
const v37PrivateReadinessMarker =
  "    AND app.private_platform_identity_runtime_schema_readiness_v3();";
const v37PredecessorAclChecks = [
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.platform_identity_runtime_schema_readiness_v2()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.platform_identity_runtime_schema_readiness_v2()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "",
].join("\n");
const v37CatalogChecks = dollarQuotedConstant(
  representationCompatibilitySource,
  "catalog_checks",
);
const v37FunctionChecks = dollarQuotedConstant(
  representationCompatibilitySource,
  "function_checks",
);
const v38ObservationCatalogChecks = dollarQuotedConstant(
  observationCompatibilitySource,
  "observation_catalog_checks",
);
const v38ObservationFunctionChecks = dollarQuotedConstant(
  observationCompatibilitySource,
  "observation_function_checks",
);
const v38ActiveListEntry = [
  "    ('app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38ListEntries = [
  "    ('app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.list_platform_identity_accounts_v2(uuid,text,uuid,uuid,integer,boolean)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38ActiveGetEntry = [
  "    ('app.get_platform_identity_account_v1(uuid,uuid,uuid,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38GetEntries = [
  "    ('app.get_platform_identity_account_v1(uuid,uuid,uuid,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.get_platform_identity_account_v2(uuid,uuid,uuid,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38ActivePrelinkEntry = [
  "    ('app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38PrelinkEntries = [
  "    ('app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.prelink_platform_identity_account_v2(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38ActiveRetireEntry = [
  "    ('app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38RetireEntries = [
  "    ('app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v38NewGuardEntry = [
  "    ('app.guard_platform_federated_external_identity_v4()',",
  "      ARRAY['periapsis_migrator']::text[]),",
].join("\n");
const v38GuardEntries = [
  "    ('app.guard_platform_federated_external_identity_v3()',",
  "      ARRAY['periapsis_migrator']::text[]),",
  v38NewGuardEntry,
].join("\n");
const v38NewDocumentEntry = [
  "    ('app.private_platform_identity_account_document_v2(uuid,uuid)',",
  "      ARRAY['periapsis_migrator']::text[]),",
].join("\n");
const v38DocumentEntries = [
  "    ('app.private_platform_identity_account_document_v1(uuid,uuid)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  v38NewDocumentEntry,
].join("\n");
const v38CatalogMarker =
  "  IF NOT (\n    SELECT count(*) = 2 AND coalesce(bool_and(";
const v38FunctionMarker =
  "  SELECT pg_catalog.pg_get_functiondef(\n" +
  "    'app.private_platform_identity_account_document_v2(uuid,uuid)'::regprocedure";
const v38PrivateReadinessMarker =
  "    AND app.private_platform_identity_runtime_schema_readiness_v4();";
const v38PredecessorAclChecks = [
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.schema_compatibility_v37()'::regprocedure,'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.schema_compatibility_v37()'::regprocedure,'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "",
].join("\n");
const v39Checks = dollarQuotedConstant(directCompatibilitySource, "v39_checks");
const v39ActiveCreateEntry = [
  "    ('app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v39CreateEntries = [
  "    ('app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v39ActiveRetireEntry = [
  "    ('app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v39RetireEntries = [
  "    ('app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_migrator']::text[]),",
  "    ('app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)',",
  "      ARRAY['periapsis_api','periapsis_migrator']::text[]),",
].join("\n");
const v39ConstraintCount22 = [
  "    AND (SELECT count(*) = 22",
  "         AND count(*) FILTER (WHERE constraint_row.contype = 'c') = 5",
].join("\n");
const v39ConstraintCount20 = [
  "    AND (SELECT count(*) = 20",
  "         AND count(*) FILTER (WHERE constraint_row.contype = 'c') = 5",
].join("\n");
const v39FunctionMarker = [
  "  IF NOT dependency_surface_ready OR NOT trusted_root_catalog_ready",
  "     OR NOT account_relation_ready OR NOT account_contract_ready",
].join("\n");
const v39DependencyExclusionMarker = [
  "        'private_platform_identity_dependency_surface_hash_v5',",
  "        'private_platform_identity_runtime_schema_readiness_v5',",
  "        'platform_identity_runtime_schema_readiness_v5',",
  "        'schema_compatibility_v39'",
].join("\n");
const v39DependencyExclusions = [
  `${v39DependencyExclusionMarker},`,
  "        'private_platform_oidc_direct_dependency_surface_hash_v1',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v1',",
  "        'platform_oidc_direct_runtime_schema_readiness_v1'",
].join("\n");
const v39PrivateReadinessMarker =
  "    AND app.private_platform_identity_runtime_schema_readiness_v5();";
const v39PredecessorAclChecks = [
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.schema_compatibility_v38()'::regprocedure,'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.schema_compatibility_v38()'::regprocedure,'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "",
].join("\n");
const v40IdentityDependencyExclusionMarker = [
  "        'private_platform_identity_dependency_surface_hash_v6',",
  "        'private_platform_identity_runtime_schema_readiness_v6',",
  "        'platform_identity_runtime_schema_readiness_v6',",
  "        'schema_compatibility_v40',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v1',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v1',",
  "        'platform_oidc_direct_runtime_schema_readiness_v1'",
].join("\n");
const v40IdentityDependencyExclusions = [
  "        'private_platform_identity_dependency_surface_hash_v6',",
  "        'private_platform_identity_runtime_schema_readiness_v6',",
  "        'platform_identity_runtime_schema_readiness_v6',",
  "        'schema_compatibility_v40',",
  "        'private_platform_identity_dependency_surface_hash_v5',",
  "        'private_platform_identity_runtime_schema_readiness_v5',",
  "        'platform_identity_runtime_schema_readiness_v5',",
  "        'schema_compatibility_v39',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v1',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v1',",
  "        'platform_oidc_direct_runtime_schema_readiness_v1',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v2',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v2',",
  "        'platform_oidc_direct_runtime_schema_readiness_v2'",
].join("\n");
const v40DirectDependencyExclusionMarker = [
  "      'private_platform_oidc_direct_dependency_surface_hash_v2',",
  "      'private_platform_oidc_direct_runtime_schema_readiness_v2',",
  "      'platform_oidc_direct_runtime_schema_readiness_v2'",
].join("\n");
const v40DirectDependencyExclusions = [
  `${v40DirectDependencyExclusionMarker},`,
  "      'private_platform_oidc_direct_dependency_surface_hash_v1',",
  "      'private_platform_oidc_direct_runtime_schema_readiness_v1',",
  "      'platform_oidc_direct_runtime_schema_readiness_v1'",
].join("\n");
const v40DirectDormantInvariant = dollarQuotedConstant(
  directAdministrationCompatibilitySource,
  "dormant_invariant",
  "old",
);
const v40DirectLifecycleInvariant = dollarQuotedConstant(
  directAdministrationCompatibilitySource,
  "lifecycle_invariant",
  "new",
);
const v40DirectTenantSwitchEntry =
  "      ('app.apply_platform_oidc_tenant_switch_v1(jsonb)'),";
const v40DirectAdministrationEntries = [
  v40DirectTenantSwitchEntry,
  "      ('app.lookup_platform_oidc_tenant_switch_replay_v1(jsonb)'),",
  "      ('app.activate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'),",
  "      ('app.deactivate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'),",
].join("\n");
const v40DirectPrivateMarker = "        'guard_platform_oidc_login_policy_v1',";
const v40DirectPrivateReplacement = [
  v40DirectPrivateMarker,
  "        'guard_platform_auth_provider_binding_dependency_v1',",
  "        'guard_platform_oidc_direct_runtime_dependency_v1',",
  "        'private_platform_auth_provider_document_v1',",
  "        'private_platform_oidc_direct_activation_available_v1',",
  "        'set_platform_oidc_direct_login_activation_v1',",
].join("\n");
const v40DirectFinalMarker = "  RETURN true;\nEND;";
const v40DirectPrivateChecks = dollarQuotedConstant(
  directAdministrationCompatibilitySource,
  "v40_checks",
);
const v40DirectPrivateReadinessMarker =
  "    AND app.private_platform_oidc_direct_runtime_schema_readiness_v2();";
const v40DirectPredecessorAclChecks = [
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api','app.schema_compatibility_v39()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker','app.schema_compatibility_v39()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_api',",
  "      'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND NOT pg_catalog.has_function_privilege(",
  "      'periapsis_worker',",
  "      'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure,",
  "      'EXECUTE'",
  "    )",
  "    AND app.platform_identity_runtime_schema_readiness_v6()",
  "",
].join("\n");

const v41IdentitySchemaMarker = "        'schema_compatibility_v41',";
const v41IdentitySchemaReplacement = [
  v41IdentitySchemaMarker,
  "        'private_platform_identity_dependency_surface_hash_v6',",
  "        'private_platform_identity_runtime_schema_readiness_v6',",
  "        'platform_identity_runtime_schema_readiness_v6',",
  "        'schema_compatibility_v40',",
].join("\n");
const v41IdentityDirectMarker = [
  "        'private_platform_oidc_direct_dependency_surface_hash_v2',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v2',",
  "        'platform_oidc_direct_runtime_schema_readiness_v2'",
].join("\n");
const v41IdentityDirectReplacement = [
  `${v41IdentityDirectMarker},`,
  "        'private_platform_oidc_direct_dependency_surface_hash_v3',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v3',",
  "        'platform_oidc_direct_runtime_schema_readiness_v3',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v1',",
  "        'private_mfa_policy_administration_schema_readiness_v1',",
  "        'mfa_policy_administration_schema_readiness_v1'",
].join("\n");
const v41DirectCurrentMarker = [
  "      'private_platform_oidc_direct_dependency_surface_hash_v3',",
  "      'private_platform_oidc_direct_runtime_schema_readiness_v3',",
  "      'platform_oidc_direct_runtime_schema_readiness_v3',",
].join("\n");
const v41DirectCurrentReplacement = [
  v41DirectCurrentMarker,
  "      'private_platform_oidc_direct_dependency_surface_hash_v2',",
  "      'private_platform_oidc_direct_runtime_schema_readiness_v2',",
  "      'platform_oidc_direct_runtime_schema_readiness_v2',",
].join("\n");
const v41ReadinessFinalMarker = "  RETURN true;\nEND;";
const v41MFAPrivateCheck = [
  "  IF NOT app.private_mfa_policy_administration_schema_readiness_v1() THEN",
  "    RETURN false;",
  "  END IF;",
  "",
  "",
].join("\n");
const v41IdentityPublicReadinessMarker =
  "    AND app.private_platform_identity_runtime_schema_readiness_v7();";
const v41IdentityPublicChecks =
  [
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_api','app.schema_compatibility_v40()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_worker','app.schema_compatibility_v40()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_api',",
    "      'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_worker',",
    "      'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND app.mfa_policy_administration_schema_readiness_v1()",
  ].join("\n") + "\n";
const v41DirectPublicReadinessMarker =
  "    AND app.private_platform_oidc_direct_runtime_schema_readiness_v3();";
const v41DirectPublicChecks =
  [
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_api','app.schema_compatibility_v40()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_worker','app.schema_compatibility_v40()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_api',",
    "      'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_worker',",
    "      'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_api',",
    "      'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND NOT pg_catalog.has_function_privilege(",
    "      'periapsis_worker',",
    "      'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure,",
    "      'EXECUTE'",
    "    )",
    "    AND app.platform_identity_runtime_schema_readiness_v7()",
  ].join("\n") + "\n";

const v42IdentityDependencyMarker = "        'schema_compatibility_v42',";
const v42IdentityDependencyExclusions = [
  v42IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v7',",
  "        'private_platform_identity_runtime_schema_readiness_v7',",
  "        'platform_identity_runtime_schema_readiness_v7',",
  "        'schema_compatibility_v41',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v4',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v4',",
  "        'platform_oidc_direct_runtime_schema_readiness_v4',",
  "        'private_platform_saml_direct_dependency_surface_hash_v1',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v1',",
  "        'platform_saml_direct_runtime_schema_readiness_v1',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v2',",
  "        'private_mfa_policy_administration_schema_readiness_v2',",
  "        'mfa_policy_administration_schema_readiness_v2',",
].join("\n");
const v42MFAPublicReadinessV1 =
  "        'app.mfa_policy_administration_schema_readiness_v1()'::regprocedure";
const v42MFAPublicReadinessExclusions = [
  `${v42MFAPublicReadinessV1},`,
  "        'app.mfa_policy_administration_schema_readiness_v2()'::regprocedure",
].join("\n");
const v42OIDCRestartCheck = [
  "  IF NOT EXISTS (",
  "    SELECT 1 FROM pg_catalog.pg_indexes",
  "    WHERE schemaname='public'",
  "      AND indexname='platform_post_primary_totp_challenges_live_continuation_key'",
  "      AND indexdef LIKE '%WHERE (state = ''pending''::text)%'",
  "  ) OR to_regprocedure('app.begin_platform_post_primary_totp_v2(jsonb)') IS NULL THEN",
  "    RETURN false;",
  "  END IF;",
  "",
  "",
].join("\n");

const v43IdentityDependencyMarker = "        'schema_compatibility_v43',";
const v43IdentityDependencyExclusions = [
  v43IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v8',",
  "        'private_platform_identity_runtime_schema_readiness_v8',",
  "        'platform_identity_runtime_schema_readiness_v8',",
  "        'schema_compatibility_v42',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v5',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v5',",
  "        'platform_oidc_direct_runtime_schema_readiness_v5',",
  "        'private_platform_saml_direct_dependency_surface_hash_v2',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v2',",
  "        'platform_saml_direct_runtime_schema_readiness_v2',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v3',",
  "        'private_mfa_policy_administration_schema_readiness_v3',",
  "        'mfa_policy_administration_schema_readiness_v3',",
].join("\n");
const v43MFAPublicReadinessV2 =
  "        'app.mfa_policy_administration_schema_readiness_v2()'::regprocedure";
const v43MFAPublicReadinessExclusions = [
  `${v43MFAPublicReadinessV2},`,
  "        'app.mfa_policy_administration_schema_readiness_v3()'::regprocedure",
].join("\n");
const v43SAMLMetadataProjectionCheck = [
  "  IF NOT EXISTS (",
  "    SELECT 1 FROM pg_catalog.pg_proc AS function_row",
  "    JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner",
  "    JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang",
  "    WHERE function_row.oid=",
  "      'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure",
  "      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'",
  "      AND function_row.provolatile='s' AND function_row.prosecdef",
  "      AND function_row.proconfig IS NOT DISTINCT FROM",
  "        ARRAY['search_path=pg_catalog, public, app']::text[]",
  "      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(",
  "        function_row.prosrc,'UTF8')),'hex')='f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989'",
  "  ) THEN RETURN false; END IF;",
  "",
  "",
].join("\n");
const v43SAMLReadinessFinalMarker = "  RETURN true;";

const v44IdentityDependencyMarker = "        'schema_compatibility_v44',";
const v44IdentityDependencyExclusions = [
  v44IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v9',",
  "        'private_platform_identity_runtime_schema_readiness_v9',",
  "        'platform_identity_runtime_schema_readiness_v9',",
  "        'schema_compatibility_v43',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v6',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v6',",
  "        'platform_oidc_direct_runtime_schema_readiness_v6',",
  "        'private_platform_saml_direct_dependency_surface_hash_v3',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v3',",
  "        'platform_saml_direct_runtime_schema_readiness_v3',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v4',",
  "        'private_mfa_policy_administration_schema_readiness_v4',",
  "        'mfa_policy_administration_schema_readiness_v4',",
].join("\n");
const v44MFAPublicReadinessV3 =
  "        'app.mfa_policy_administration_schema_readiness_v3()'::regprocedure";
const v44MFAPublicReadinessExclusions = [
  `${v44MFAPublicReadinessV3},`,
  "        'app.mfa_policy_administration_schema_readiness_v4()'::regprocedure",
].join("\n");

const v45IdentityDependencyMarker = "        'schema_compatibility_v45',";
const v45IdentityDependencyExclusions = [
  v45IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v10',",
  "        'private_platform_identity_runtime_schema_readiness_v10',",
  "        'platform_identity_runtime_schema_readiness_v10',",
  "        'schema_compatibility_v44',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v7',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v7',",
  "        'platform_oidc_direct_runtime_schema_readiness_v7',",
  "        'private_platform_saml_direct_dependency_surface_hash_v4',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v4',",
  "        'platform_saml_direct_runtime_schema_readiness_v4',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v5',",
  "        'private_mfa_policy_administration_schema_readiness_v5',",
  "        'mfa_policy_administration_schema_readiness_v5',",
].join("\n");
const v45MFAPublicReadinessV4 =
  "        'app.mfa_policy_administration_schema_readiness_v4()'::regprocedure";
const v45MFAPublicReadinessExclusions = [
  `${v45MFAPublicReadinessV4},`,
  "        'app.mfa_policy_administration_schema_readiness_v5()'::regprocedure",
].join("\n");
const v46IdentityDependencyMarker = "        'schema_compatibility_v46',";
const v46IdentityDependencyExclusions = [
  v46IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v11',",
  "        'private_platform_identity_runtime_schema_readiness_v11',",
  "        'platform_identity_runtime_schema_readiness_v11',",
  "        'schema_compatibility_v45',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v8',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v8',",
  "        'platform_oidc_direct_runtime_schema_readiness_v8',",
  "        'private_platform_saml_direct_dependency_surface_hash_v5',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v5',",
  "        'platform_saml_direct_runtime_schema_readiness_v5',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v6',",
  "        'private_mfa_policy_administration_schema_readiness_v6',",
  "        'mfa_policy_administration_schema_readiness_v6',",
].join("\n");
const v46MFAPublicReadinessV5 =
  "        'app.mfa_policy_administration_schema_readiness_v5()'::regprocedure";
const v46MFAPublicReadinessExclusions = [
  `${v46MFAPublicReadinessV5},`,
  "        'app.mfa_policy_administration_schema_readiness_v6()'::regprocedure",
].join("\n");
const v47IdentityDependencyMarker = "        'schema_compatibility_v47',";
const v47IdentityDependencyExclusions = [
  v47IdentityDependencyMarker,
  "        'private_platform_identity_dependency_surface_hash_v12',",
  "        'private_platform_identity_runtime_schema_readiness_v12',",
  "        'platform_identity_runtime_schema_readiness_v12',",
  "        'schema_compatibility_v46',",
  "        'private_platform_oidc_direct_dependency_surface_hash_v9',",
  "        'private_platform_oidc_direct_runtime_schema_readiness_v9',",
  "        'platform_oidc_direct_runtime_schema_readiness_v9',",
  "        'private_platform_saml_direct_dependency_surface_hash_v6',",
  "        'private_platform_saml_direct_runtime_schema_readiness_v6',",
  "        'platform_saml_direct_runtime_schema_readiness_v6',",
  "        'private_mfa_policy_administration_dependency_surface_hash_v7',",
  "        'private_mfa_policy_administration_schema_readiness_v7',",
  "        'mfa_policy_administration_schema_readiness_v7',",
].join("\n");
const v47MFAPublicReadinessV6 =
  "        'app.mfa_policy_administration_schema_readiness_v6()'::regprocedure";
const v47MFAPublicReadinessExclusions = [
  `${v47MFAPublicReadinessV6},`,
  "        'app.mfa_policy_administration_schema_readiness_v7()'::regprocedure",
].join("\n");
const v47TicketMutationReadinessV1Entry = [
  "('app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)',",
  "      'v'::\"char\",true,false),",
].join("\n");
const v47TicketMutationReadinessV2Entry = [
  "('app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)',",
  "      'v'::\"char\",false,false),",
].join("\n");
const v47TicketWatcherReadinessV1Entry = [
  "('app.private_notification_operator_candidates_v1(uuid,uuid)',",
  "       '7578ee7692d7d08ab7b4dac54857737ee4da052bef7ee1d346892f06e8d08c8b',",
  "       'periapsis_notification_dispatch_owner','s',",
  "       ARRAY['search_path=pg_catalog, public, app']::text[],",
  "       ARRAY['periapsis_notification_dispatch_owner']::text[]),",
].join("\n");
const v47TicketWatcherReadinessV2Entry = [
  "('app.private_notification_operator_candidates_v1(uuid,uuid)',",
  "       '7578ee7692d7d08ab7b4dac54857737ee4da052bef7ee1d346892f06e8d08c8b',",
  "       'periapsis_notification_dispatch_owner','s',",
  "       ARRAY['search_path=pg_catalog, public, app']::text[],",
  "       ARRAY['periapsis_migrator','periapsis_notification_dispatch_owner']::text[]),",
].join("\n");
const v45SLATriggerActionReadinessMarker = "  RETURN EXISTS (";
const v45SLATriggerActionReadinessPrerequisite = [
  "  IF NOT EXISTS (",
  "    SELECT 1 FROM pg_catalog.pg_proc AS procedure",
  "    JOIN pg_catalog.pg_roles AS owner",
  "      ON owner.oid=procedure.proowner",
  "    WHERE procedure.oid=",
  "      'app.private_v45_sla_action_repairs_ready()'::regprocedure",
  "      AND owner.rolname='periapsis_sla_readiness_owner'",
  "      AND procedure.prosecdef AND procedure.provolatile='s'",
  "      AND pg_catalog.encode(pg_catalog.sha256(",
  "        pg_catalog.convert_to(procedure.prosrc,'UTF8')",
  "      ),'hex')=",
  "        '16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00'",
  "      AND (SELECT count(*)=1 AND coalesce(bool_and(",
  "        privilege.grantor=procedure.proowner",
  "        AND privilege.grantee=procedure.proowner",
  "        AND privilege.privilege_type='EXECUTE'",
  "        AND NOT privilege.is_grantable",
  "      ),false) FROM pg_catalog.aclexplode(coalesce(",
  "        procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)",
  "      )) AS privilege)",
  "  ) OR NOT app.private_v45_sla_action_repairs_ready() THEN",
  "    RETURN false;",
  "  END IF;",
  "",
  "",
].join("\n");
const v45TicketRuntimeReadinessMarker = "  RETURN EXISTS (";
function v45TicketRuntimeReadinessPrerequisite(surface) {
  return [
    "  IF NOT EXISTS (",
    "    SELECT 1 FROM pg_catalog.pg_proc AS procedure",
    "    JOIN pg_catalog.pg_roles AS owner",
    "      ON owner.oid=procedure.proowner",
    "    WHERE procedure.oid=",
    "      'app.private_v45_ticket_runtime_repairs_ready(text)'::regprocedure",
    "      AND owner.rolname='periapsis_migrator'",
    "      AND procedure.prosecdef AND procedure.provolatile='s'",
    "      AND pg_catalog.encode(pg_catalog.sha256(",
    "        pg_catalog.convert_to(procedure.prosrc,'UTF8')",
    "      ),'hex')=",
    "        'ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a'",
    "      AND (SELECT count(*)=1 AND coalesce(bool_and(",
    "        privilege.grantor=procedure.proowner",
    "        AND privilege.grantee=procedure.proowner",
    "        AND privilege.privilege_type='EXECUTE'",
    "        AND NOT privilege.is_grantable",
    "      ),false) FROM pg_catalog.aclexplode(coalesce(",
    "        procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)",
    "      )) AS privilege)",
    `  ) OR NOT app.private_v45_ticket_runtime_repairs_ready('${surface}') THEN`,
    "    RETURN false;",
    "  END IF;",
    "",
    "",
  ].join("\n");
}
const v45TicketBulkReadinessPrerequisite =
  v45TicketRuntimeReadinessPrerequisite("bulk");
const v45TicketExportReadinessPrerequisite =
  v45TicketRuntimeReadinessPrerequisite("export");

const functionSourceDefinitions = [
  {
    constant: "SchemaCompatibilityV38",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "schema_compatibility_v38",
    sourceName: "schema_compatibility_v36",
    sourceTransforms: [
      ["schema_compatibility_v36", "schema_compatibility_v38"],
      ["1788062677386", "1788069336676"],
      ["journal_count = 170", "journal_count = 177"],
    ],
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV39",
    name: "schema_compatibility_v39",
    sourceConstant: "SchemaCompatibilityV38",
    sourceTransforms: [
      ["schema_compatibility_v38", "schema_compatibility_v39"],
      ["1788069336676", "1788077000000"],
      ["journal_count = 177", "journal_count = 180"],
    ],
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV40",
    name: "schema_compatibility_v40",
    sourceConstant: "SchemaCompatibilityV39",
    sourceTransforms: [
      ["schema_compatibility_v39", "schema_compatibility_v40"],
      ["1788077000000", "1788085744122"],
      ["journal_count = 180", "journal_count = 182"],
    ],
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV41",
    name: "schema_compatibility_v41",
    sourceConstant: "SchemaCompatibilityV40",
    sourceTransforms: [
      ["schema_compatibility_v40", "schema_compatibility_v41"],
      ["1788085744122", "1788094095501"],
      ["journal_count = 182", "journal_count = 184"],
    ],
    runtime: true,
  },
  {
    constant: "SchemaCompatibilityV42",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "schema_compatibility_v42",
  },
  {
    constant: "SchemaCompatibilityV43",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "schema_compatibility_v43",
  },
  {
    constant: "SchemaCompatibilityV44",
    migration: "0196_v44_compatibility.sql",
    name: "schema_compatibility_v44",
  },
  {
    constant: "SchemaCompatibilityV45",
    migration: "0198_v45_compatibility.sql",
    name: "schema_compatibility_v45",
  },
  {
    constant: "SchemaCompatibilityV46",
    migration: "0201_v46_compatibility.sql",
    name: "schema_compatibility_v46",
  },
  {
    constant: "RetiredSchemaCompatibilityV45",
    name: "schema_compatibility_v45",
    sourceConstant: "SchemaCompatibilityV45",
  },
  {
    constant: "RetiredSchemaCompatibilityV44",
    name: "schema_compatibility_v44",
    sourceConstant: "SchemaCompatibilityV44",
  },
  {
    constant: "RetiredSchemaCompatibilityV40",
    name: "schema_compatibility_v40",
    sourceConstant: "SchemaCompatibilityV40",
  },
  {
    constant: "RetiredSchemaCompatibilityV39",
    name: "schema_compatibility_v39",
    sourceConstant: "SchemaCompatibilityV39",
    runtime: false,
  },
  {
    constant: "RetiredSchemaCompatibilityV38",
    name: "schema_compatibility_v38",
    sourceConstant: "SchemaCompatibilityV38",
    runtime: false,
  },
  {
    constant: "RetiredSchemaCompatibilityV37",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "schema_compatibility_v37",
    sourceName: "schema_compatibility_v36",
    sourceTransforms: [
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["1788062677386", "1788067083196"],
      ["journal_count = 170", "journal_count = 174"],
    ],
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV4",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "private_platform_identity_dependency_surface_hash_v4",
    sourceName: "private_tenant_platform_oidc_dependency_surface_hash_v1",
    sourceTransforms: [
      [
        "private_tenant_platform_oidc_dependency_surface_hash_v1",
        "private_platform_identity_dependency_surface_hash_v4",
      ],
      [
        "private_tenant_platform_oidc_runtime_schema_readiness_v1",
        "private_platform_identity_runtime_schema_readiness_v4",
      ],
      [
        "tenant_platform_oidc_runtime_schema_readiness_v1",
        "platform_identity_runtime_schema_readiness_v4",
      ],
      ["schema_compatibility_v35", "schema_compatibility_v38"],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV5",
    name: "private_platform_identity_dependency_surface_hash_v5",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV4",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v4",
        "private_platform_identity_dependency_surface_hash_v5",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v4",
        "private_platform_identity_runtime_schema_readiness_v5",
      ],
      [
        "platform_identity_runtime_schema_readiness_v4",
        "platform_identity_runtime_schema_readiness_v5",
      ],
      ["schema_compatibility_v38", "schema_compatibility_v39"],
      [v39DependencyExclusionMarker, v39DependencyExclusions],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV6",
    name: "private_platform_identity_dependency_surface_hash_v6",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV5",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v5",
        "private_platform_identity_dependency_surface_hash_v6",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v5",
        "private_platform_identity_runtime_schema_readiness_v6",
      ],
      [
        "platform_identity_runtime_schema_readiness_v5",
        "platform_identity_runtime_schema_readiness_v6",
      ],
      ["schema_compatibility_v39", "schema_compatibility_v40"],
      [v40IdentityDependencyExclusionMarker, v40IdentityDependencyExclusions],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV7",
    name: "private_platform_identity_dependency_surface_hash_v7",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV6",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v6",
        "private_platform_identity_dependency_surface_hash_v7",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v6",
        "private_platform_identity_runtime_schema_readiness_v7",
      ],
      [
        "platform_identity_runtime_schema_readiness_v6",
        "platform_identity_runtime_schema_readiness_v7",
      ],
      ["schema_compatibility_v40", "schema_compatibility_v41"],
      [v41IdentitySchemaMarker, v41IdentitySchemaReplacement],
      [v41IdentityDirectMarker, v41IdentityDirectReplacement],
    ],
    runtime: true,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV8",
    name: "private_platform_identity_dependency_surface_hash_v8",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV7",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v7",
        "private_platform_identity_dependency_surface_hash_v8",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v7",
        "private_platform_identity_runtime_schema_readiness_v8",
      ],
      [
        "platform_identity_runtime_schema_readiness_v7",
        "platform_identity_runtime_schema_readiness_v8",
      ],
      ["schema_compatibility_v41", "schema_compatibility_v42"],
      [v42IdentityDependencyMarker, v42IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV9",
    name: "private_platform_identity_dependency_surface_hash_v9",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV8",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v8",
        "private_platform_identity_dependency_surface_hash_v9",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v8",
        "private_platform_identity_runtime_schema_readiness_v9",
      ],
      [
        "platform_identity_runtime_schema_readiness_v8",
        "platform_identity_runtime_schema_readiness_v9",
      ],
      ["schema_compatibility_v42", "schema_compatibility_v43"],
      [v43IdentityDependencyMarker, v43IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV10",
    name: "private_platform_identity_dependency_surface_hash_v10",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV9",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v9",
        "private_platform_identity_dependency_surface_hash_v10",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v9",
        "private_platform_identity_runtime_schema_readiness_v10",
      ],
      [
        "platform_identity_runtime_schema_readiness_v9",
        "platform_identity_runtime_schema_readiness_v10",
      ],
      ["schema_compatibility_v43", "schema_compatibility_v44"],
      [v44IdentityDependencyMarker, v44IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV11",
    name: "private_platform_identity_dependency_surface_hash_v11",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV10",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v10",
        "private_platform_identity_dependency_surface_hash_v11",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v10",
        "private_platform_identity_runtime_schema_readiness_v11",
      ],
      [
        "platform_identity_runtime_schema_readiness_v10",
        "platform_identity_runtime_schema_readiness_v11",
      ],
      ["schema_compatibility_v44", "schema_compatibility_v45"],
      [v45IdentityDependencyMarker, v45IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV12",
    name: "private_platform_identity_dependency_surface_hash_v12",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV11",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v11",
        "private_platform_identity_dependency_surface_hash_v12",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v11",
        "private_platform_identity_runtime_schema_readiness_v12",
      ],
      [
        "platform_identity_runtime_schema_readiness_v11",
        "platform_identity_runtime_schema_readiness_v12",
      ],
      ["schema_compatibility_v45", "schema_compatibility_v46"],
      [v46IdentityDependencyMarker, v46IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV4",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "private_platform_identity_runtime_schema_readiness_v4",
    sourceName: "private_platform_identity_runtime_schema_readiness_v2",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v2",
        "private_platform_identity_runtime_schema_readiness_v3",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v2",
        "private_platform_identity_dependency_surface_hash_v3",
      ],
      [
        "platform_identity_runtime_schema_readiness_v2",
        "platform_identity_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["schema_compatibility_v35", "schema_compatibility_v36"],
      [
        "6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852",
        "3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04",
      ],
      [
        "dbe197debc5813ff66b9d7ad38c1cf273537f587d9d2612dea829e0709c3dfa9",
        "979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473",
      ],
      [
        "app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
        "app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
      ],
      ["SELECT count(*) = 11", "SELECT count(*) = 14"],
      [v37FunctionEntryMarker, v37FunctionEntryReplacement],
      [v37CatalogMarker, v37CatalogChecks + v37CatalogMarker],
      [v37FunctionMarker, v37FunctionChecks + v37FunctionMarker],
      [
        "private_platform_identity_runtime_schema_readiness_v3",
        "private_platform_identity_runtime_schema_readiness_v4",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v3",
        "private_platform_identity_dependency_surface_hash_v4",
      ],
      [
        "platform_identity_runtime_schema_readiness_v3",
        "platform_identity_runtime_schema_readiness_v4",
      ],
      ["schema_compatibility_v37", "schema_compatibility_v38"],
      [
        "3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04",
        "df4b65f12876ea3db587f5721abf2ce4e00e8d6676ece9c3e8de5409d4cb8205",
      ],
      [
        "979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473",
        "f078b26e61ed4daa2885a310118c2aacbdcdc4a9d93999fc16fbc1e639e7049f",
      ],
      [v38ActiveListEntry, v38ListEntries],
      [v38ActiveGetEntry, v38GetEntries],
      [v38ActivePrelinkEntry, v38PrelinkEntries],
      [v38ActiveRetireEntry, v38RetireEntries],
      ["SELECT count(*) = 14", "SELECT count(*) = 20"],
      [
        "platform_federated_external_identities_guard_v3",
        "platform_federated_external_identities_guard_v4",
      ],
      [
        "app.guard_platform_federated_external_identity_v3()",
        "app.guard_platform_federated_external_identity_v4()",
      ],
      [
        "app.private_platform_identity_account_document_v1(uuid,uuid)",
        "app.private_platform_identity_account_document_v2(uuid,uuid)",
      ],
      [v38NewGuardEntry, v38GuardEntries],
      [v38NewDocumentEntry, v38DocumentEntries],
      [v38CatalogMarker, v38ObservationCatalogChecks + v38CatalogMarker],
      [v38FunctionMarker, v38ObservationFunctionChecks + v38FunctionMarker],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV5",
    name: "private_platform_identity_runtime_schema_readiness_v5",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV4",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v4",
        "private_platform_identity_runtime_schema_readiness_v5",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v4",
        "private_platform_identity_dependency_surface_hash_v5",
      ],
      [
        "platform_identity_runtime_schema_readiness_v4",
        "platform_identity_runtime_schema_readiness_v5",
      ],
      ["schema_compatibility_v38", "schema_compatibility_v39"],
      [
        "df4b65f12876ea3db587f5721abf2ce4e00e8d6676ece9c3e8de5409d4cb8205",
        "6a28391afdce6696eef764bf08aa3c5cd59926c3720a555548aeea080b086127",
      ],
      [
        "f078b26e61ed4daa2885a310118c2aacbdcdc4a9d93999fc16fbc1e639e7049f",
        "a096dcc3b17fd035a87d2d52fdb4d8817f5a6c7fa666aee8fd2c2cc6d4217273",
      ],
      [v39ActiveCreateEntry, v39CreateEntries],
      [v39ActiveRetireEntry, v39RetireEntries],
      ["SELECT count(*) = 20", "SELECT count(*) = 22"],
      [v39ConstraintCount22, v39ConstraintCount20],
      [v39FunctionMarker, v39Checks + v39FunctionMarker],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV6",
    name: "private_platform_identity_runtime_schema_readiness_v6",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV5",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v5",
        "private_platform_identity_runtime_schema_readiness_v6",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v5",
        "private_platform_identity_dependency_surface_hash_v6",
      ],
      [
        "platform_identity_runtime_schema_readiness_v5",
        "platform_identity_runtime_schema_readiness_v6",
      ],
      ["schema_compatibility_v39", "schema_compatibility_v40"],
      [
        "6a28391afdce6696eef764bf08aa3c5cd59926c3720a555548aeea080b086127",
        "b6ac9c2d70924d1d3194dcc38fea91b6245a2e798df202bbdbfcdacf96e57c7e",
      ],
      [
        "a096dcc3b17fd035a87d2d52fdb4d8817f5a6c7fa666aee8fd2c2cc6d4217273",
        "6481d203d3c704a2ec2331ae49e0a9b5a2bced4ed8cbc0c7347a61f8d8f019d6",
      ],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV7",
    name: "private_platform_identity_runtime_schema_readiness_v7",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV6",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v6",
        "private_platform_identity_runtime_schema_readiness_v7",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v6",
        "private_platform_identity_dependency_surface_hash_v7",
      ],
      [
        "platform_identity_runtime_schema_readiness_v6",
        "platform_identity_runtime_schema_readiness_v7",
      ],
      ["schema_compatibility_v40", "schema_compatibility_v41"],
      [
        "b6ac9c2d70924d1d3194dcc38fea91b6245a2e798df202bbdbfcdacf96e57c7e",
        "11aaeb68992daf0e5df7a81eefc66aab1f6d2572b834ff73c3a4d6989253b287",
      ],
      [
        "6481d203d3c704a2ec2331ae49e0a9b5a2bced4ed8cbc0c7347a61f8d8f019d6",
        "d22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287",
      ],
      [v41ReadinessFinalMarker, v41MFAPrivateCheck + v41ReadinessFinalMarker],
    ],
    runtime: true,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV8",
    name: "private_platform_identity_runtime_schema_readiness_v8",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV7",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v7",
        "private_platform_identity_runtime_schema_readiness_v8",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v7",
        "private_platform_identity_dependency_surface_hash_v8",
      ],
      [
        "platform_identity_runtime_schema_readiness_v7",
        "platform_identity_runtime_schema_readiness_v8",
      ],
      ["schema_compatibility_v41", "schema_compatibility_v42"],
      [
        "private_mfa_policy_administration_schema_readiness_v1",
        "private_mfa_policy_administration_schema_readiness_v2",
      ],
      [
        "11aaeb68992daf0e5df7a81eefc66aab1f6d2572b834ff73c3a4d6989253b287",
        "ea0eb6ee4edbadef50c532930f7e34d3f616b32899b2f6337412f684804d1431",
      ],
      [
        "d22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287",
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
      ],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV9",
    name: "private_platform_identity_runtime_schema_readiness_v9",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV8",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v8",
        "private_platform_identity_runtime_schema_readiness_v9",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v8",
        "private_platform_identity_dependency_surface_hash_v9",
      ],
      [
        "platform_identity_runtime_schema_readiness_v8",
        "platform_identity_runtime_schema_readiness_v9",
      ],
      ["schema_compatibility_v42", "schema_compatibility_v43"],
      [
        "private_mfa_policy_administration_schema_readiness_v2",
        "private_mfa_policy_administration_schema_readiness_v3",
      ],
      [
        "ea0eb6ee4edbadef50c532930f7e34d3f616b32899b2f6337412f684804d1431",
        "f86426fedb8a656730f22f4b6ce4f9e4133e830b9867dac78c82392d382b78ed",
      ],
      [
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
      ],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV10",
    name: "private_platform_identity_runtime_schema_readiness_v10",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV9",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v9",
        "private_platform_identity_runtime_schema_readiness_v10",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v9",
        "private_platform_identity_dependency_surface_hash_v10",
      ],
      [
        "platform_identity_runtime_schema_readiness_v9",
        "platform_identity_runtime_schema_readiness_v10",
      ],
      ["schema_compatibility_v43", "schema_compatibility_v44"],
      [
        "private_mfa_policy_administration_schema_readiness_v3",
        "private_mfa_policy_administration_schema_readiness_v4",
      ],
      [
        "f86426fedb8a656730f22f4b6ce4f9e4133e830b9867dac78c82392d382b78ed",
        "7dfc42e5dd59ab9fc99f901dbd1a3c1825dc7afa713d52a3258d1b28f16328dc",
      ],
      [
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
      ],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV11",
    name: "private_platform_identity_runtime_schema_readiness_v11",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV10",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v10",
        "private_platform_identity_dependency_surface_hash_v11",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v10",
        "private_platform_identity_runtime_schema_readiness_v11",
      ],
      [
        "platform_identity_runtime_schema_readiness_v10",
        "platform_identity_runtime_schema_readiness_v11",
      ],
      ["schema_compatibility_v44", "schema_compatibility_v45"],
      [
        "private_mfa_policy_administration_schema_readiness_v4",
        "private_mfa_policy_administration_schema_readiness_v5",
      ],
      [
        "7dfc42e5dd59ab9fc99f901dbd1a3c1825dc7afa713d52a3258d1b28f16328dc",
        "d7b3f12fb20fef0712d4c5ac7e777b2c8c59d94eb6ac5fc62cbe0a80828ef343",
      ],
      [
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
      ],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV12",
    name: "private_platform_identity_runtime_schema_readiness_v12",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV11",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v11",
        "private_platform_identity_dependency_surface_hash_v12",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v11",
        "private_platform_identity_runtime_schema_readiness_v12",
      ],
      [
        "platform_identity_runtime_schema_readiness_v11",
        "platform_identity_runtime_schema_readiness_v12",
      ],
      ["schema_compatibility_v45", "schema_compatibility_v46"],
      [
        "private_mfa_policy_administration_schema_readiness_v5",
        "private_mfa_policy_administration_schema_readiness_v6",
      ],
      [
        "d7b3f12fb20fef0712d4c5ac7e777b2c8c59d94eb6ac5fc62cbe0a80828ef343",
        "2d33728110b9e5828cb86ad15dbc066a69242ff3611f2793e9408b0838da35e7",
      ],
      [
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
      ],
    ],
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV4",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v4",
    sourceName: "platform_identity_runtime_schema_readiness_v2",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v2",
        "private_platform_identity_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["schema_compatibility_v35", "schema_compatibility_v36"],
      ["current_count = 170", "current_count = 174"],
      [
        v37PrivateReadinessMarker,
        v37PredecessorAclChecks + v37PrivateReadinessMarker,
      ],
      [
        "platform_identity_runtime_schema_readiness_v3",
        "platform_identity_runtime_schema_readiness_v4",
      ],
      ["schema_compatibility_v37", "schema_compatibility_v38"],
      ["current_count = 174", "current_count = 177"],
      [
        v38PrivateReadinessMarker,
        v38PredecessorAclChecks + v38PrivateReadinessMarker,
      ],
    ],
    runtime: false,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV5",
    name: "platform_identity_runtime_schema_readiness_v5",
    sourceConstant: "PlatformIdentityRuntimeReadinessV4",
    sourceTransforms: [
      [
        "platform_identity_runtime_schema_readiness_v4",
        "platform_identity_runtime_schema_readiness_v5",
      ],
      ["schema_compatibility_v38", "schema_compatibility_v39"],
      ["current_count = 177", "current_count = 180"],
      [
        v39PrivateReadinessMarker,
        v39PredecessorAclChecks + v39PrivateReadinessMarker,
      ],
    ],
    runtime: false,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV6",
    name: "platform_identity_runtime_schema_readiness_v6",
    sourceConstant: "PlatformIdentityRuntimeReadinessV5",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v5",
        "private_platform_identity_runtime_schema_readiness_v6",
      ],
      ["schema_compatibility_v39", "schema_compatibility_v40"],
      ["current_count = 180", "current_count = 182"],
    ],
    runtime: false,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV7",
    name: "platform_identity_runtime_schema_readiness_v7",
    sourceConstant: "PlatformIdentityRuntimeReadinessV6",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v6",
        "private_platform_identity_runtime_schema_readiness_v7",
      ],
      ["schema_compatibility_v40", "schema_compatibility_v41"],
      ["current_count = 182", "current_count = 184"],
      [
        v41IdentityPublicReadinessMarker,
        v41IdentityPublicChecks + v41IdentityPublicReadinessMarker,
      ],
    ],
    runtime: true,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV8",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v8",
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV9",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v9",
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV10",
    migration: "0196_v44_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v10",
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV11",
    migration: "0198_v45_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v11",
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV12",
    migration: "0201_v46_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v12",
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV1",
    migration: "0179_platform_oidc_direct_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v1",
    runtime: false,
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV2",
    name: "private_platform_oidc_direct_dependency_surface_hash_v2",
    sourceConstant: "PrivatePlatformOIDCDirectDependencySurfaceHashV1",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v1",
        "private_platform_oidc_direct_dependency_surface_hash_v2",
      ],
      [
        "private_platform_oidc_direct_runtime_schema_readiness_v1",
        "private_platform_oidc_direct_runtime_schema_readiness_v2",
      ],
      [
        "platform_oidc_direct_runtime_schema_readiness_v1",
        "platform_oidc_direct_runtime_schema_readiness_v2",
      ],
      [v40DirectDependencyExclusionMarker, v40DirectDependencyExclusions],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV3",
    name: "private_platform_oidc_direct_dependency_surface_hash_v3",
    sourceConstant: "PrivatePlatformOIDCDirectDependencySurfaceHashV2",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v2",
        "private_platform_oidc_direct_dependency_surface_hash_v3",
      ],
      [
        "private_platform_oidc_direct_runtime_schema_readiness_v2",
        "private_platform_oidc_direct_runtime_schema_readiness_v3",
      ],
      [
        "platform_oidc_direct_runtime_schema_readiness_v2",
        "platform_oidc_direct_runtime_schema_readiness_v3",
      ],
      [v41DirectCurrentMarker, v41DirectCurrentReplacement],
    ],
    runtime: true,
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV4",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v4",
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV5",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v5",
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV6",
    migration: "0196_v44_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v6",
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV7",
    migration: "0198_v45_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v7",
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV8",
    migration: "0201_v46_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v8",
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV1",
    migration: "0179_platform_oidc_direct_compatibility.sql",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV2",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v2",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV1",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v1",
        "private_platform_oidc_direct_dependency_surface_hash_v2",
      ],
      [
        "4d86365af67a2e98aef60473360474ae6b69d30c6548ff9605514fcb6133febe",
        "abad60eab36af53228d2f4ca1981f26b349f82f5fdf24538cc57af81039b561a",
      ],
      [
        "314be1f25c22af04d55868c1fcefa537884765d0c9083ef203aad1d8fed225df",
        "4693f7681d42acda62971c06878bb66cd1643efa2a2a48899480c3d9ce714c2a",
      ],
      [v40DirectDormantInvariant, v40DirectLifecycleInvariant],
      [v40DirectTenantSwitchEntry, v40DirectAdministrationEntries],
      [
        "SELECT count(*) = 21 AND coalesce(bool_and(",
        "SELECT count(*) = 24 AND coalesce(bool_and(",
      ],
      [v40DirectPrivateMarker, v40DirectPrivateReplacement],
      [v40DirectFinalMarker, v40DirectPrivateChecks + v40DirectFinalMarker],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV3",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v3",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV2",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v2",
        "private_platform_oidc_direct_dependency_surface_hash_v3",
      ],
      [
        "abad60eab36af53228d2f4ca1981f26b349f82f5fdf24538cc57af81039b561a",
        "f06b06d63728a9a6b678120cd6551c91598219638f488c1887424919c5fd981d",
      ],
      [
        "4693f7681d42acda62971c06878bb66cd1643efa2a2a48899480c3d9ce714c2a",
        "2f2a42486e1b90ead2c74ab87a27f2cc41c710f82ae7f3cd0be593ce5f1e40cc",
      ],
      [v41ReadinessFinalMarker, v41MFAPrivateCheck + v41ReadinessFinalMarker],
    ],
    runtime: true,
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV4",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v4",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV3",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v3",
        "private_platform_oidc_direct_dependency_surface_hash_v4",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v1",
        "private_mfa_policy_administration_schema_readiness_v2",
      ],
      [
        "f06b06d63728a9a6b678120cd6551c91598219638f488c1887424919c5fd981d",
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
      ],
      [
        "2f2a42486e1b90ead2c74ab87a27f2cc41c710f82ae7f3cd0be593ce5f1e40cc",
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
      ],
      [
        "%platform_oidc_login_policies AS login_policy%",
        "%platform_oidc_login_policies AS oidc_login%",
      ],
      [
        "%WHEN ''oidc'' THEN coalesce(login_policy.enabled, false)%",
        "%WHEN ''oidc'' THEN coalesce(oidc_login.enabled,false)%",
      ],
      [v41ReadinessFinalMarker, v42OIDCRestartCheck + v41ReadinessFinalMarker],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV5",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v5",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV4",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v4",
        "private_platform_oidc_direct_dependency_surface_hash_v5",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v2",
        "private_mfa_policy_administration_schema_readiness_v3",
      ],
      [
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
      ],
      [
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
      ],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV6",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v6",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV5",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v5",
        "private_platform_oidc_direct_dependency_surface_hash_v6",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v3",
        "private_mfa_policy_administration_schema_readiness_v4",
      ],
      [
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
      ],
      [
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
      ],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV7",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v7",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV6",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v6",
        "private_platform_oidc_direct_dependency_surface_hash_v7",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v4",
        "private_mfa_policy_administration_schema_readiness_v5",
      ],
      [
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
      ],
      [
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
      ],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV8",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v8",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV7",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v7",
        "private_platform_oidc_direct_dependency_surface_hash_v8",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v5",
        "private_mfa_policy_administration_schema_readiness_v6",
      ],
      [
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
      ],
      [
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
      ],
    ],
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV1",
    migration: "0179_platform_oidc_direct_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV2",
    name: "platform_oidc_direct_runtime_schema_readiness_v2",
    sourceConstant: "PlatformOIDCDirectRuntimeReadinessV1",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_runtime_schema_readiness_v1",
        "private_platform_oidc_direct_runtime_schema_readiness_v2",
      ],
      ["schema_compatibility_v39", "schema_compatibility_v40"],
      ["current_count = 180", "current_count = 182"],
      [
        v40DirectPrivateReadinessMarker,
        v40DirectPredecessorAclChecks + v40DirectPrivateReadinessMarker,
      ],
    ],
    runtime: false,
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV3",
    name: "platform_oidc_direct_runtime_schema_readiness_v3",
    sourceConstant: "PlatformOIDCDirectRuntimeReadinessV2",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_runtime_schema_readiness_v2",
        "private_platform_oidc_direct_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v40", "schema_compatibility_v41"],
      ["current_count = 182", "current_count = 184"],
      [
        "platform_identity_runtime_schema_readiness_v6",
        "platform_identity_runtime_schema_readiness_v7",
      ],
      [
        v41DirectPublicReadinessMarker,
        v41DirectPublicChecks + v41DirectPublicReadinessMarker,
      ],
    ],
    runtime: true,
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV4",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v4",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV5",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v5",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV6",
    migration: "0196_v44_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v6",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV7",
    migration: "0198_v45_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v7",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV8",
    migration: "0201_v46_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v8",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV1",
    migration: "0183_mfa_policy_administration_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v1",
    runtime: true,
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV2",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v2",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV3",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v3",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV4",
    migration: "0196_v44_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v4",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV5",
    migration: "0198_v45_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v5",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV6",
    migration: "0201_v46_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v6",
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV1",
    migration: "0183_mfa_policy_administration_compatibility.sql",
    name: "private_mfa_policy_administration_schema_readiness_v1",
    declarationIndex: "last",
    sourceTransforms: [
      [
        "__DEPENDENCY_SOURCE_HASH__",
        "dcfa970dc5239c535eeb30a7433989a3aab8572ec05572e6b660092f9eb6e73b",
      ],
      [
        "__DEPENDENCY_SURFACE_HASH__",
        "d22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287",
      ],
    ],
    runtime: true,
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV2",
    name: "private_mfa_policy_administration_schema_readiness_v2",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV1",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v1",
        "private_mfa_policy_administration_dependency_surface_hash_v2",
      ],
      [v42MFAPublicReadinessV1, v42MFAPublicReadinessExclusions],
      [
        "dcfa970dc5239c535eeb30a7433989a3aab8572ec05572e6b660092f9eb6e73b",
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
      ],
      [
        "d22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287",
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
      ],
    ],
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV3",
    name: "private_mfa_policy_administration_schema_readiness_v3",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV2",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v2",
        "private_mfa_policy_administration_dependency_surface_hash_v3",
      ],
      [v43MFAPublicReadinessV2, v43MFAPublicReadinessExclusions],
      [
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
      ],
      [
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
      ],
    ],
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV4",
    name: "private_mfa_policy_administration_schema_readiness_v4",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV3",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v3",
        "private_mfa_policy_administration_dependency_surface_hash_v4",
      ],
      [v44MFAPublicReadinessV3, v44MFAPublicReadinessExclusions],
      [
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
      ],
      [
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
      ],
    ],
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV5",
    name: "private_mfa_policy_administration_schema_readiness_v5",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV4",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v4",
        "private_mfa_policy_administration_dependency_surface_hash_v5",
      ],
      [v45MFAPublicReadinessV4, v45MFAPublicReadinessExclusions],
      [
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
      ],
      [
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
      ],
    ],
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV6",
    name: "private_mfa_policy_administration_schema_readiness_v6",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV5",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v5",
        "private_mfa_policy_administration_dependency_surface_hash_v6",
      ],
      [v46MFAPublicReadinessV5, v46MFAPublicReadinessExclusions],
      [
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
      ],
      [
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
      ],
    ],
  },
  {
    constant: "MFAPolicyAdministrationReadinessV1",
    migration: "0183_mfa_policy_administration_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v1",
    runtime: true,
  },
  {
    constant: "MFAPolicyAdministrationReadinessV2",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v2",
  },
  {
    constant: "MFAPolicyAdministrationReadinessV3",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v3",
  },
  {
    constant: "MFAPolicyAdministrationReadinessV4",
    migration: "0196_v44_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v4",
  },
  {
    constant: "MFAPolicyAdministrationReadinessV5",
    migration: "0198_v45_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v5",
  },
  {
    constant: "MFAPolicyAdministrationReadinessV6",
    migration: "0201_v46_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v6",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV1",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v1",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV2",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v2",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV3",
    migration: "0196_v44_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v3",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV4",
    migration: "0198_v45_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v4",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV5",
    migration: "0201_v46_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v5",
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV1",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "private_platform_saml_direct_runtime_schema_readiness_v1",
    sourceTransforms: [
      [
        "__DEPENDENCY_SOURCE__",
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
      ],
      [
        "__DEPENDENCY_RESULT__",
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
      ],
    ],
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV2",
    name: "private_platform_saml_direct_runtime_schema_readiness_v2",
    sourceConstant: "PrivatePlatformSAMLDirectRuntimeReadinessV1",
    sourceTransforms: [
      [
        "private_platform_saml_direct_dependency_surface_hash_v1",
        "private_platform_saml_direct_dependency_surface_hash_v2",
      ],
      [
        "129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da",
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
      ],
      [
        "bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d",
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
      ],
      [
        v43SAMLReadinessFinalMarker,
        v43SAMLMetadataProjectionCheck + v43SAMLReadinessFinalMarker,
      ],
    ],
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV3",
    name: "private_platform_saml_direct_runtime_schema_readiness_v3",
    sourceConstant: "PrivatePlatformSAMLDirectRuntimeReadinessV2",
    sourceTransforms: [
      [
        "private_platform_saml_direct_dependency_surface_hash_v2",
        "private_platform_saml_direct_dependency_surface_hash_v3",
      ],
      [
        "dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb",
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
      ],
      [
        "0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba",
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
      ],
    ],
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV4",
    name: "private_platform_saml_direct_runtime_schema_readiness_v4",
    sourceConstant: "PrivatePlatformSAMLDirectRuntimeReadinessV3",
    sourceTransforms: [
      [
        "private_platform_saml_direct_dependency_surface_hash_v3",
        "private_platform_saml_direct_dependency_surface_hash_v4",
      ],
      [
        "99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598",
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
      ],
      [
        "4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3",
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
      ],
    ],
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV5",
    name: "private_platform_saml_direct_runtime_schema_readiness_v5",
    sourceConstant: "PrivatePlatformSAMLDirectRuntimeReadinessV4",
    sourceTransforms: [
      [
        "private_platform_saml_direct_dependency_surface_hash_v4",
        "private_platform_saml_direct_dependency_surface_hash_v5",
      ],
      [
        "873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8",
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
      ],
      [
        "ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb",
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
      ],
    ],
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV1",
    migration: "0187_platform_saml_direct_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v1",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV2",
    migration: "0189_platform_saml_metadata_projection_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v2",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV3",
    migration: "0196_v44_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v3",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV4",
    migration: "0198_v45_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v4",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV5",
    migration: "0201_v46_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v5",
  },
  {
    constant: "TicketMutationRuntimeReadinessV1",
    migration: "0196_v44_compatibility.sql",
    name: "ticket_mutation_runtime_schema_readiness_v1",
  },
  {
    constant: "SLATriggerActionRuntimeReadinessV1",
    migration: "0192_sla_trigger_action_runtime.sql",
    name: "sla_trigger_action_runtime_schema_readiness_v1",
    sourceTransforms: [
      [
        v45SLATriggerActionReadinessMarker,
        v45SLATriggerActionReadinessPrerequisite +
          v45SLATriggerActionReadinessMarker,
      ],
    ],
  },
  {
    constant: "PlatformLocalAccountRuntimeReadinessV1",
    migration: "0193_platform_local_account_runtime.sql",
    name: "platform_local_account_runtime_schema_readiness_v1",
  },
  {
    constant: "TicketBulkRuntimeReadinessV1",
    migration: "0194_ticket_bulk_export_runtime.sql",
    name: "ticket_bulk_runtime_schema_readiness_v1",
    sourceTransforms: [
      [
        v45TicketRuntimeReadinessMarker,
        v45TicketBulkReadinessPrerequisite + v45TicketRuntimeReadinessMarker,
      ],
    ],
  },
  {
    constant: "TicketExportRuntimeReadinessV1",
    migration: "0194_ticket_bulk_export_runtime.sql",
    name: "ticket_export_runtime_schema_readiness_v1",
    sourceTransforms: [
      [
        v45TicketRuntimeReadinessMarker,
        v45TicketExportReadinessPrerequisite + v45TicketRuntimeReadinessMarker,
      ],
    ],
  },
  {
    constant: "AlertDFIRRuntimeReadinessV1",
    migration: "0195_alert_dfir_runtime.sql",
    name: "alert_dfir_runtime_schema_readiness_v1",
  },
  {
    constant: "TicketMetadataRuntimeReadinessV1",
    migration: "0197_ticket_metadata_replace_v1.sql",
    name: "ticket_metadata_runtime_schema_readiness_v1",
  },
  {
    constant: "TicketWatcherRuntimeReadinessV1",
    migration: "0199_ticket_watcher_runtime.sql",
    name: "ticket_watcher_runtime_schema_readiness_v1",
  },
  {
    constant: "GuardMigrationConvergenceAttestationV1",
    migration: "0200_v46_forward_repair.sql",
    name: "guard_migration_convergence_attestation_v1",
  },
  {
    constant: "PrivateV46MigrationConvergenceSchemaReadinessV1",
    migration: "0200_v46_forward_repair.sql",
    name: "private_v46_migration_convergence_schema_readiness_v1",
  },
  {
    constant: "PrivateSchemaCompatibilityJournalV46",
    migration: "0200_v46_forward_repair.sql",
    name: "private_schema_compatibility_journal_v46",
  },
  {
    constant: "SchemaCompatibilityV37",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "schema_compatibility_v37",
    sourceName: "schema_compatibility_v36",
    sourceTransforms: [
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["1788062677386", "1788067083196"],
      ["journal_count = 170", "journal_count = 174"],
    ],
    runtime: false,
  },
  {
    constant: "RetiredSchemaCompatibilityV36",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "schema_compatibility_v36",
  },
  {
    constant: "SchemaCompatibilityV36",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "schema_compatibility_v36",
    runtime: false,
  },
  {
    constant: "RetiredSchemaCompatibilityV35",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "schema_compatibility_v35",
    runtime: false,
  },
  // Historical aliases remain generated for predecessor-upgrade evidence only.
  // Runtime health receives only entries whose runtime flag is not false.
  {
    constant: "SchemaCompatibilityV35",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "schema_compatibility_v35",
    runtime: false,
  },
  {
    constant: "RetiredSchemaCompatibilityV34",
    migration: "0162_tenant_platform_identity_binding_compatibility.sql",
    name: "schema_compatibility_v34",
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV34",
    migration: "0162_tenant_platform_identity_binding_compatibility.sql",
    name: "schema_compatibility_v34",
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV33",
    migration: "0158_platform_identity_provider_compatibility.sql",
    name: "schema_compatibility_v33",
    runtime: false,
  },
  {
    constant: "PlatformTenantLifecycleReadiness",
    migration: "0152_platform_tenant_lifecycle_readiness.sql",
    name: "platform_tenant_lifecycle_schema_readiness_v1",
  },
  // These predecessor readiness hashes remain TypeScript-only evidence for
  // upgrade tests; the API/worker health path never trusts or calls them.
  {
    constant: "PlatformIdentityProviderReadiness",
    migration: "0158_platform_identity_provider_compatibility.sql",
    name: "platform_identity_provider_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "TenantPlatformIdentityBindingSurfaceHash",
    migration: "0162_tenant_platform_identity_binding_compatibility.sql",
    name: "private_tenant_platform_identity_binding_surface_hash_v1",
    runtime: false,
  },
  {
    constant: "TenantPlatformIdentityBindingReadinessV1",
    migration: "0162_tenant_platform_identity_binding_compatibility.sql",
    name: "tenant_platform_identity_binding_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "TenantPlatformIdentityBindingReadinessV2",
    migration: "0162_tenant_platform_identity_binding_compatibility.sql",
    name: "tenant_platform_identity_binding_schema_readiness_v2",
    runtime: false,
  },
  {
    constant: "PrivateTenantPlatformOIDCRuntimeReadinessV1",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "private_tenant_platform_oidc_runtime_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "TenantPlatformOIDCRuntimeReadinessV1",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "tenant_platform_oidc_runtime_schema_readiness_v1",
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV3",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "private_platform_identity_dependency_surface_hash_v3",
    sourceName: "private_tenant_platform_oidc_dependency_surface_hash_v1",
    sourceTransforms: [
      [
        "private_tenant_platform_oidc_dependency_surface_hash_v1",
        "private_platform_identity_dependency_surface_hash_v3",
      ],
      [
        "private_tenant_platform_oidc_runtime_schema_readiness_v1",
        "private_platform_identity_runtime_schema_readiness_v3",
      ],
      [
        "tenant_platform_oidc_runtime_schema_readiness_v1",
        "platform_identity_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v35", "schema_compatibility_v37"],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV3",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "private_platform_identity_runtime_schema_readiness_v3",
    sourceName: "private_platform_identity_runtime_schema_readiness_v2",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v2",
        "private_platform_identity_runtime_schema_readiness_v3",
      ],
      [
        "private_platform_identity_dependency_surface_hash_v2",
        "private_platform_identity_dependency_surface_hash_v3",
      ],
      [
        "platform_identity_runtime_schema_readiness_v2",
        "platform_identity_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["schema_compatibility_v35", "schema_compatibility_v36"],
      [
        "6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852",
        "3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04",
      ],
      [
        "dbe197debc5813ff66b9d7ad38c1cf273537f587d9d2612dea829e0709c3dfa9",
        "979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473",
      ],
      [
        "app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
        "app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
      ],
      ["SELECT count(*) = 11", "SELECT count(*) = 14"],
      [v37FunctionEntryMarker, v37FunctionEntryReplacement],
      [v37CatalogMarker, v37CatalogChecks + v37CatalogMarker],
      [v37FunctionMarker, v37FunctionChecks + v37FunctionMarker],
    ],
    runtime: false,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV3",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v3",
    sourceName: "platform_identity_runtime_schema_readiness_v2",
    sourceTransforms: [
      [
        "private_platform_identity_runtime_schema_readiness_v2",
        "private_platform_identity_runtime_schema_readiness_v3",
      ],
      ["schema_compatibility_v36", "schema_compatibility_v37"],
      ["schema_compatibility_v35", "schema_compatibility_v36"],
      ["current_count = 170", "current_count = 174"],
      [
        v37PrivateReadinessMarker,
        v37PredecessorAclChecks + v37PrivateReadinessMarker,
      ],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV2",
    migration: "0166_platform_oidc_binding_readiness.sql",
    name: "private_platform_identity_dependency_surface_hash_v2",
    sourceName: "private_tenant_platform_oidc_dependency_surface_hash_v1",
    sourceTransforms: [
      [
        "private_tenant_platform_oidc_dependency_surface_hash_v1",
        "private_platform_identity_dependency_surface_hash_v2",
      ],
      [
        "private_tenant_platform_oidc_runtime_schema_readiness_v1",
        "private_platform_identity_runtime_schema_readiness_v2",
      ],
      [
        "tenant_platform_oidc_runtime_schema_readiness_v1",
        "platform_identity_runtime_schema_readiness_v2",
      ],
      ["schema_compatibility_v35", "schema_compatibility_v36"],
    ],
    runtime: false,
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV2",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "private_platform_identity_runtime_schema_readiness_v2",
    runtime: false,
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV2",
    migration: "0169_platform_identity_account_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v2",
    runtime: false,
  },
  {
    constant: "SchemaCompatibilityV47",
    migration: "0208_v47_compatibility.sql",
    name: "schema_compatibility_v47",
  },
  {
    constant: "RetiredSchemaCompatibilityV46",
    name: "schema_compatibility_v46",
    sourceConstant: "SchemaCompatibilityV46",
  },
  {
    constant: "PrivateV47MigrationConvergenceSchemaReadinessV1",
    migration: "0208_v47_compatibility.sql",
    name: "private_v47_migration_convergence_schema_readiness_v1",
  },
  {
    constant: "PrivateSchemaCompatibilityJournalV47",
    migration: "0208_v47_compatibility.sql",
    name: "private_schema_compatibility_journal_v47",
  },
  {
    constant: "PrivatePlatformIdentityDependencySurfaceHashV13",
    name: "private_platform_identity_dependency_surface_hash_v13",
    sourceConstant: "PrivatePlatformIdentityDependencySurfaceHashV12",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v12",
        "private_platform_identity_dependency_surface_hash_v13",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v12",
        "private_platform_identity_runtime_schema_readiness_v13",
      ],
      [
        "platform_identity_runtime_schema_readiness_v12",
        "platform_identity_runtime_schema_readiness_v13",
      ],
      ["schema_compatibility_v46", "schema_compatibility_v47"],
      [v47IdentityDependencyMarker, v47IdentityDependencyExclusions],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV9",
    migration: "0208_v47_compatibility.sql",
    name: "private_platform_oidc_direct_dependency_surface_hash_v9",
  },
  {
    constant: "PrivatePlatformSAMLDirectDependencySurfaceHashV6",
    migration: "0208_v47_compatibility.sql",
    name: "private_platform_saml_direct_dependency_surface_hash_v6",
  },
  {
    constant: "PrivateMFAPolicyAdministrationDependencySurfaceHashV7",
    migration: "0208_v47_compatibility.sql",
    name: "private_mfa_policy_administration_dependency_surface_hash_v7",
  },
  {
    constant: "PrivateMFAPolicyAdministrationReadinessV7",
    name: "private_mfa_policy_administration_schema_readiness_v7",
    sourceConstant: "PrivateMFAPolicyAdministrationReadinessV6",
    sourceTransforms: [
      [
        "private_mfa_policy_administration_dependency_surface_hash_v6",
        "private_mfa_policy_administration_dependency_surface_hash_v7",
      ],
      [v47MFAPublicReadinessV6, v47MFAPublicReadinessExclusions],
      [
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
        "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
      ],
      [
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
        "c57409efff14eba6b392a8ea21bba97953be945cb5849e2d14d2f843249d79fa",
      ],
    ],
  },
  {
    constant: "PrivatePlatformIdentityRuntimeReadinessV13",
    name: "private_platform_identity_runtime_schema_readiness_v13",
    sourceConstant: "PrivatePlatformIdentityRuntimeReadinessV12",
    sourceTransforms: [
      [
        "private_platform_identity_dependency_surface_hash_v12",
        "private_platform_identity_dependency_surface_hash_v13",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v12",
        "private_platform_identity_runtime_schema_readiness_v13",
      ],
      [
        "platform_identity_runtime_schema_readiness_v12",
        "platform_identity_runtime_schema_readiness_v13",
      ],
      ["schema_compatibility_v46", "schema_compatibility_v47"],
      [
        "private_mfa_policy_administration_schema_readiness_v6",
        "private_mfa_policy_administration_schema_readiness_v7",
      ],
      [
        "2d33728110b9e5828cb86ad15dbc066a69242ff3611f2793e9408b0838da35e7",
        "a90fe9d78c3bce7bffc47a71cb01ec3b83161dedc4adf3fee6839fa63c9a2394",
      ],
      [
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
        "c57409efff14eba6b392a8ea21bba97953be945cb5849e2d14d2f843249d79fa",
      ],
    ],
  },
  {
    constant: "PrivatePlatformOIDCDirectRuntimeReadinessV9",
    name: "private_platform_oidc_direct_runtime_schema_readiness_v9",
    sourceConstant: "PrivatePlatformOIDCDirectRuntimeReadinessV8",
    sourceTransforms: [
      [
        "private_platform_oidc_direct_dependency_surface_hash_v8",
        "private_platform_oidc_direct_dependency_surface_hash_v9",
      ],
      [
        "private_mfa_policy_administration_schema_readiness_v6",
        "private_mfa_policy_administration_schema_readiness_v7",
      ],
      [
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
        "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
      ],
      [
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
        "c57409efff14eba6b392a8ea21bba97953be945cb5849e2d14d2f843249d79fa",
      ],
    ],
  },
  {
    constant: "PrivatePlatformSAMLDirectRuntimeReadinessV6",
    name: "private_platform_saml_direct_runtime_schema_readiness_v6",
    sourceConstant: "PrivatePlatformSAMLDirectRuntimeReadinessV5",
    sourceTransforms: [
      [
        "private_platform_saml_direct_dependency_surface_hash_v5",
        "private_platform_saml_direct_dependency_surface_hash_v6",
      ],
      [
        "fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7",
        "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
      ],
      [
        "b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36",
        "c57409efff14eba6b392a8ea21bba97953be945cb5849e2d14d2f843249d79fa",
      ],
    ],
  },
  {
    constant: "MFAPolicyAdministrationReadinessV7",
    migration: "0208_v47_compatibility.sql",
    name: "mfa_policy_administration_schema_readiness_v7",
  },
  {
    constant: "PlatformIdentityRuntimeReadinessV13",
    migration: "0208_v47_compatibility.sql",
    name: "platform_identity_runtime_schema_readiness_v13",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV9",
    migration: "0208_v47_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v9",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV6",
    migration: "0208_v47_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v6",
  },
  {
    constant: "TicketMutationRuntimeReadinessV2",
    name: "ticket_mutation_runtime_schema_readiness_v2",
    sourceConstant: "TicketMutationRuntimeReadinessV1",
    sourceTransforms: [
      [
        "ticket_mutation_runtime_schema_readiness_v1",
        "ticket_mutation_runtime_schema_readiness_v2",
      ],
      [v47TicketMutationReadinessV1Entry, v47TicketMutationReadinessV2Entry],
    ],
  },
  {
    constant: "TicketWatcherRuntimeReadinessV2",
    name: "ticket_watcher_runtime_schema_readiness_v2",
    sourceConstant: "TicketWatcherRuntimeReadinessV1",
    sourceTransforms: [
      [v47TicketWatcherReadinessV1Entry, v47TicketWatcherReadinessV2Entry],
    ],
  },
  {
    constant: "TicketBulkRuntimeReadinessV2",
    migration: "0204_ticket_comment_downstream.sql",
    name: "ticket_bulk_runtime_schema_readiness_v2",
  },
  {
    constant: "TicketExportRuntimeReadinessV2",
    migration: "0204_ticket_comment_downstream.sql",
    name: "ticket_export_runtime_schema_readiness_v2",
  },
  {
    constant: "ContactsPortalSchemaReadinessV2",
    migration: "0204_ticket_comment_downstream.sql",
    name: "contacts_portal_schema_readiness_v2",
  },
  {
    constant: "SLAObjectEventIngressSchemaReadinessV1",
    migration: "0205_sla_object_event_ingress.sql",
    name: "sla_object_event_ingress_schema_readiness_v1",
  },
  {
    constant: "NotificationSchemaReadinessV4",
    migration: "0206_smtp_runtime_assurance.sql",
    name: "notification_schema_readiness_v4",
  },
  {
    constant: "TenantLDAPInteractiveAuthSchemaReadinessV1",
    migration: "0207_interactive_ldap_authentication.sql",
    name: "tenant_ldap_interactive_auth_schema_readiness_v1",
  },
  {
    constant: "SchemaCompatibilityV48",
    migration: "0218_v48_compatibility.sql",
    name: "schema_compatibility_v48",
  },
  {
    constant: "RetiredSchemaCompatibilityV47",
    name: "schema_compatibility_v47",
    sourceConstant: "SchemaCompatibilityV47",
  },
  {
    constant: "PrivateSchemaCompatibilityJournalV48",
    migration: "0218_v48_compatibility.sql",
    name: "private_schema_compatibility_journal_v48",
  },
  {
    constant: "PrivateReleaseRuntimeDependencySurfaceHashV48",
    migration: "0218_v48_compatibility.sql",
    name: "private_release_runtime_dependency_surface_hash_v48",
  },
  {
    constant: "PrivateReleaseRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "private_release_runtime_schema_readiness_v48",
  },
  {
    constant: "ReleaseRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "release_runtime_schema_readiness_v48",
  },
  {
    constant: "FederatedAuthenticationReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "federated_authentication_schema_readiness_v48",
  },
  {
    constant: "PlatformOIDCDirectRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "platform_oidc_direct_runtime_schema_readiness_v48",
  },
  {
    constant: "PlatformSAMLDirectRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "platform_saml_direct_runtime_schema_readiness_v48",
  },
  {
    constant: "PlatformLocalAccountRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "platform_local_account_runtime_schema_readiness_v48",
  },
  {
    constant: "SLATriggerActionRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "sla_trigger_action_runtime_schema_readiness_v48",
  },
  {
    constant: "SLAObjectEventIngressReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "sla_object_event_ingress_schema_readiness_v48",
  },
  {
    constant: "TicketBulkRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "ticket_bulk_runtime_schema_readiness_v48",
  },
  {
    constant: "TicketExportRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "ticket_export_runtime_schema_readiness_v48",
  },
  {
    constant: "TicketMetadataRuntimeReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "ticket_metadata_runtime_schema_readiness_v48",
  },
  {
    constant: "PrivateRotateSLAReadinessV48",
    migration: "0218_v48_compatibility.sql",
    name: "private_rotate_sla_readiness_v48",
  },
  {
    constant: "SealSchemaCompatibilityManifestV48",
    migration: "0218_v48_compatibility.sql",
    name: "seal_schema_compatibility_manifest",
    hasArguments: true,
    runtime: false,
  },
];

// V49 is intentionally registered only after its dedicated custom migration
// joins the journal. This lets the independently generated historical manifest
// remain reproducible while the final 0227 schema is still being frozen; once
// 0229 exists, missing or malformed V49 roots fail generation closed.
if (migrationFiles.includes("0229_v49_compatibility.sql")) {
  functionSourceDefinitions.push(
    {
      constant: "SchemaCompatibilityV49",
      migration: "0229_v49_compatibility.sql",
      name: "schema_compatibility_v49",
    },
    {
      constant: "RetiredSchemaCompatibilityV48",
      name: "schema_compatibility_v48",
      sourceConstant: "SchemaCompatibilityV48",
    },
    {
      constant: "PrivateSchemaCompatibilityJournalV49",
      migration: "0229_v49_compatibility.sql",
      name: "private_schema_compatibility_journal_v49",
    },
    {
      constant: "PrivateReleaseRuntimeDependencySurfaceHashV49",
      migration: "0229_v49_compatibility.sql",
      name: "private_release_runtime_dependency_surface_hash_v49",
    },
    {
      constant: "PrivateReleaseRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "private_release_runtime_schema_readiness_v49",
    },
    {
      constant: "ReleaseRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "release_runtime_schema_readiness_v49",
    },
    {
      constant: "FederatedAuthenticationReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "federated_authentication_schema_readiness_v49",
    },
    {
      constant: "PlatformOIDCDirectRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "platform_oidc_direct_runtime_schema_readiness_v49",
    },
    {
      constant: "PlatformSAMLDirectRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "platform_saml_direct_runtime_schema_readiness_v49",
    },
    {
      constant: "PlatformLocalAccountRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "platform_local_account_runtime_schema_readiness_v49",
    },
    {
      constant: "SLATriggerActionRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "sla_trigger_action_runtime_schema_readiness_v49",
    },
    {
      constant: "SLAObjectEventIngressReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "sla_object_event_ingress_schema_readiness_v49",
    },
    {
      constant: "TicketBulkRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "ticket_bulk_runtime_schema_readiness_v49",
    },
    {
      constant: "TicketExportRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "ticket_export_runtime_schema_readiness_v49",
    },
    {
      constant: "TicketMetadataRuntimeReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "ticket_metadata_runtime_schema_readiness_v49",
    },
    {
      constant: "NotificationDispatchReadinessV49",
      migration: "0229_v49_compatibility.sql",
      name: "notification_dispatch_readiness_v49",
    },
    {
      constant: "SealSchemaCompatibilityManifestV49",
      migration: "0229_v49_compatibility.sql",
      name: "seal_schema_compatibility_manifest",
      hasArguments: true,
      runtime: false,
    },
  );
}

if (
  new Set(functionSourceDefinitions.map(({ constant }) => constant)).size !==
  functionSourceDefinitions.length
) {
  throw new Error("Trusted function source constants must be unique");
}

const functionSources = new Map();
const functionSourceHashes = [];
for (const entry of functionSourceDefinitions) {
  let source;
  let declaration;
  if (entry.sourceConstant !== undefined) {
    source = functionSources.get(entry.sourceConstant);
    declaration = `generated source ${entry.sourceConstant}`;
    if (source === undefined) {
      throw new Error(`Missing trusted function source: ${declaration}`);
    }
  } else {
    const migrationSource = readFileSync(
      resolve(migrationsRoot, entry.migration),
      "utf8",
    );
    const sourceName = entry.sourceName ?? entry.name;
    const escapedName = sourceName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const declarationPattern = new RegExp(
      `^CREATE(?: OR REPLACE)? FUNCTION app\\.${escapedName}\\(${entry.hasArguments === true ? "" : "\\)"}`,
      "gm",
    );
    const declarations = [...migrationSource.matchAll(declarationPattern)];
    declaration = `app.${sourceName}(${entry.hasArguments === true ? "..." : ""})`;
    if (declarations.length === 0) {
      throw new Error(`Missing trusted function declaration: ${declaration}`);
    }
    if (declarations.length > 1 && entry.declarationIndex !== "last") {
      throw new Error(`Duplicate trusted function declaration: ${declaration}`);
    }
    const selectedDeclaration =
      entry.declarationIndex === "last" ? declarations.at(-1) : declarations[0];
    const declarationOffset = selectedDeclaration.index;
    const bodyMatch = migrationSource
      .slice(declarationOffset)
      .match(/AS \$([A-Za-z0-9_]*)\$/);
    if (bodyMatch?.index === undefined) {
      throw new Error(`Invalid trusted function body: ${declaration}`);
    }
    const bodyMarker = bodyMatch[0];
    const bodyOffset = declarationOffset + bodyMatch.index;
    const bodyEndMarker = `$${bodyMatch[1]}$;`;
    const bodyEnd = migrationSource.indexOf(
      bodyEndMarker,
      bodyOffset + bodyMarker.length,
    );
    if (bodyEnd < 0) {
      throw new Error(`Invalid trusted function body: ${declaration}`);
    }
    source = migrationSource.slice(bodyOffset + bodyMarker.length, bodyEnd);
  }
  for (const [from, to] of entry.sourceTransforms ?? []) {
    if (!source.includes(from)) {
      throw new Error(
        `Missing trusted function source transform in ${declaration}: ${from}`,
      );
    }
    source = source.replaceAll(from, to);
  }
  functionSources.set(entry.constant, source);
  functionSourceHashes.push({
    ...entry,
    hash: createHash("sha256").update(source).digest("hex"),
  });
}

const typescriptTarget = resolve(
  repositoryRoot,
  "packages/db/src/admin/schema-compatibility-manifest.gen.ts",
);
const typescriptEntries = journal.entries
  .map(
    (entry, index) => `  {
    tag: ${JSON.stringify(entry.tag)},
    createdAt: ${entry.when},
    hash: ${JSON.stringify(migrationHashes[index])},
  },`,
  )
  .join("\n");
const typescriptSource = `// Code generated by scripts/generate-schema-compatibility.mjs; DO NOT EDIT.

export const expectedMigrations = [
${typescriptEntries}
] as const;

export const expectedMigrationCount = ${journal.entries.length};
export const expectedMigrationCreatedAt = ${latest.when};
export const expectedMigrationHash =
  ${JSON.stringify(migrationHash)};
export const expectedMigrationFingerprint =
  ${JSON.stringify(migrationFingerprint)};
export const supportedLegacyV45MigrationCount =
  ${supportedLegacyV45MigrationCount};
export const supportedLegacyV45MigrationReplacements = ${JSON.stringify(
  supportedLegacyV45MigrationReplacements,
  undefined,
  2,
)} as const;
${functionSourceHashes
  .map(
    ({ constant, hash }) =>
      `export const expected${constant}SourceHash =\n  ${JSON.stringify(hash)};`,
  )
  .join("\n")}
`;
mkdirSync(dirname(typescriptTarget), { recursive: true });
writeFileSync(
  typescriptTarget,
  await prettier.format(typescriptSource, { parser: "typescript" }),
);

const notifierSourceConstants = new Set([
  "SchemaCompatibilityV49",
  "PrivateReleaseRuntimeDependencySurfaceHashV49",
  "PrivateReleaseRuntimeReadinessV49",
  "ReleaseRuntimeReadinessV49",
  "NotificationDispatchReadinessV49",
]);
const notifierFunctionSourceHashes = functionSourceHashes.filter(
  ({ constant }) => notifierSourceConstants.has(constant),
);
if (notifierFunctionSourceHashes.length !== notifierSourceConstants.size) {
  throw new Error("Missing a trusted V49 notifier function source");
}
const notifierTypescriptTarget = resolve(
  repositoryRoot,
  "services/notifier/src/schema-compatibility.gen.ts",
);
const notifierTypescriptSource = `// Code generated by scripts/generate-schema-compatibility.mjs; DO NOT EDIT.

export const expectedMigrationFingerprint =
  ${JSON.stringify(migrationFingerprint)};
${notifierFunctionSourceHashes
  .map(
    ({ constant, hash }) =>
      `export const expected${constant}SourceHash =\n  ${JSON.stringify(hash)};`,
  )
  .join("\n")}
`;
mkdirSync(dirname(notifierTypescriptTarget), { recursive: true });
writeFileSync(
  notifierTypescriptTarget,
  await prettier.format(notifierTypescriptSource, { parser: "typescript" }),
);

const packages = [
  {
    name: "postgres",
    path: resolve(
      repositoryRoot,
      "services/api/internal/postgres/schema_compatibility.gen.go",
    ),
  },
  {
    name: "postgres",
    path: resolve(
      repositoryRoot,
      "services/worker/internal/postgres/schema_compatibility.gen.go",
    ),
  },
];

for (const target of packages) {
  const functionSourceHashConstants = functionSourceHashes
    .filter(({ runtime }) => runtime !== false)
    .map(
      ({ constant, hash }) =>
        `const expected${constant}SourceHash = ${JSON.stringify(hash)}`,
    )
    .join("\n");
  const source = `// Code generated by scripts/generate-schema-compatibility.mjs; DO NOT EDIT.\n\npackage ${target.name}\n\nconst expectedMigrationCount int64 = ${journal.entries.length}\nconst expectedMigrationCreatedAt int64 = ${latest.when}\nconst expectedMigrationHash = ${JSON.stringify(migrationHash)}\nconst expectedMigrationFingerprint = ${JSON.stringify(migrationFingerprint)}\n${functionSourceHashConstants}\n`;
  mkdirSync(dirname(target.path), { recursive: true });
  writeFileSync(target.path, source);
}
