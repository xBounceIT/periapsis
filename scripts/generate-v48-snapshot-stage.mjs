import {
  cpSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const schemaRoot = resolve(repositoryRoot, "packages/db/src/schema");
const stagedSchemaRoot = resolve(
  repositoryRoot,
  "packages/db/.v48-snapshot-work/stage-schema",
);
const outputPath = resolve(
  repositoryRoot,
  "packages/db/v48-snapshot-stage-entry.ts",
);

const stage = Number.parseInt(process.argv[2] ?? "", 10);
if (!Number.isInteger(stage) || stage < 209 || stage > 218) {
  throw new Error(
    "Usage: node scripts/generate-v48-snapshot-stage.mjs <209..218>",
  );
}

const introducedAt = new Map([
  ["tenantLdapJitAuthorityIssuanceReceipts", 210],
  ["tenantMfaLdapRecoveryReplacementCapabilities", 210],
  ["platformLdapProviderConfigurations", 211],
  ["platformLdapProviderEndpoints", 211],
  ["platformLdapBindSecrets", 211],
  ["platformLdapMappingRules", 211],
  ["platformLdapExternalIdentities", 211],
  ["platformLdapExternalIdentityAliases", 211],
  ["platformLdapRoleGrants", 211],
  ["platformLdapAuthenticationRuns", 211],
  ["platformLdapSessionProvenance", 211],
  ["platformLdapTestRuns", 211],
  ["tenantMembershipLifecycleCommands", 212],
  ["auditOperationsOwnerRole", 213],
  ["platformUserAuthorizationEpochs", 213],
  ["tenantAuditExportJobs", 213],
  ["tenantAuditOperationReceipts", 213],
  ["tenantAuditExportManifests", 213],
  ["platformAuditExportJobs", 213],
  ["platformAuditOperationReceipts", 213],
  ["platformAuditExportManifests", 213],
  ["tenantAuditRetentionPolicies", 213],
  ["platformAuditRetentionPolicy", 213],
  ["tenantAuditLegalHolds", 213],
  ["platformAuditLegalHolds", 213],
  ["tenantAuditSegments", 213],
  ["platformAuditSegments", 213],
  ["tenantAuditRetentionAnchors", 213],
  ["tenantAuditRetentionPruneCapabilities", 213],
  ["platformAuditRetentionAnchor", 213],
  ["tenantSettings", 214],
  ["tenantSettingsOwnerRole", 214],
  ["platformGlobalSettings", 216],
  ["platformFeatureFlags", 216],
  ["platformOperationsOwnerRole", 216],
  ["alertCaseLinkRetractions", 217],
]);

rmSync(stagedSchemaRoot, { force: true, recursive: true });
cpSync(schemaRoot, stagedSchemaRoot, { recursive: true });

function replaceOnce(fileName, before, after) {
  const path = resolve(stagedSchemaRoot, fileName);
  const source = readFileSync(path, "utf8");
  const first = source.indexOf(before);
  if (first === -1 || source.indexOf(before, first + before.length) !== -1) {
    throw new Error(`Expected one staged schema marker in ${fileName}`);
  }
  writeFileSync(path, source.replace(before, after));
}

if (stage < 211) {
  replaceOnce(
    "identity-platform-federation.ts",
    "sql`${table.kind} in ('ldap', 'oidc', 'saml')`",
    "sql`${table.kind} in ('oidc', 'saml')`",
  );
  replaceOnce(
    "identity-platform-federation.ts",
    "sql`${table.providerKind} in ('ldap', 'oidc', 'saml')`",
    "sql`${table.providerKind} in ('oidc', 'saml')`",
  );
}

if (stage < 212) {
  replaceOnce(
    "identity.ts",
    '    lifecycleRevision: integer("lifecycle_revision").notNull().default(1),\n',
    "",
  );
  replaceOnce(
    "identity.ts",
    '    check(\n      "tenant_memberships_lifecycle_revision_check",\n      sql`${table.lifecycleRevision} between 1 and 2147483647`,\n    ),\n',
    "",
  );
}

if (stage < 215) {
  replaceOnce(
    "operator-teams.ts",
    "sql`${table.operation} in ('operator_team.create', 'platform.tenant_access.authorize')`",
    "sql`${table.operation} = 'operator_team.create'`",
  );
}

if (stage < 217) {
  replaceOnce(
    "ticketing.ts",
    '    unique("alert_case_links_identity_key").on(\n      table.tenantId,\n      table.id,\n      table.alertId,\n      table.caseId,\n    ),\n',
    "",
  );
}

const seen = new Set();
const exportsByModule = [];
for (const fileName of readdirSync(stagedSchemaRoot).toSorted()) {
  if (
    !fileName.endsWith(".ts") ||
    fileName === "index.ts" ||
    fileName === "relations.ts"
  ) {
    continue;
  }

  const source = readFileSync(resolve(stagedSchemaRoot, fileName), "utf8");
  const names = [
    ...source.matchAll(/^export const ([A-Za-z][A-Za-z0-9]*)\s*=/gm),
  ]
    .map((match) => match[1])
    .filter((name) => {
      const introduction = introducedAt.get(name);
      if (introduction !== undefined) {
        seen.add(name);
      }
      return introduction === undefined || introduction <= stage;
    });
  if (names.length !== 0) {
    exportsByModule.push({ fileName, names });
  }
}

const missing = [...introducedAt.keys()].filter((name) => !seen.has(name));
if (missing.length !== 0) {
  throw new Error(
    `V48 snapshot symbols are missing from the canonical schema: ${missing.join(", ")}`,
  );
}

const lines = [
  "// Generated staging entry for the V48 Drizzle snapshot chain.",
  `// Stage: ${stage}. Do not commit this temporary file.`,
];
for (const { fileName, names } of exportsByModule) {
  lines.push(
    `export { ${names.join(", ")} } from "./.v48-snapshot-work/stage-schema/${basename(fileName, ".ts")}.js";`,
  );
}
lines.push("");
writeFileSync(outputPath, lines.join("\n"));

process.stdout.write(
  `Wrote ${outputPath} for stage ${stage} with ${exportsByModule.reduce((count, entry) => count + entry.names.length, 0)} exports.\n`,
);
