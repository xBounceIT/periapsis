import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const openapiSource = readFileSync(
  resolve(repositoryRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

const minimumGetPaths = [
  "/api/v1/platform/tenants",
  "/api/v1/platform/users",
  "/api/v1/platform/providers",
  "/api/v1/platform/audit",
  "/api/v1/tenants/{tenantId}",
  "/api/v1/tenants/{tenantId}/users",
  "/api/v1/tenants/{tenantId}/contacts",
  "/api/v1/tenants/{tenantId}/groups",
  "/api/v1/tenants/{tenantId}/operator-teams",
  "/api/v1/tenants/{tenantId}/roles",
  "/api/v1/tenants/{tenantId}/permissions",
  "/api/v1/tenants/{tenantId}/auth-providers",
  "/api/v1/tenants/{tenantId}/ldap-mappings",
  "/api/v1/tenants/{tenantId}/alerts",
  "/api/v1/tenants/{tenantId}/cases",
  "/api/v1/tenants/{tenantId}/workflows",
  "/api/v1/tenants/{tenantId}/custom-fields",
  "/api/v1/tenants/{tenantId}/sla-policies",
  "/api/v1/tenants/{tenantId}/business-calendars",
  "/api/v1/tenants/{tenantId}/notification-rules",
  "/api/v1/tenants/{tenantId}/notification-templates",
  "/api/v1/tenants/{tenantId}/webhooks",
  "/api/v1/tenants/{tenantId}/audit-events",
];

const requiredExplicitActions = [
  ["/api/v1/tenants/{tenantId}/alerts/{alertId}/link", "post"],
  ["/api/v1/tenants/{tenantId}/alerts/{alertId}/unlink", "post"],
];

const sourceLines = openapiSource.split(/\r?\n/);
const pathsStart = sourceLines.findIndex((line) => /^paths:\s*$/.test(line));
if (pathsStart === -1) {
  throw new Error(
    "Minimum endpoint contract invariant failed: canonical paths block is missing",
  );
}

const operationsByPath = new Map();
let currentPath;

for (const line of sourceLines.slice(pathsStart + 1)) {
  if (/^\S/.test(line)) break;

  const pathMatch = /^ {2}(?:"([^"]+)"|'([^']+)'|(\/[^:]+)):\s*$/.exec(line);
  if (pathMatch !== null) {
    currentPath = pathMatch[1] ?? pathMatch[2] ?? pathMatch[3];
    operationsByPath.set(currentPath, new Set());
    continue;
  }

  if (/^ {2}\S/.test(line)) currentPath = undefined;

  const operationMatch =
    /^ {4}(get|put|post|delete|options|head|patch|trace):\s*$/.exec(line);
  if (currentPath !== undefined && operationMatch !== null) {
    operationsByPath.get(currentPath).add(operationMatch[1]);
  }
}

const missingOperations = minimumGetPaths
  .filter((path) => !operationsByPath.get(path)?.has("get"))
  .map((path) => `GET ${path}`);

for (const [path, method] of requiredExplicitActions) {
  if (!operationsByPath.get(path)?.has(method)) {
    missingOperations.push(`${method.toUpperCase()} ${path}`);
  }
}

if (missingOperations.length > 0) {
  throw new Error(
    `Minimum endpoint contract invariant failed; missing exact operations:\n${missingOperations.join("\n")}`,
  );
}
