import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);

const fail = (message) => {
  throw new Error(`Tenant authorization contract invariant failed: ${message}`);
};

const assert = (condition, message) => {
  if (!condition) fail(message);
};

const operation = (path, method) => {
  const value = document.paths?.[path]?.[method];
  assert(value !== undefined, `${method.toUpperCase()} ${path} is missing`);
  return value;
};

const parameterRefs = (value) =>
  new Set((value.parameters ?? []).map((parameter) => parameter.$ref));

const securityNames = (value) =>
  new Set(Object.keys(value.security?.[0] ?? {}));

const exactValues = (actual, expected, message) => {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: received ${JSON.stringify(actual)}`,
  );
};

const conditionalFragmentMatches = (schema, value) => {
  if (schema === undefined) return true;
  if (
    schema.allOf?.some((branch) => !conditionalFragmentMatches(branch, value))
  ) {
    return false;
  }
  if (
    schema.anyOf !== undefined &&
    !schema.anyOf.some((branch) => conditionalFragmentMatches(branch, value))
  ) {
    return false;
  }
  if (
    schema.not !== undefined &&
    conditionalFragmentMatches(schema.not, value)
  ) {
    return false;
  }
  if (schema.const !== undefined && schema.const !== value) return false;
  if (schema.enum !== undefined && !schema.enum.includes(value)) return false;
  if (schema.if !== undefined) {
    const branch = conditionalFragmentMatches(schema.if, value)
      ? schema.then
      : schema.else;
    if (!conditionalFragmentMatches(branch, value)) return false;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    if (schema.required?.some((property) => !Object.hasOwn(value, property))) {
      return false;
    }
    for (const [property, propertySchema] of Object.entries(
      schema.properties ?? {},
    )) {
      if (
        Object.hasOwn(value, property) &&
        !conditionalFragmentMatches(propertySchema, value[property])
      ) {
        return false;
      }
    }
  }
  return true;
};

const acceptsConditionalRepresentation = (schema, value) =>
  (schema.allOf ?? []).every((rule) => conditionalFragmentMatches(rule, value));

const referencedSchema = (reference) => {
  const prefix = "#/components/schemas/";
  assert(
    reference.startsWith(prefix),
    `unsupported local schema reference ${reference}`,
  );
  const schemaName = reference.slice(prefix.length);
  const schema = document.components.schemas[schemaName];
  assert(schema !== undefined, `referenced schema ${schemaName} is missing`);
  return schema;
};

const schemaMatchesRepresentation = (schema, value) => {
  if (schema.$ref !== undefined) {
    if (!schemaMatchesRepresentation(referencedSchema(schema.$ref), value)) {
      return false;
    }
  }
  if (
    schema.allOf?.some((branch) => !schemaMatchesRepresentation(branch, value))
  ) {
    return false;
  }
  if (
    schema.anyOf !== undefined &&
    !schema.anyOf.some((branch) => schemaMatchesRepresentation(branch, value))
  ) {
    return false;
  }
  if (
    schema.oneOf !== undefined &&
    schema.oneOf.filter((branch) => schemaMatchesRepresentation(branch, value))
      .length !== 1
  ) {
    return false;
  }
  if (
    schema.not !== undefined &&
    schemaMatchesRepresentation(schema.not, value)
  ) {
    return false;
  }
  if (schema.const !== undefined && schema.const !== value) return false;
  if (schema.enum !== undefined && !schema.enum.includes(value)) return false;
  if (schema.type === "object" && !isObject(value)) return false;
  if (schema.type === "array" && !Array.isArray(value)) return false;
  if (schema.type === "string" && typeof value !== "string") return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (
    schema.type === "integer" &&
    (!Number.isInteger(value) || !Number.isFinite(value))
  ) {
    return false;
  }
  if (schema.type === "number" && !Number.isFinite(value)) return false;
  if (schema.if !== undefined) {
    const branch = schemaMatchesRepresentation(schema.if, value)
      ? schema.then
      : schema.else;
    if (branch !== undefined && !schemaMatchesRepresentation(branch, value)) {
      return false;
    }
  }
  if (isObject(value)) {
    const properties = schema.properties ?? {};
    if (schema.required?.some((property) => !Object.hasOwn(value, property))) {
      return false;
    }
    for (const [property, propertyValue] of Object.entries(value)) {
      const propertySchema = properties[property];
      if (
        propertySchema !== undefined &&
        !schemaMatchesRepresentation(propertySchema, propertyValue)
      ) {
        return false;
      }
      if (
        propertySchema === undefined &&
        schema.additionalProperties === false
      ) {
        return false;
      }
    }
  }
  return true;
};

const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const permissionKeys = [
  "permission.read",
  "role.read",
  "role.manage",
  "role.grant",
  "user.read",
  "membership.manage",
  "group.read",
  "group.manage",
  "group.membership.manage",
  "operator_team.read",
  "operator_team.manage",
  "operator_team.roster.manage",
  "service_account.read",
  "service_account.manage",
  "service_account.credential.manage",
  "identity_provider.read",
  "identity_provider.manage",
  "identity_provider.test",
  "identity_mapping.read",
  "identity_mapping.manage",
  "identity_sync.run",
  "identity_policy.read",
  "identity_policy.manage",
  "settings.read",
  "settings.manage",
  "audit.read",
  "audit.export",
  "audit.retention.manage",
  "sla.read",
  "sla.manage",
  "sla.simulate",
  "workflow.read",
  "workflow.manage",
  "alert.create",
  "alert.read",
  "alert.activity.read",
  "alert.comment.read",
  "alert.link.read",
  "alert.update",
  "alert.delete",
  "alert.assign",
  "alert.claim",
  "alert.escalate",
  "alert.sla.override",
  "alert.comment.public",
  "alert.comment.private",
  "case.create",
  "case.read",
  "case.activity.read",
  "case.comment.read",
  "case.link.read",
  "case.update",
  "case.claim",
  "case.transfer",
  "case.transition",
  "case.sla.override",
  "case.comment.public",
  "case.comment.private",
  "custom_field.read",
  "custom_field.manage",
  "dfir.ioc.read",
  "dfir.ioc.manage",
  "dfir.asset.read",
  "dfir.asset.manage",
  "dfir.evidence.read",
  "dfir.evidence.manage",
  "dfir.timeline.read",
  "dfir.timeline.manage",
  "dfir.task.read",
  "dfir.task.manage",
  "dfir.attachment.read",
  "dfir.attachment.manage",
  "dfir.relationship.read",
  "dfir.relationship.manage",
  "contact.read",
  "contact.manage",
  "contact.preference.manage",
  "contact_group.read",
  "contact_group.manage",
  "portal.alert.read",
  "portal.case.read",
  "portal.comment.public",
  "portal.attachment.read",
  "portal.contact.preference.manage",
  "notification.manage",
];
const tenantScopes = ["own", "assigned", "operator_team", "tenant"];
const platformPermissionKeys = [
  "platform.tenant.read",
  "platform.tenant.create",
  "platform.tenant.manage",
  "platform.tenant.access",
  "platform.operator_team.read",
  "platform.operator_team.manage",
  "platform.identity_provider.read",
  "platform.identity_provider.manage",
  "platform.identity_provider.test",
  "platform.identity_binding.read",
  "platform.identity_binding.manage",
  "platform.identity_policy.read",
  "platform.identity_policy.manage",
  "platform.identity_account.read",
  "platform.identity_account.manage",
  "platform.notification.manage",
  "platform.audit.read",
  "platform.audit.export",
  "platform.audit.retention.manage",
  "platform.user.read",
  "platform.operations.read",
  "platform.settings.read",
  "platform.settings.manage",
  "platform.feature_flag.read",
  "platform.feature_flag.manage",
];

exactValues(
  document.components.schemas.TenantPermissionKey.enum,
  permissionKeys,
  "tenant permission keys must be the exact accepted tenant set",
);
exactValues(
  document.components.schemas.TenantPrincipalType.enum,
  ["human", "service_account"],
  "tenant principal types must separate humans and service accounts",
);
exactValues(
  document.components.schemas.PlatformPermission.enum,
  platformPermissionKeys,
  "platform permission keys must be the exact accepted platform set",
);
exactValues(
  document.components.schemas.TenantAuthorizationScope.enum,
  tenantScopes,
  "tenant authorization scopes must be exact and must exclude platform",
);
assert(
  document.components.schemas.Session.properties.permissions.items.$ref ===
    "#/components/schemas/PlatformPermission",
  "Session.permissions must remain platform-only",
);
exactValues(
  document.components.schemas.TenantUserSummary.properties.membershipStatus
    .enum,
  ["invited", "active", "suspended"],
  "tenant user membership lifecycle must preserve invited users",
);

const operations = [
  [
    "/api/v1/tenants/{tenantId}/me/authority",
    "get",
    "getTenantAuthority",
    undefined,
  ],
  [
    "/api/v1/tenants/{tenantId}/permissions",
    "get",
    "listTenantPermissions",
    "permission.read",
  ],
  ["/api/v1/tenants/{tenantId}/roles", "get", "listTenantRoles", "role.read"],
  [
    "/api/v1/tenants/{tenantId}/roles",
    "post",
    "createTenantRole",
    "role.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/roles/{roleId}",
    "get",
    "getTenantRole",
    "role.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/roles/{roleId}",
    "patch",
    "updateTenantRole",
    "role.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/roles/{roleId}",
    "delete",
    "archiveTenantRole",
    "role.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/roles/{roleId}/policy",
    "put",
    "replaceTenantRolePolicy",
    "role.manage",
  ],
  ["/api/v1/tenants/{tenantId}/users", "get", "listTenantUsers", "user.read"],
  [
    "/api/v1/tenants/{tenantId}/users/{userId}/role-grants",
    "get",
    "listUserRoleGrants",
    "role.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/users/{userId}/role-grants",
    "post",
    "grantUserRole",
    "role.grant",
  ],
  [
    "/api/v1/tenants/{tenantId}/role-grants/{grantId}/revoke",
    "post",
    "revokeRoleGrant",
    "role.grant",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups",
    "get",
    "listTenantSecurityGroups",
    "group.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups",
    "post",
    "createTenantSecurityGroup",
    "group.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}",
    "get",
    "getTenantSecurityGroup",
    "group.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}",
    "patch",
    "updateTenantSecurityGroup",
    "group.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}",
    "delete",
    "archiveTenantSecurityGroup",
    "group.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships",
    "get",
    "listTenantSecurityGroupMemberships",
    "group.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships",
    "post",
    "createTenantSecurityGroupMembership",
    "group.membership.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships/{membershipId}/revoke",
    "post",
    "revokeTenantSecurityGroupMembership",
    "group.membership.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants",
    "get",
    "listTenantSecurityGroupRoleGrants",
    "group.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants",
    "post",
    "grantTenantSecurityGroupRole",
    "group.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants/{grantId}/revoke",
    "post",
    "revokeTenantSecurityGroupRoleGrant",
    "group.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers",
    "get",
    "listTenantLDAPAuthProviders",
    "identity_provider.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers",
    "post",
    "createTenantLDAPAuthProvider",
    "identity_provider.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}",
    "get",
    "getTenantLDAPAuthProvider",
    "identity_provider.read",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}",
    "put",
    "updateTenantLDAPAuthProvider",
    "identity_provider.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}",
    "delete",
    "archiveTenantLDAPAuthProvider",
    "identity_provider.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}/bind-secret",
    "put",
    "setTenantLDAPAuthProviderBindSecret",
    "identity_provider.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}/bind-secret",
    "delete",
    "clearTenantLDAPAuthProviderBindSecret",
    "identity_provider.manage",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}/tests/connection",
    "post",
    "testTenantLDAPAuthProviderConnection",
    "identity_provider.test",
  ],
  [
    "/api/v1/tenants/{tenantId}/auth-providers/{providerId}/tests/bind",
    "post",
    "testTenantLDAPAuthProviderBind",
    "identity_provider.test",
  ],
];

for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
  for (const method of [
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
  ]) {
    const value = pathItem?.[method];
    if (value === undefined || !securityNames(value).has("sessionCookie")) {
      continue;
    }
    const authorization = value["x-periapsis-authorization"];
    assert(
      authorization !== undefined,
      `${value.operationId ?? `${method.toUpperCase()} ${path}`} lacks authorization metadata`,
    );
    const acceptsServiceAccounts = (value.security ?? []).some(
      (requirement) => requirement.serviceAccountBearer !== undefined,
    );
    exactValues(
      authorization.principalTypes,
      acceptsServiceAccounts ? ["human", "service_account"] : ["human"],
      `${value.operationId} principal types must match its authentication alternatives`,
    );
    assert(
      authorization.activeSession === true ||
        authorization.activeMembership === true,
      `${value.operationId} must require a live session or live membership`,
    );
    if (!["get", "head", "options"].includes(method)) {
      assert(
        securityNames(value).has("csrfToken"),
        `${value.operationId} must require CSRF with cookie authentication`,
      );
    }
  }
}

for (const [path, method, operationId, permission] of operations) {
  const value = operation(path, method);
  assert(
    value.operationId === operationId,
    `${operationId} operationId drifted`,
  );
  assert(
    securityNames(value).has("sessionCookie"),
    `${operationId} must require the session cookie`,
  );
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path",
    `${operationId} lacks path tenant context`,
  );
  assert(
    authorization?.activeMembership === true,
    `${operationId} lacks active membership`,
  );
  exactValues(
    authorization?.principalTypes,
    ["human"],
    `${operationId} principal type must be human-only`,
  );
  if (permission === undefined) {
    assert(
      authorization.permission === undefined,
      `${operationId} must not require a tenant permission beyond active membership`,
    );
  } else {
    assert(
      authorization.permission === permission,
      `${operationId} must require ${permission}`,
    );
    exactValues(
      authorization.scopes,
      ["tenant"],
      `${operationId} must require exact tenant scope`,
    );
  }
}

const platformOperatorTeamsPath = "/api/v1/platform/operator-teams";
const platformOperatorTeamPath =
  "/api/v1/platform/operator-teams/{operatorTeamId}";
const tenantOperatorTeamsPath = "/api/v1/tenants/{tenantId}/operator-teams";
const assignmentEpochsPath = `${tenantOperatorTeamsPath}/{operatorTeamId}/assignment-epochs`;
const assignmentEpochPath = `${assignmentEpochsPath}/{assignmentEpochId}`;
const assignmentEndPath = `${assignmentEpochPath}/end`;
const operatorTeamRosterPath = `${assignmentEpochPath}/roster`;
const operatorTeamRosterRevokePath = `${operatorTeamRosterPath}/{rosterEntryId}/revoke`;

const platformOperatorTeamOperations = [
  [
    platformOperatorTeamsPath,
    "get",
    "listPlatformOperatorTeams",
    "platform.operator_team.read",
  ],
  [
    platformOperatorTeamsPath,
    "post",
    "createPlatformOperatorTeam",
    "platform.operator_team.manage",
  ],
  [
    platformOperatorTeamPath,
    "get",
    "getPlatformOperatorTeam",
    "platform.operator_team.read",
  ],
  [
    platformOperatorTeamPath,
    "patch",
    "updatePlatformOperatorTeam",
    "platform.operator_team.manage",
  ],
  [
    platformOperatorTeamPath,
    "delete",
    "archivePlatformOperatorTeam",
    "platform.operator_team.manage",
  ],
];
for (const [
  path,
  method,
  operationId,
  permission,
] of platformOperatorTeamOperations) {
  const value = operation(path, method);
  assert(
    value.operationId === operationId,
    `${operationId} operationId drifted`,
  );
  const authorization = value["x-periapsis-authorization"];
  assert(
    securityNames(value).has("sessionCookie") &&
      authorization?.activeSession === true &&
      authorization.activeMembership === undefined &&
      authorization.tenantContext === undefined &&
      authorization.permission === permission,
    `${operationId} must enforce exact platform session authority`,
  );
  exactValues(
    authorization.scopes,
    ["platform"],
    `${operationId} must require exact platform scope`,
  );
}

const tenantOperatorTeamOperations = [
  [
    tenantOperatorTeamsPath,
    "get",
    "listTenantOperatorTeamAssignmentEpochs",
    "operator_team.read",
    ["tenant"],
  ],
  [
    assignmentEpochsPath,
    "post",
    "startOperatorTeamAssignmentEpoch",
    "operator_team.manage",
    ["tenant"],
  ],
  [
    assignmentEpochPath,
    "get",
    "getOperatorTeamAssignmentEpoch",
    "operator_team.read",
    ["operator_team", "tenant"],
  ],
  [
    assignmentEndPath,
    "post",
    "endOperatorTeamAssignmentEpoch",
    "operator_team.manage",
    ["tenant"],
  ],
  [
    operatorTeamRosterPath,
    "get",
    "listOperatorTeamRosterEntries",
    "operator_team.read",
    ["operator_team", "tenant"],
  ],
  [
    operatorTeamRosterPath,
    "post",
    "addOperatorTeamRosterEntry",
    "operator_team.roster.manage",
    ["operator_team", "tenant"],
  ],
  [
    operatorTeamRosterRevokePath,
    "post",
    "revokeOperatorTeamRosterEntry",
    "operator_team.roster.manage",
    ["operator_team", "tenant"],
  ],
];
for (const [
  path,
  method,
  operationId,
  permission,
  scopes,
] of tenantOperatorTeamOperations) {
  const value = operation(path, method);
  assert(
    value.operationId === operationId,
    `${operationId} operationId drifted`,
  );
  const authorization = value["x-periapsis-authorization"];
  assert(
    securityNames(value).has("sessionCookie") &&
      authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === permission,
    `${operationId} must enforce exact tenant operator-team authority`,
  );
  exactValues(
    authorization.scopes,
    scopes,
    `${operationId} operator-team scope set drifted`,
  );
}

for (const [path, method, additionalPermissions] of [
  [assignmentEndPath, "post", ["role.grant"]],
  [operatorTeamRosterPath, "get", ["user.read"]],
  [operatorTeamRosterPath, "post", ["role.grant"]],
  [operatorTeamRosterRevokePath, "post", ["role.grant"]],
]) {
  exactValues(
    operation(path, method)["x-periapsis-authorization"].additionalPermissions,
    additionalPermissions,
    `${method.toUpperCase()} ${path} additional permissions drifted`,
  );
}

const operatorTeamContractOperations = [
  ...platformOperatorTeamOperations.map(([path, method]) =>
    operation(path, method),
  ),
  ...tenantOperatorTeamOperations.map(([path, method]) =>
    operation(path, method),
  ),
];
for (const value of operatorTeamContractOperations) {
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) < 400) continue;
    const resolved = response.$ref?.startsWith("#/components/responses/")
      ? document.components.responses[response.$ref.split("/").at(-1)]
      : response;
    assert(
      resolved?.content?.["application/problem+json"]?.schema?.$ref ===
        "#/components/schemas/Problem",
      `${value.operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
}
assert(
  operation(platformOperatorTeamPath, "delete")
    .responses["409"].description.toLowerCase()
    .includes("active tenant assignment epoch"),
  "operator-team archive conflict must name the active-assignment invariant",
);

const operatorTeamMutations = [
  operation(platformOperatorTeamsPath, "post"),
  operation(platformOperatorTeamPath, "patch"),
  operation(platformOperatorTeamPath, "delete"),
  operation(assignmentEpochsPath, "post"),
  operation(assignmentEndPath, "post"),
  operation(operatorTeamRosterPath, "post"),
  operation(operatorTeamRosterRevokePath, "post"),
];
for (const value of operatorTeamMutations) {
  assert(
    securityNames(value).has("csrfToken"),
    `${value.operationId} must require CSRF with cookie authentication`,
  );
}
for (const value of [
  operatorTeamMutations[0],
  operatorTeamMutations[3],
  operatorTeamMutations[5],
]) {
  assert(
    parameterRefs(value).has("#/components/parameters/IdempotencyKey"),
    `${value.operationId} must require Idempotency-Key`,
  );
  const description = value.responses["201"]?.description ?? "";
  assert(
    description.includes("same resource's current representation") &&
      description.includes("current strong ETag") &&
      description.includes("never undoes later mutations"),
    `${value.operationId} must specify exact non-restorative replay semantics`,
  );
}
for (const value of [
  operatorTeamMutations[1],
  operatorTeamMutations[2],
  operatorTeamMutations[4],
]) {
  assert(
    parameterRefs(value).has("#/components/parameters/IfMatch") &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must require strong If-Match with 412 and 428`,
  );
}
assert(
  parameterRefs(operatorTeamMutations[6]).has(
    "#/components/parameters/EdgeIfMatch",
  ) &&
    operatorTeamMutations[6].responses["412"] !== undefined &&
    operatorTeamMutations[6].responses["428"] !== undefined,
  "revokeOperatorTeamRosterEntry must require representation-bound edge If-Match",
);
for (const [value, expectedHeader] of [
  [operation(platformOperatorTeamsPath, "post"), "StrongETag"],
  [operation(platformOperatorTeamPath, "get"), "StrongETag"],
  [operation(platformOperatorTeamPath, "patch"), "StrongETag"],
  [operation(assignmentEpochsPath, "post"), "StrongETag"],
  [operation(assignmentEpochPath, "get"), "StrongETag"],
  [operation(operatorTeamRosterPath, "post"), "EdgeStrongETag"],
]) {
  assert(
    value.responses[Object.hasOwn(value.responses, "201") ? "201" : "200"]
      .headers.ETag.$ref === `#/components/headers/${expectedHeader}`,
    `${value.operationId} must return ${expectedHeader}`,
  );
}

for (const rosterPath of [
  operatorTeamRosterPath,
  operatorTeamRosterRevokePath,
]) {
  assert(
    rosterPath.includes("/{assignmentEpochId}/roster"),
    `${rosterPath} must carry the exact assignment epoch in the path`,
  );
}

for (const [schemaName, properties, required] of [
  [
    "OperatorTeamCreateRequest",
    ["key", "name", "description"],
    ["key", "name"],
  ],
  ["OperatorTeamPatchRequest", ["name", "description"], []],
  ["OperatorTeamArchiveRequest", ["reason"], ["reason"]],
  ["OperatorTeamAssignmentEpochStartRequest", ["reason"], ["reason"]],
  ["OperatorTeamAssignmentEpochEndRequest", ["reason"], ["reason"]],
  [
    "OperatorTeamRosterEntryCreateRequest",
    ["membershipId", "reason", "expiresAt"],
    ["membershipId", "reason"],
  ],
]) {
  const schema = document.components.schemas[schemaName];
  assert(
    schema.additionalProperties === false,
    `${schemaName} must reject mass assignment`,
  );
  exactValues(
    Object.keys(schema.properties),
    properties,
    `${schemaName} writable fields drifted`,
  );
  exactValues(
    schema.required ?? [],
    required,
    `${schemaName} required fields drifted`,
  );
  for (const forbidden of [
    "id",
    "tenantId",
    "operatorTeamId",
    "assignmentEpochId",
    "state",
    "version",
    "createdAt",
    "updatedAt",
    "archivedAt",
    "endedAt",
    "revokedAt",
    "provenance",
  ]) {
    assert(
      schema.properties[forbidden] === undefined,
      `${schemaName} must not accept server-owned ${forbidden}`,
    );
  }
}
assert(
  operation(platformOperatorTeamPath, "delete").requestBody?.required ===
    true &&
    operation(platformOperatorTeamPath, "delete").requestBody.content[
      "application/json"
    ].schema.$ref === "#/components/schemas/OperatorTeamArchiveRequest",
  "archivePlatformOperatorTeam must require an audited reason body",
);

const authority = operation("/api/v1/tenants/{tenantId}/me/authority", "get");
assert(
  authority.responses["200"].headers["Cache-Control"].$ref ===
    "#/components/headers/NoStore",
  "authority projection must emit Cache-Control: no-store",
);
assert(
  document.components.headers.NoStore.schema.const === "no-store",
  "NoStore response header must be fixed to no-store",
);

const mutations = [
  operation("/api/v1/tenants/{tenantId}/roles", "post"),
  operation("/api/v1/tenants/{tenantId}/roles/{roleId}", "patch"),
  operation("/api/v1/tenants/{tenantId}/roles/{roleId}", "delete"),
  operation("/api/v1/tenants/{tenantId}/roles/{roleId}/policy", "put"),
  operation("/api/v1/tenants/{tenantId}/users/{userId}/role-grants", "post"),
  operation("/api/v1/tenants/{tenantId}/role-grants/{grantId}/revoke", "post"),
  operation("/api/v1/tenants/{tenantId}/groups", "post"),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}", "patch"),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}", "delete"),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}/memberships", "post"),
  operation(
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships/{membershipId}/revoke",
    "post",
  ),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants", "post"),
  operation(
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants/{grantId}/revoke",
    "post",
  ),
];
for (const value of mutations) {
  assert(
    securityNames(value).has("csrfToken"),
    `${value.operationId} must require CSRF with cookie authentication`,
  );
}

const idempotentCreates = [
  mutations[0],
  mutations[4],
  mutations[6],
  mutations[9],
  mutations[11],
];
for (const value of idempotentCreates) {
  assert(
    parameterRefs(value).has("#/components/parameters/IdempotencyKey"),
    `${value.operationId} must require Idempotency-Key`,
  );
  const createdDescription = value.responses["201"]?.description ?? "";
  assert(
    createdDescription.includes("same resource's current representation") &&
      createdDescription.includes("current strong ETag") &&
      createdDescription.includes("never undoes later mutations"),
    `${value.operationId} must describe non-restorative current-resource replay semantics`,
  );
}
const idempotencyDescription =
  document.components.parameters.IdempotencyKey.description ?? "";
const normalizedIdempotencyDescription = idempotencyDescription.replace(
  /\s+/gu,
  " ",
);
assert(
  normalizedIdempotencyDescription.includes(
    "same resource's current representation",
  ) &&
    normalizedIdempotencyDescription.includes("current strong ETag") &&
    normalizedIdempotencyDescription.includes(
      "without undoing later mutations",
    ) &&
    normalizedIdempotencyDescription.includes(
      "one-time credential issue or rotation replay instead returns 409",
    ) &&
    normalizedIdempotencyDescription.includes("without the bearer token") &&
    normalizedIdempotencyDescription.includes(
      "retention window documented by that operation",
    ) &&
    normalizedIdempotencyDescription.includes(
      "does not promise indefinite replay",
    ),
  "Idempotency-Key must distinguish non-secret replay from one-time-secret replay",
);

for (const value of [
  mutations[1],
  mutations[2],
  mutations[3],
  mutations[7],
  mutations[8],
]) {
  assert(
    parameterRefs(value).has("#/components/parameters/IfMatch"),
    `${value.operationId} must require strong If-Match`,
  );
  assert(
    value.responses["412"] !== undefined,
    `${value.operationId} must describe 412`,
  );
  assert(
    value.responses["428"] !== undefined,
    `${value.operationId} must describe 428`,
  );
}

for (const value of [mutations[5], mutations[10], mutations[12]]) {
  assert(
    parameterRefs(value).has("#/components/parameters/EdgeIfMatch"),
    `${value.operationId} must require representation-bound authorization-edge If-Match`,
  );
  assert(
    value.responses["412"] !== undefined,
    `${value.operationId} must describe 412`,
  );
  assert(
    value.responses["428"] !== undefined,
    `${value.operationId} must describe 428`,
  );
}

assert(
  document.components.parameters.IfMatch.schema.$ref ===
    "#/components/schemas/StrongEntityTag",
  "If-Match must use the strong entity-tag schema",
);
assert(
  !document.components.schemas.StrongEntityTag.pattern.startsWith("W/"),
  "weak entity tags must not be accepted",
);
const boundedResourceVersionPattern =
  "(?:[1-9][0-9]{0,8}|1[0-9]{9}|20[0-9]{8}|21[0-3][0-9]{7}|214[0-6][0-9]{6}|2147[0-3][0-9]{5}|21474[0-7][0-9]{4}|214748[0-2][0-9]{3}|2147483[0-5][0-9]{2}|21474836[0-3][0-9]|214748364[0-7])";
exactValues(
  document.components.schemas.StrongEntityTag.pattern,
  `^"v${boundedResourceVersionPattern}"$`,
  "resource entity tags must bind the exact positive PostgreSQL int4 range",
);
exactValues(
  document.components.schemas.EdgeStrongEntityTag.pattern,
  `^"v${boundedResourceVersionPattern}-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"$`,
  "authorization-edge entity tags must bind the bounded version and a canonical representation digest",
);
assert(
  document.components.schemas.ResourceVersion.description.includes(
    "numeric prefix in strong validators",
  ),
  "resource versions must describe both version-only and composite validator usage",
);
assert(
  document.components.parameters.EdgeIfMatch.schema.$ref ===
    "#/components/schemas/EdgeStrongEntityTag",
  "authorization-edge If-Match must use the representation-bound entity-tag schema",
);

for (const mutationIndex of [4, 9, 11]) {
  assert(
    mutations[mutationIndex].responses["201"].headers.ETag.$ref ===
      "#/components/headers/EdgeStrongETag",
    `${mutations[mutationIndex].operationId} must return a representation-bound edge ETag`,
  );
}

for (const [path, label] of [
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships/{membershipId}/revoke",
    "group membership",
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants/{grantId}/revoke",
    "group role grant",
  ],
  [
    "/api/v1/tenants/{tenantId}/role-grants/{grantId}/revoke",
    "direct role grant",
  ],
]) {
  const revoke = operation(path, "post");
  assert(
    revoke.summary.includes("authorization-API-managed") &&
      revoke.description.includes("managedByAuthorizationApi") &&
      revoke.description.toLowerCase().includes("source kind alone"),
    `${label} revocation must document its exact server-derived ownership boundary`,
  );
}
const directGrantPathDescription =
  document.components.schemas.DirectUserRoleGrant.properties.pathType
    .description;
assert(
  directGrantPathDescription.includes("managedByAuthorizationApi") &&
    directGrantPathDescription.includes("other than revoked"),
  "direct role-grant path metadata must not infer ownership from its path or provenance",
);

for (const schemaName of [
  "DirectUserRoleGrant",
  "TenantSecurityGroupMembership",
  "TenantSecurityGroupRoleGrant",
]) {
  const schema = document.components.schemas[schemaName];
  assert(
    schema.required.includes("etag") &&
      schema.properties.etag?.$ref ===
        "#/components/schemas/EdgeStrongEntityTag",
    `${schemaName} must carry its required representation-bound ETag in every detail and list projection`,
  );
  const ownership = schema.properties.managedByAuthorizationApi;
  assert(
    ownership?.type === "boolean" &&
      !schema.required.includes("managedByAuthorizationApi") &&
      ownership.description.includes("treat omission as false") &&
      ownership.description.includes("never infer ownership from sourceKind"),
    `${schemaName} must expose fail-closed optional server-derived mutation ownership`,
  );
}
assert(
  document.components.schemas.EdgeStrongEntityTag.description.includes(
    "managedByAuthorizationApi compatibility hint",
  ),
  "edge validators must deliberately preserve rolling stability across the optional ownership hint",
);

for (const schemaName of [
  "TenantRole",
  "TenantRoleSummary",
  "DirectUserRoleGrant",
]) {
  const schema = document.components.schemas[schemaName];
  assert(
    schema.required.includes("version"),
    `${schemaName} must expose version`,
  );
}
assert(
  document.components.schemas.TenantRolePolicy.required.includes(
    "permissions",
  ) &&
    document.components.schemas.TenantRolePolicy.required.includes(
      "delegationCeiling",
    ),
  "role policy replacement must include grants and delegation ceiling atomically",
);
assert(
  document.components.schemas.RoleGrantProvenance.properties.expiresAt !==
    undefined,
  "role grant provenance must expose optional expiry",
);
assert(
  document.components.schemas.RoleGrantProvenance.required.includes("reason"),
  "role grant provenance must expose the safe grant reason",
);
assert(
  document.components.schemas.DirectUserRoleGrantRequest.required.includes(
    "reason",
  ),
  "direct user role grants must require an audited reason",
);
const writableExpiryPattern =
  "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](?:\\.[0-9]{1,6}0*)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$";
for (const schemaName of [
  "DirectUserRoleGrantRequest",
  "TenantSecurityGroupMembershipCreateRequest",
  "TenantSecurityGroupRoleGrantRequest",
  "OperatorTeamRosterEntryCreateRequest",
]) {
  const schema = document.components.schemas[schemaName];
  const expiry = schema.properties.expiresAt;
  const expiryDescription = expiry?.description?.replace(/\s+/g, " ") ?? "";
  const expiryPattern = new RegExp(expiry?.pattern ?? "");
  assert(
    expiry?.type === "string" &&
      expiry.format === "date-time" &&
      expiry.pattern === writableExpiryPattern &&
      !schema.required.includes("expiresAt") &&
      expiryDescription.includes("microsecond precision") &&
      expiryDescription.includes("UTC-normalized year") &&
      expiryDescription.includes("outside 0000 through 9999") &&
      expiryDescription.includes("leap-second notation") &&
      expiryDescription.includes("explicit null is invalid"),
    `${schemaName} must expose an optional, non-null, microsecond-exact expiry`,
  );
  assert(
    expiryPattern.test("2026-08-24T16:30:00-23:59") &&
      expiryPattern.test("2026-08-24T16:30:00-00:00") &&
      !expiryPattern.test("2016-12-31T23:59:60Z"),
    `${schemaName} must accept bounded offsets, preserve -00:00, and exclude leap seconds`,
  );
}
assert(
  document.components.schemas.TenantAuthority.properties.delegationCeiling.items
    .$ref === "#/components/schemas/EffectiveTenantDelegation",
  "live authority must expose effective delegation expiry horizons",
);
assert(
  document.components.schemas.TenantAuthority.properties.roleGrants.maxItems ===
    200,
  "live authority must support every effective role path below the truncation sentinel",
);
const authorityOperatorTeamRelationships =
  document.components.schemas.TenantAuthority.properties
    .operatorTeamRelationships;
assert(
  document.components.schemas.TenantAuthority.required.includes(
    "operatorTeamRelationships",
  ) &&
    authorityOperatorTeamRelationships.maxItems === 200 &&
    authorityOperatorTeamRelationships.uniqueItems === true &&
    authorityOperatorTeamRelationships.items.$ref ===
      "#/components/schemas/TenantOperatorTeamRelationship",
  "live authority must expose bounded exact operator-team assignment relationships",
);
const tenantOperatorTeamRelationship =
  document.components.schemas.TenantOperatorTeamRelationship;
assert(
  tenantOperatorTeamRelationship.additionalProperties === false &&
    tenantOperatorTeamRelationship.required.length === 2 &&
    tenantOperatorTeamRelationship.required.includes("operatorTeamId") &&
    tenantOperatorTeamRelationship.required.includes("assignmentEpochId") &&
    tenantOperatorTeamRelationship.properties.operatorTeamId.format ===
      "uuid" &&
    tenantOperatorTeamRelationship.properties.assignmentEpochId.format ===
      "uuid",
  "operator-team authority relationships must remain exact team and assignment-epoch pairs",
);
assert(
  document.components.schemas.EffectiveTenantDelegation.properties
    .delegableUntil !== undefined,
  "effective delegation tuples must expose optional delegableUntil",
);
assert(
  document.components.schemas.RoleGrantRevokeRequest.required.includes(
    "reason",
  ),
  "grant revocation must require an audited reason",
);
assert(
  document.components.schemas.GrantReason.maxLength === 500,
  "grant and revocation reasons must remain bounded",
);
exactValues(
  document.components.schemas.GrantReason.pattern,
  "^(?=.*\\S)[^\\u0000-\\u001F\\u007F-\\u009F]+$",
  "administrative reasons must reject blank and control-character input",
);
const grantReasonPattern = new RegExp(
  document.components.schemas.GrantReason.pattern,
);
assert(
  grantReasonPattern.test("Planned rotation") &&
    !grantReasonPattern.test("   ") &&
    !grantReasonPattern.test("unsafe\u0001reason"),
  "administrative reason validation must accept text and reject blank/control input",
);

for (const [path, method, additional] of [
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships",
    "get",
    ["user.read"],
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships",
    "post",
    ["role.grant"],
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/memberships/{membershipId}/revoke",
    "post",
    ["role.grant"],
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants",
    "get",
    ["role.read"],
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants",
    "post",
    ["role.grant"],
  ],
  [
    "/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants/{grantId}/revoke",
    "post",
    ["role.grant"],
  ],
]) {
  exactValues(
    operation(path, method)["x-periapsis-authorization"].additionalPermissions,
    additional,
    `${method.toUpperCase()} ${path} additional permissions drifted`,
  );
}

const operatorTeamSchema = document.components.schemas.OperatorTeam;
for (const field of [
  "id",
  "key",
  "name",
  "description",
  "state",
  "activeAssignmentCount",
  "version",
  "createdAt",
  "updatedAt",
]) {
  assert(
    operatorTeamSchema.required.includes(field),
    `OperatorTeam must require ${field}`,
  );
}
const archivedTeamLifecycle = operatorTeamSchema.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "archived",
);
assert(
  archivedTeamLifecycle?.then?.required?.includes("archivedAt") &&
    archivedTeamLifecycle.then.properties.activeAssignmentCount.maximum === 0,
  "archived operator teams must expose archivedAt and have no active assignments",
);

const assignmentEpochSchema =
  document.components.schemas.OperatorTeamAssignmentEpoch;
for (const field of [
  "epochId",
  "tenantId",
  "operatorTeam",
  "state",
  "startedAt",
  "startedByUserId",
  "startReason",
  "version",
  "updatedAt",
]) {
  assert(
    assignmentEpochSchema.required.includes(field),
    `OperatorTeamAssignmentEpoch must require ${field}`,
  );
}
const endedEpochLifecycle = assignmentEpochSchema.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "ended",
);
assert(
  ["endedAt", "endedByUserId", "endReason"].every((field) =>
    endedEpochLifecycle?.then?.required?.includes(field),
  ),
  "ended assignment epochs must retain complete end history",
);
const forbiddenUntilEnded = new Set(
  endedEpochLifecycle?.else?.not?.anyOf?.flatMap(
    (rule) => rule.required ?? [],
  ) ?? [],
);
for (const field of ["endedAt", "endedByUserId", "endReason"]) {
  assert(
    forbiddenUntilEnded.has(field),
    `active assignment epochs must omit ${field}`,
  );
}
const activeEpochTeamLifecycle = assignmentEpochSchema.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "active",
);
assert(
  activeEpochTeamLifecycle?.then?.properties?.operatorTeam?.properties?.state
    ?.const === "active",
  "active assignment epochs must reference an active global operator team",
);
assert(
  acceptsConditionalRepresentation(assignmentEpochSchema, {
    operatorTeam: { state: "active" },
    state: "active",
  }) &&
    !acceptsConditionalRepresentation(assignmentEpochSchema, {
      operatorTeam: { state: "archived" },
      state: "active",
    }) &&
    acceptsConditionalRepresentation(assignmentEpochSchema, {
      endReason: "Rotation complete",
      endedAt: "now",
      endedByUserId: "actor-id",
      operatorTeam: { state: "archived" },
      state: "ended",
    }),
  "assignment-epoch lifecycle fixtures must reject active epochs for archived teams and preserve ended history",
);

const rosterEntrySchema = document.components.schemas.OperatorTeamRosterEntry;
for (const field of [
  "id",
  "tenantId",
  "operatorTeamId",
  "assignmentEpochId",
  "member",
  "provenance",
  "managedByOperatorTeamApi",
  "state",
  "etag",
  "version",
  "updatedAt",
]) {
  assert(
    rosterEntrySchema.required.includes(field),
    `OperatorTeamRosterEntry must require ${field}`,
  );
}
assert(
  rosterEntrySchema.properties.etag.$ref ===
    "#/components/schemas/EdgeStrongEntityTag" &&
    rosterEntrySchema.properties.managedByOperatorTeamApi.type === "boolean" &&
    rosterEntrySchema.properties.managedByOperatorTeamApi.description.includes(
      "never infer ownership from sourceKind",
    ),
  "operator-team roster edges must expose a representation ETag and explicit server-derived ownership",
);
const rosterRevocationLifecycle = rosterEntrySchema.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "revoked",
);
assert(
  ["revokedAt", "revokedByUserId", "revokeReason"].every((field) =>
    rosterRevocationLifecycle?.then?.required?.includes(field),
  ),
  "revoked roster edges must retain complete revocation history",
);
const rosterManualOwnership = rosterEntrySchema.allOf?.find(
  (rule) =>
    rule.if?.properties?.provenance?.properties?.sourceKind?.const === "manual",
);
assert(
  rosterManualOwnership?.then?.properties?.provenance?.required?.includes(
    "grantedByUserId",
  ),
  "manual roster edges must retain their human grantor",
);
const expiredRosterLifecycle = rosterEntrySchema.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "expired",
);
assert(
  expiredRosterLifecycle === undefined &&
    rosterEntrySchema.properties.state.description.includes(
      "generic fail-closed state",
    ),
  "expired roster edges must allow any inactive dependency without inventing provenance expiry",
);
const manualRosterProvenance = {
  grantedByUserId: "actor-id",
  sourceKind: "manual",
};
assert(
  acceptsConditionalRepresentation(rosterEntrySchema, {
    provenance: manualRosterProvenance,
    state: "active",
  }) &&
    acceptsConditionalRepresentation(rosterEntrySchema, {
      provenance: { ...manualRosterProvenance, retiredAt: "past" },
      state: "expired",
    }) &&
    acceptsConditionalRepresentation(rosterEntrySchema, {
      provenance: manualRosterProvenance,
      state: "expired",
    }) &&
    acceptsConditionalRepresentation(rosterEntrySchema, {
      provenance: manualRosterProvenance,
      revokeReason: "Roster rotation",
      revokedAt: "now",
      revokedByUserId: "actor-id",
      state: "revoked",
    }),
  "roster lifecycle fixtures must preserve active, generic dependency expiry, retired-source expiry, and complete revocation states",
);
assert(
  document.components.schemas.OperatorTeamRosterEntryCreateRequest.properties
    .membershipId !== undefined &&
    document.components.schemas.OperatorTeamRosterEntryCreateRequest.properties
      .userId === undefined,
  "roster writes must bind an exact tenant membership instead of a global user",
);

const edgeProvenance = document.components.schemas.AuthorizationEdgeProvenance;
for (const field of [
  "sourceKind",
  "sourceId",
  "authoritative",
  "grantedAt",
  "reason",
]) {
  assert(
    edgeProvenance.required.includes(field),
    `authorization edge provenance must require ${field}`,
  );
}
assert(
  edgeProvenance.properties.sourceType === undefined,
  "new independently owned edges must not conflate source origin with path type",
);
assert(
  edgeProvenance.properties.retiredAt !== undefined,
  "edge provenance must expose source retirement",
);
const effectiveEdgeProvenance =
  document.components.schemas.EffectiveAuthorizationEdgeProvenance;
assert(
  effectiveEdgeProvenance.additionalProperties === false &&
    effectiveEdgeProvenance.properties.retiredAt === undefined,
  "live authority edge provenance must structurally reject retiredAt",
);
const effectiveRoleProvenance =
  document.components.schemas.EffectiveRoleGrantProvenance;
assert(
  effectiveRoleProvenance.additionalProperties === false &&
    effectiveRoleProvenance.properties.retiredAt === undefined,
  "live role-grant provenance must structurally reject retiredAt",
);
const manualRoleSourceRule = effectiveRoleProvenance.allOf?.find(
  (rule) => rule.if?.properties?.sourceKind?.const === "manual",
);
const mappedRoleSourceRule = effectiveRoleProvenance.allOf?.find(
  (rule) => rule.if?.properties?.sourceKind?.const === "identity_mapping",
);
const systemRoleSourceRule = effectiveRoleProvenance.allOf?.find((rule) =>
  rule.if?.properties?.sourceKind?.enum?.includes("platform_recovery"),
);
exactValues(
  manualRoleSourceRule?.then?.properties?.sourceType?.enum,
  ["direct", "group"],
  "manual effective role provenance source types must remain path-scoped",
);
exactValues(
  mappedRoleSourceRule?.then?.properties?.sourceType?.enum,
  ["identity_provider", "group"],
  "identity-mapped effective role provenance source types must remain path-scoped",
);
exactValues(
  systemRoleSourceRule?.then?.properties?.sourceType?.enum,
  ["system", "group"],
  "system effective role provenance source types must remain path-scoped",
);
assert(
  document.components.schemas.RoleGrantProvenance.properties.retiredAt !==
    undefined,
  "historical role-grant provenance must preserve source retirement",
);
for (const [schemaName, manualProvenance, mappedProvenance] of [
  [
    "EffectiveAuthorizationEdgeProvenance",
    { sourceKind: "manual", grantedByUserId: "actor-id" },
    { sourceKind: "identity_mapping" },
  ],
  [
    "EffectiveRoleGrantProvenance",
    {
      sourceKind: "manual",
      sourceType: "direct",
      grantedByUserId: "actor-id",
    },
    { sourceKind: "identity_mapping", sourceType: "identity_provider" },
  ],
]) {
  const schema = document.components.schemas[schemaName];
  const manualOwnership = schema.allOf?.find(
    (rule) => rule.if?.properties?.sourceKind?.const === "manual",
  );
  assert(
    manualOwnership?.then?.required?.includes("grantedByUserId"),
    `${schemaName} must require the human grantor for manual live provenance`,
  );
  assert(
    acceptsConditionalRepresentation(schema, manualProvenance) &&
      acceptsConditionalRepresentation(schema, mappedProvenance),
    `${schemaName} rejected a valid live owner representation`,
  );
  const manualWithoutGrantor = { ...manualProvenance };
  delete manualWithoutGrantor.grantedByUserId;
  assert(
    !acceptsConditionalRepresentation(schema, manualWithoutGrantor),
    `${schemaName} accepted manual live provenance without a grantor`,
  );
}
for (const schemaName of [
  "DirectUserRoleGrant",
  "TenantSecurityGroupMembership",
  "TenantSecurityGroupRoleGrant",
]) {
  const schema = document.components.schemas[schemaName];
  assert(
    schema.properties.revokeReason?.$ref === "#/components/schemas/GrantReason",
    `${schemaName} must expose a bounded revoke reason`,
  );
  const lifecycle = schema.allOf?.find(
    (rule) => rule.if?.properties?.state?.const === "revoked",
  );
  assert(
    lifecycle?.then?.required?.includes("revokedAt") &&
      lifecycle.then.required.includes("revokedByUserId") &&
      lifecycle.then.required.includes("revokeReason"),
    `${schemaName} must require complete revocation history when revoked`,
  );
  const forbiddenUnlessRevoked = new Set(
    lifecycle?.else?.not?.anyOf?.flatMap((rule) => rule.required ?? []) ?? [],
  );
  for (const field of ["revokedAt", "revokedByUserId", "revokeReason"]) {
    assert(
      forbiddenUnlessRevoked.has(field),
      `${schemaName} must omit ${field} unless revoked`,
    );
  }
  const expiredLifecycle = schema.allOf?.find(
    (rule) => rule.if?.properties?.state?.const === "expired",
  );
  assert(
    expiredLifecycle?.then?.properties?.provenance?.required?.includes(
      "expiresAt",
    ),
    `${schemaName} must require provenance expiry when the edge is expired`,
  );
  const manualOwnership = schema.allOf?.find(
    (rule) =>
      rule.if?.properties?.provenance?.properties?.sourceKind?.const ===
      "manual",
  );
  assert(
    manualOwnership?.then?.properties?.provenance?.required?.includes(
      "grantedByUserId",
    ),
    `${schemaName} must require the human grantor for a manual-owned edge`,
  );
}

const directGrantSchema = document.components.schemas.DirectUserRoleGrant;
const directSourceRule = (sourceKind) =>
  directGrantSchema.allOf.find((rule) => {
    const sourceKindSchema =
      rule.if?.properties?.provenance?.properties?.sourceKind;
    return (
      sourceKindSchema?.const === sourceKind ||
      sourceKindSchema?.enum?.includes(sourceKind)
    );
  });
for (const [sourceKind, sourceType] of [
  ["manual", "direct"],
  ["identity_mapping", "identity_provider"],
  ["system", "system"],
  ["tenant_creation", "system"],
  ["platform_recovery", "system"],
]) {
  assert(
    directSourceRule(sourceKind)?.then?.properties?.provenance?.properties
      ?.sourceType?.const === sourceType,
    `direct role grants owned by ${sourceKind} must require sourceType=${sourceType}`,
  );
}

const manualDirectProvenance = {
  sourceKind: "manual",
  sourceType: "direct",
  grantedByUserId: "actor-id",
};
for (const provenance of [
  manualDirectProvenance,
  { sourceKind: "identity_mapping", sourceType: "identity_provider" },
  { sourceKind: "system", sourceType: "system" },
  { sourceKind: "tenant_creation", sourceType: "system" },
  { sourceKind: "platform_recovery", sourceType: "system" },
]) {
  assert(
    acceptsConditionalRepresentation(directGrantSchema, {
      provenance,
      state: "active",
    }),
    `valid direct role-grant owner ${provenance.sourceKind} was rejected`,
  );
}
assert(
  acceptsConditionalRepresentation(directGrantSchema, {
    provenance: { ...manualDirectProvenance, expiresAt: "future" },
    state: "expired",
  }),
  "a valid expired manual direct role grant was rejected",
);
assert(
  acceptsConditionalRepresentation(directGrantSchema, {
    provenance: manualDirectProvenance,
    revokeReason: "Access removed",
    revokedAt: "now",
    revokedByUserId: "actor-id",
    state: "revoked",
  }),
  "a valid revoked manual direct role grant was rejected",
);
for (const [name, value] of [
  [
    "expired without provenance expiry",
    { provenance: manualDirectProvenance, state: "expired" },
  ],
  [
    "manual without a grantor",
    {
      provenance: { sourceKind: "manual", sourceType: "direct" },
      state: "active",
    },
  ],
  [
    "manual with a system source type",
    {
      provenance: {
        ...manualDirectProvenance,
        sourceType: "system",
      },
      state: "active",
    },
  ],
  [
    "identity mapping with a direct source type",
    {
      provenance: { sourceKind: "identity_mapping", sourceType: "direct" },
      state: "active",
    },
  ],
  [
    "system owner with an identity-provider source type",
    {
      provenance: { sourceKind: "system", sourceType: "identity_provider" },
      state: "active",
    },
  ],
  [
    "tenant-creation owner with a direct source type",
    {
      provenance: { sourceKind: "tenant_creation", sourceType: "direct" },
      state: "active",
    },
  ],
  [
    "platform-recovery owner with a direct source type",
    {
      provenance: {
        sourceKind: "platform_recovery",
        sourceType: "direct",
      },
      state: "active",
    },
  ],
  [
    "active with revocation history",
    {
      provenance: manualDirectProvenance,
      revokeReason: "Access removed",
      revokedAt: "now",
      revokedByUserId: "actor-id",
      state: "active",
    },
  ],
  [
    "revoked without a reason",
    {
      provenance: manualDirectProvenance,
      revokedAt: "now",
      revokedByUserId: "actor-id",
      state: "revoked",
    },
  ],
]) {
  assert(
    !acceptsConditionalRepresentation(directGrantSchema, value),
    `invalid direct role grant passed conditional validation: ${name}`,
  );
}

for (const schemaName of [
  "TenantSecurityGroupMembership",
  "TenantSecurityGroupRoleGrant",
]) {
  const schema = document.components.schemas[schemaName];
  const manualProvenance = {
    sourceKind: "manual",
    grantedByUserId: "actor-id",
  };
  for (const value of [
    { provenance: manualProvenance, state: "active" },
    {
      provenance: { ...manualProvenance, expiresAt: "past" },
      state: "expired",
    },
    { provenance: { sourceKind: "identity_mapping" }, state: "active" },
    {
      provenance: manualProvenance,
      revokeReason: "Access removed",
      revokedAt: "now",
      revokedByUserId: "actor-id",
      state: "revoked",
    },
  ]) {
    assert(
      acceptsConditionalRepresentation(schema, value),
      `${schemaName} rejected a valid owner/lifecycle representation`,
    );
  }
  for (const [name, value] of [
    [
      "expired without provenance expiry",
      { provenance: manualProvenance, state: "expired" },
    ],
    [
      "manual without a grantor",
      { provenance: { sourceKind: "manual" }, state: "active" },
    ],
  ]) {
    assert(
      !acceptsConditionalRepresentation(schema, value),
      `${schemaName} accepted ${name}`,
    );
  }
}
const effectivePath =
  document.components.schemas.EffectiveTenantRoleAuthorityPath;
exactValues(
  effectivePath.oneOf.map((branch) => branch.$ref),
  [
    "#/components/schemas/DirectEffectiveTenantRoleAuthorityPath",
    "#/components/schemas/GroupEffectiveTenantRoleAuthorityPath",
  ],
  "effective authority must be an exact direct-or-group union",
);
assert(
  effectivePath.discriminator?.propertyName === "pathType",
  "effective authority must discriminate on pathType",
);
exactValues(
  effectivePath.discriminator.mapping,
  {
    direct: "#/components/schemas/DirectEffectiveTenantRoleAuthorityPath",
    group: "#/components/schemas/GroupEffectiveTenantRoleAuthorityPath",
  },
  "effective authority discriminator mappings must remain explicit",
);
for (const [schemaName, pathType, branchName] of [
  ["DirectEffectiveTenantRoleAuthorityPath", "direct", "direct"],
  ["GroupEffectiveTenantRoleAuthorityPath", "group", "group"],
]) {
  const branch = document.components.schemas[schemaName];
  exactValues(
    branch.required,
    ["pathType", branchName],
    `${schemaName} must require its discriminator and payload branch`,
  );
  assert(
    branch.additionalProperties === false &&
      branch.properties.pathType.const === pathType &&
      Object.keys(branch.properties).length === 2 &&
      branch.properties[branchName] !== undefined,
    `${schemaName} must reject missing, opposite, and combined authority branches`,
  );
}
assert(
  document.components.schemas.GroupTenantRoleAuthorityPath.properties
    .membershipEdge !== undefined &&
    document.components.schemas.GroupTenantRoleAuthorityPath.properties
      .roleGrantEdge !== undefined,
  "group authority must preserve both independently owned edges",
);
assert(
  document.components.schemas.DirectTenantRoleAuthorityPath.properties
    .provenance.$ref === "#/components/schemas/EffectiveRoleGrantProvenance" &&
    document.components.schemas.TenantSecurityGroupMembershipPathEdge.properties
      .provenance.$ref ===
      "#/components/schemas/EffectiveAuthorizationEdgeProvenance" &&
    document.components.schemas.TenantSecurityGroupRoleGrantPathEdge.properties
      .provenance.$ref ===
      "#/components/schemas/EffectiveAuthorizationEdgeProvenance" &&
    document.components.schemas.EffectiveTenantRoleGrant.properties.provenance
      .$ref === "#/components/schemas/EffectiveRoleGrantProvenance",
  "every live direct and group authority provenance projection must exclude retired sources",
);
assert(
  document.components.schemas.EffectiveTenantRoleGrant.properties
    .effectiveExpiresAt !== undefined,
  "effective group authority must expose its exact path expiry",
);

const effectiveGrantSchema =
  document.components.schemas.EffectiveTenantRoleGrant;
const contractGrantId = "0198c97d-cf4f-7000-8000-000000000101";
const contractRoleId = "0198c97d-cf4f-7000-8000-000000000102";
const contractActorId = "0198c97d-cf4f-7000-8000-000000000103";
const contractMembershipEdgeId = "0198c97d-cf4f-7000-8000-000000000104";
const contractMembershipSourceId = "0198c97d-cf4f-7000-8000-000000000105";
const effectiveProvenanceBase = {
  authoritative: false,
  grantedAt: "2026-08-23T10:00:00Z",
  reason: "Contract fixture",
  sourceId: contractGrantId,
};
const directEffectiveProvenanceFixtures = [
  [
    "manual/direct",
    {
      ...effectiveProvenanceBase,
      grantedByUserId: contractActorId,
      sourceKind: "manual",
      sourceType: "direct",
    },
  ],
  [
    "identity_mapping/identity_provider",
    {
      ...effectiveProvenanceBase,
      sourceKind: "identity_mapping",
      sourceType: "identity_provider",
    },
  ],
  ...["system", "tenant_creation", "platform_recovery"].map((sourceKind) => [
    `${sourceKind}/system`,
    {
      ...effectiveProvenanceBase,
      sourceKind,
      sourceType: "system",
    },
  ]),
];
const groupMembershipProvenanceFixture = {
  authoritative: false,
  grantedAt: "2026-08-22T10:00:00Z",
  grantedByUserId: contractActorId,
  reason: "Membership fixture",
  sourceId: contractMembershipSourceId,
  sourceKind: "manual",
};
const withoutSourceType = (provenance) => {
  const edge = { ...provenance };
  delete edge.sourceType;
  return edge;
};
const withoutProperty = (value, property) => {
  const copy = { ...value };
  delete copy[property];
  return copy;
};
const directEffectiveGrantFixture = (
  provenance,
  nestedProvenance = provenance,
) => ({
  grantId: contractGrantId,
  path: {
    direct: {
      grantId: contractGrantId,
      provenance: nestedProvenance,
    },
    pathType: "direct",
  },
  provenance,
  roleId: contractRoleId,
  roleKey: "contract_role",
  roleName: "Contract role",
});
const groupEffectiveGrantFixture = (provenance) => ({
  grantId: contractGrantId,
  path: {
    group: {
      group: {
        id: "0198c97d-cf4f-7000-8000-000000000106",
        key: "contract_group",
        name: "Contract group",
      },
      membershipEdge: {
        id: contractMembershipEdgeId,
        provenance: groupMembershipProvenanceFixture,
      },
      roleGrantEdge: {
        id: contractGrantId,
        provenance: withoutSourceType(provenance),
      },
    },
    pathType: "group",
  },
  provenance,
  roleId: contractRoleId,
  roleKey: "contract_role",
  roleName: "Contract role",
});

for (const [label, provenance] of directEffectiveProvenanceFixtures) {
  assert(
    schemaMatchesRepresentation(
      effectiveGrantSchema,
      directEffectiveGrantFixture(provenance),
    ),
    `effective grant schema rejected valid direct ${label} provenance`,
  );
  assert(
    schemaMatchesRepresentation(
      effectiveGrantSchema,
      groupEffectiveGrantFixture({ ...provenance, sourceType: "group" }),
    ),
    `effective grant schema rejected valid group ${label} provenance`,
  );
}

const validManualEffectiveProvenance = directEffectiveProvenanceFixtures[0][1];
const invalidEffectiveGrantFixtures = [
  [
    "manual/system direct provenance",
    directEffectiveGrantFixture({
      ...validManualEffectiveProvenance,
      sourceType: "system",
    }),
  ],
  [
    "manual direct provenance without a grantor",
    directEffectiveGrantFixture(
      withoutProperty(validManualEffectiveProvenance, "grantedByUserId"),
    ),
  ],
  [
    "identity_mapping/direct provenance",
    directEffectiveGrantFixture({
      ...effectiveProvenanceBase,
      sourceKind: "identity_mapping",
      sourceType: "direct",
    }),
  ],
  [
    "system/identity_provider provenance",
    directEffectiveGrantFixture({
      ...effectiveProvenanceBase,
      sourceKind: "system",
      sourceType: "identity_provider",
    }),
  ],
  [
    "group provenance in a direct top-level projection",
    directEffectiveGrantFixture(
      { ...validManualEffectiveProvenance, sourceType: "group" },
      validManualEffectiveProvenance,
    ),
  ],
  [
    "group provenance in a nested direct projection",
    directEffectiveGrantFixture(validManualEffectiveProvenance, {
      ...validManualEffectiveProvenance,
      sourceType: "group",
    }),
  ],
  [
    "non-group provenance in a group top-level projection",
    groupEffectiveGrantFixture(validManualEffectiveProvenance),
  ],
  [
    "manual group provenance without a grantor",
    groupEffectiveGrantFixture({
      ...withoutProperty(validManualEffectiveProvenance, "grantedByUserId"),
      sourceType: "group",
    }),
  ],
];
for (const [label, fixture] of invalidEffectiveGrantFixtures) {
  assert(
    !schemaMatchesRepresentation(effectiveGrantSchema, fixture),
    `effective grant schema accepted ${label}`,
  );
}
assert(
  document.components.schemas.DirectUserRoleGrant.required.includes("pathType"),
  "direct role-grant resources must remain unambiguous to revoke",
);

const paginated = [
  operation("/api/v1/tenants/{tenantId}/permissions", "get"),
  operation("/api/v1/tenants/{tenantId}/roles", "get"),
  operation("/api/v1/tenants/{tenantId}/users", "get"),
  operation("/api/v1/tenants/{tenantId}/users/{userId}/role-grants", "get"),
  operation("/api/v1/tenants/{tenantId}/groups", "get"),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}/memberships", "get"),
  operation("/api/v1/tenants/{tenantId}/groups/{groupId}/role-grants", "get"),
];
for (const value of paginated) {
  const refs = parameterRefs(value);
  assert(
    refs.has("#/components/parameters/AfterCursor"),
    `${value.operationId} lacks cursor pagination`,
  );
  assert(
    refs.has("#/components/parameters/PageSize"),
    `${value.operationId} lacks bounded page size`,
  );
}

const serviceAccountBasePath = "/api/v1/tenants/{tenantId}/service-accounts";
const serviceAccountPath = `${serviceAccountBasePath}/{serviceAccountId}`;
const serviceAccountRoleGrantsPath = `${serviceAccountPath}/role-grants`;
const serviceAccountRoleGrantRevokePath = `${serviceAccountRoleGrantsPath}/{grantId}/revoke`;
const serviceAccountCredentialsPath = `${serviceAccountPath}/credentials`;
const serviceAccountCredentialPath = `${serviceAccountCredentialsPath}/{credentialId}`;
const serviceAccountCredentialRevokePath = `${serviceAccountCredentialPath}/revoke`;
const serviceAccountCredentialRotatePath = `${serviceAccountCredentialPath}/rotate`;
const tenantAlertsPath = "/api/v1/tenants/{tenantId}/alerts";

const serviceAccountBearer =
  document.components.securitySchemes.serviceAccountBearer;
assert(
  serviceAccountBearer?.type === "http" &&
    serviceAccountBearer.scheme === "bearer",
  "serviceAccountBearer must be an HTTP bearer security scheme",
);

const servicePrincipalAdminOperations = [
  [
    serviceAccountBasePath,
    "get",
    "listTenantServiceAccounts",
    "service_account.read",
  ],
  [
    serviceAccountBasePath,
    "post",
    "createTenantServiceAccount",
    "service_account.manage",
  ],
  [
    serviceAccountPath,
    "get",
    "getTenantServiceAccount",
    "service_account.read",
  ],
  [
    serviceAccountPath,
    "patch",
    "updateTenantServiceAccount",
    "service_account.manage",
  ],
  [
    serviceAccountPath,
    "delete",
    "archiveTenantServiceAccount",
    "service_account.manage",
  ],
  [
    serviceAccountRoleGrantsPath,
    "get",
    "listTenantServiceAccountRoleGrants",
    "service_account.read",
  ],
  [
    serviceAccountRoleGrantsPath,
    "post",
    "grantTenantServiceAccountRole",
    "service_account.manage",
  ],
  [
    serviceAccountRoleGrantRevokePath,
    "post",
    "revokeTenantServiceAccountRoleGrant",
    "service_account.manage",
  ],
  [
    serviceAccountCredentialsPath,
    "get",
    "listTenantServiceAccountCredentials",
    "service_account.read",
  ],
  [
    serviceAccountCredentialsPath,
    "post",
    "issueTenantServiceAccountCredential",
    "service_account.credential.manage",
  ],
  [
    serviceAccountCredentialPath,
    "get",
    "getTenantServiceAccountCredential",
    "service_account.read",
  ],
  [
    serviceAccountCredentialRevokePath,
    "post",
    "revokeTenantServiceAccountCredential",
    "service_account.credential.manage",
  ],
  [
    serviceAccountCredentialRotatePath,
    "post",
    "rotateTenantServiceAccountCredential",
    "service_account.credential.manage",
  ],
];

for (const [
  path,
  method,
  operationId,
  permission,
] of servicePrincipalAdminOperations) {
  const value = operation(path, method);
  assert(
    value.operationId === operationId,
    `${operationId} operationId drifted`,
  );
  assert(
    value.security?.length === 1 &&
      value.security[0].sessionCookie !== undefined &&
      value.security[0].serviceAccountBearer === undefined,
    `${operationId} must be human-cookie-only`,
  );
  if (["post", "patch", "put", "delete"].includes(method)) {
    assert(
      value.security[0].csrfToken !== undefined,
      `${operationId} must require CSRF with its cookie credential`,
    );
  } else {
    assert(
      value.security[0].csrfToken === undefined,
      `${operationId} must not require CSRF for a safe read`,
    );
  }
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === permission,
    `${operationId} tenant authorization metadata drifted`,
  );
  exactValues(
    authorization.scopes,
    ["tenant"],
    `${operationId} must require exact tenant scope`,
  );
  exactValues(
    authorization.principalTypes,
    ["human"],
    `${operationId} must remain human-admin-only`,
  );
}

for (const value of [
  operation(serviceAccountRoleGrantsPath, "post"),
  operation(serviceAccountRoleGrantRevokePath, "post"),
]) {
  exactValues(
    value["x-periapsis-authorization"].additionalPermissions,
    ["role.grant"],
    `${value.operationId} must additionally require role.grant`,
  );
}

for (const value of [
  operation(serviceAccountBasePath, "get"),
  operation(serviceAccountRoleGrantsPath, "get"),
  operation(serviceAccountCredentialsPath, "get"),
]) {
  const refs = parameterRefs(value);
  assert(
    refs.has("#/components/parameters/AfterCursor") &&
      refs.has("#/components/parameters/PageSize"),
    `${value.operationId} must use bounded cursor pagination`,
  );
}

const servicePrincipalIdempotentMutations = [
  operation(serviceAccountCredentialsPath, "post"),
  operation(serviceAccountCredentialRotatePath, "post"),
  operation(tenantAlertsPath, "post"),
];
for (const value of servicePrincipalIdempotentMutations) {
  assert(
    parameterRefs(value).has("#/components/parameters/IdempotencyKey"),
    `${value.operationId} must require exactly one Idempotency-Key`,
  );
}
for (const value of [
  operation(serviceAccountBasePath, "post"),
  operation(serviceAccountRoleGrantsPath, "post"),
]) {
  assert(
    !parameterRefs(value).has("#/components/parameters/IdempotencyKey"),
    `${value.operationId} must not promise unsupported command idempotency`,
  );
}

for (const value of [
  operation(serviceAccountPath, "patch"),
  operation(serviceAccountPath, "delete"),
  operation(serviceAccountCredentialRevokePath, "post"),
  operation(serviceAccountCredentialRotatePath, "post"),
]) {
  assert(
    parameterRefs(value).has("#/components/parameters/IfMatch") &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must require strong If-Match with 412 and 428`,
  );
}
const serviceAccountGrantRevoke = operation(
  serviceAccountRoleGrantRevokePath,
  "post",
);
assert(
  parameterRefs(serviceAccountGrantRevoke).has(
    "#/components/parameters/EdgeIfMatch",
  ) &&
    serviceAccountGrantRevoke.responses["412"] !== undefined &&
    serviceAccountGrantRevoke.responses["428"] !== undefined,
  "service-account role-grant revoke must require representation-bound If-Match",
);

const tenantAlertCreate = operation(tenantAlertsPath, "post");
exactValues(
  tenantAlertCreate.security,
  [{ sessionCookie: [], csrfToken: [] }, { serviceAccountBearer: [] }],
  "Alert create must express cookie-plus-CSRF OR bearer authentication",
);
const tenantAlertAuthorization = tenantAlertCreate["x-periapsis-authorization"];
assert(
  tenantAlertAuthorization?.tenantContext === "path" &&
    tenantAlertAuthorization.activeMembership === true &&
    tenantAlertAuthorization.authenticatedServiceAccount === true &&
    tenantAlertAuthorization.permission === "alert.create",
  "Alert create tenant authority metadata drifted",
);
exactValues(
  tenantAlertAuthorization.scopes,
  ["tenant"],
  "Alert create must require exact tenant scope",
);
exactValues(
  tenantAlertAuthorization.principalTypes,
  ["human", "service_account"],
  "Alert create must accept only human and service-account principals",
);
assert(
  tenantAlertCreate.responses["201"]?.content?.["application/json"]?.schema
    ?.$ref === "#/components/schemas/Alert",
  "Alert create must return the bounded Alert representation",
);

const oneTimeCredentialMutations = [
  operation(serviceAccountCredentialsPath, "post"),
  operation(serviceAccountCredentialRotatePath, "post"),
];
for (const value of oneTimeCredentialMutations) {
  for (const status of ["201", "409"]) {
    assert(
      value.responses[status]?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
      `${value.operationId} ${status} must emit Cache-Control: no-store`,
    );
  }
  assert(
    value.responses["201"].content["application/json"].schema.$ref ===
      "#/components/schemas/ServiceAccountCredentialSecret",
    `${value.operationId} 201 must use the distinct secret-bearing schema`,
  );
  const replayProblemSchema =
    value.responses["409"].content["application/problem+json"].schema;
  assert(
    replayProblemSchema.oneOf === undefined &&
      Array.isArray(replayProblemSchema.anyOf),
    `${value.operationId} 409 must use overlap-safe anyOf branches`,
  );
  exactValues(
    replayProblemSchema.anyOf.map((branch) => branch.$ref),
    [
      "#/components/schemas/OneTimeSecretAlreadyIssuedProblem",
      "#/components/schemas/Problem",
    ],
    `${value.operationId} 409 must distinguish one-time replay from payload drift`,
  );
}

const credentialMetadata = document.components.schemas.ServiceAccountCredential;
const serviceAccountRoleGrant =
  document.components.schemas.ServiceAccountRoleGrant;
assert(
  serviceAccountRoleGrant.required.includes("managedByServiceAccountApi") &&
    serviceAccountRoleGrant.properties.managedByServiceAccountApi.type ===
      "boolean",
  "service-account role grants must expose fail-closed API ownership",
);
const expiredServiceAccountGrantLifecycle = serviceAccountRoleGrant.allOf?.find(
  (rule) => rule.if?.properties?.state?.const === "expired",
);
assert(
  expiredServiceAccountGrantLifecycle === undefined &&
    serviceAccountRoleGrant.properties.state.description.includes(
      "generic fail-closed state",
    ) &&
    acceptsConditionalRepresentation(serviceAccountRoleGrant, {
      provenance: {
        retiredAt: "past",
        sourceKind: "identity_mapping",
      },
      state: "expired",
    }),
  "expired service-account grants must allow any inactive dependency without inventing provenance expiry",
);
const forbiddenCredentialMetadataFields = [
  "bearerToken",
  "token",
  "secret",
  "secretDigest",
  "locator",
];
for (const field of forbiddenCredentialMetadataFields) {
  assert(
    credentialMetadata.properties[field] === undefined,
    `redacted credential metadata must omit ${field}`,
  );
}
for (const value of [
  operation(serviceAccountCredentialsPath, "get"),
  operation(serviceAccountCredentialPath, "get"),
  operation(serviceAccountBasePath, "get"),
  operation(serviceAccountPath, "get"),
]) {
  const serialized = JSON.stringify(value.responses["200"]);
  assert(
    !serialized.includes("ServiceAccountCredentialSecret") &&
      !serialized.includes("ServiceAccountBearerToken"),
    `${value.operationId} must not reference a secret-bearing schema`,
  );
}
const credentialSecret =
  document.components.schemas.ServiceAccountCredentialSecret;
assert(
  credentialSecret.additionalProperties === false &&
    credentialSecret.properties.credential.$ref ===
      "#/components/schemas/ServiceAccountCredential" &&
    credentialSecret.properties.bearerToken.$ref ===
      "#/components/schemas/ServiceAccountBearerToken",
  "one-time credential response must separate metadata from bearer material",
);
assert(
  document.components.schemas.OneTimeSecretAlreadyIssuedProblem.properties.code
    .const === "one_time_secret_already_issued" &&
    document.components.schemas.OneTimeSecretAlreadyIssuedProblem.properties
      .bearerToken === undefined,
  "one-time replay Problem must identify metadata without returning the token",
);

for (const schemaName of [
  "ServiceAccount",
  "ServiceAccountList",
  "ServiceAccountCreateRequest",
  "ServiceAccountPatchRequest",
  "ServiceAccountArchiveRequest",
  "ServiceAccountRoleReference",
  "ServiceAccountRoleGrant",
  "ServiceAccountRoleGrantList",
  "ServiceAccountRoleGrantRequest",
  "ServiceAccountRoleGrantRevokeRequest",
  "ServiceAccountCredentialPermissionGrant",
  "ServiceAccountCredential",
  "ServiceAccountCredentialList",
  "ServiceAccountCredentialIssueRequest",
  "ServiceAccountCredentialRotateRequest",
  "ServiceAccountCredentialRevokeRequest",
  "ServiceAccountCredentialSecret",
  "OneTimeSecretAlreadyIssuedProblem",
  "AlertCreateRequest",
  "HumanAlertCreator",
  "ServiceAccountAlertCreator",
  "Alert",
]) {
  assert(
    document.components.schemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown properties`,
  );
}
exactValues(
  document.components.schemas.ServiceAccountCredentialPermissionKey.const,
  "alert.create",
  "credential permission must be the exact machine allowlist",
);
exactValues(
  document.components.schemas.ServiceAccountCredentialScope.const,
  "tenant",
  "credential scope must be exact",
);
const credentialExpiry =
  document.components.schemas.ServiceAccountCredentialExpiry;
assert(
  credentialExpiry["x-periapsis-maximum-lifetime-seconds"] === 7_776_000 &&
    (credentialExpiry.description ?? "").includes("90 days"),
  "credential expiry must be capped at 90 days",
);
const credentialCidr = document.components.schemas.ServiceAccountCredentialCidr;
assert(
  credentialCidr.format === "cidr" &&
    credentialCidr.maxLength === 43 &&
    credentialCidr.pattern !== undefined,
  "credential networks must use a bounded canonical CIDR schema",
);
assert(
  document.components.schemas.ServiceAccountCredentialIssueRequest.properties
    .permissions.maxItems === 1 &&
    document.components.schemas.ServiceAccountCredentialIssueRequest.properties
      .allowedNetworks.maxItems === 32,
  "credential issue allowlists must remain bounded",
);
const credentialNetworkOrder = "PostgreSQL cidr order";
assert(
  document.components.schemas.ServiceAccountCredential.properties.allowedNetworks.description.includes(
    credentialNetworkOrder,
  ),
  "credential projections must declare PostgreSQL cidr ordering",
);
for (const schemaName of [
  "ServiceAccountCredentialIssueRequest",
  "ServiceAccountCredentialRotateRequest",
]) {
  const description =
    document.components.schemas[schemaName].properties.allowedNetworks
      .description ?? "";
  assert(
    description.includes(credentialNetworkOrder) &&
      description.includes("before idempotency binding"),
    `${schemaName} must normalize networks before idempotency binding`,
  );
}
assert(
  document.components.schemas.AlertCreateRequest.additionalProperties ===
    false &&
    document.components.schemas.AlertCreateRequest.properties.title
      .maxLength === 240 &&
    document.components.schemas.AlertCreateRequest.properties.description
      .maxLength === 10_000 &&
    document.components.schemas.AlertCreateRequest.properties.externalId
      .maxLength === 200,
  "minimal Alert command fields must remain bounded",
);
exactValues(
  document.components.schemas.AlertStatus.enum,
  ["new", "in_progress", "closed"],
  "Alert representations must expose every current lifecycle status",
);
assert(
  document.components.schemas.Alert.properties.status.$ref ===
    "#/components/schemas/AlertStatus",
  "Alert status must use the shared lifecycle schema",
);
const alertReplayDescription =
  tenantAlertCreate.responses["201"]?.description ?? "";
assert(
  alertReplayDescription.includes("same resource's current representation") &&
    alertReplayDescription.includes("current strong ETag") &&
    alertReplayDescription.includes("never undoes later mutations"),
  "Alert create must specify non-restorative current-resource replay semantics",
);
for (const schemaName of ["TenantRole", "TenantRoleSummary"]) {
  assert(
    document.components.schemas[schemaName].required.includes(
      "principalKind",
    ) &&
      document.components.schemas[schemaName].properties.principalKind.$ref ===
        "#/components/schemas/TenantPrincipalType",
    `${schemaName} must expose enforced principal kind`,
  );
}

const permissionPrincipalRule =
  document.components.schemas.TenantPermission.allOf?.find(
    (rule) => rule.if?.properties?.key?.const === "alert.create",
  );
exactValues(
  permissionPrincipalRule?.then?.properties?.principalTypes?.const,
  ["human", "service_account"],
  "alert.create catalog projection must allow both principal kinds",
);
exactValues(
  permissionPrincipalRule?.else?.properties?.principalTypes?.const,
  ["human"],
  "every non-alert.create catalog projection must remain human-only",
);
assert(
  (tenantAlertCreate.description ?? "").includes(
    "Supplying both authentication mechanisms",
  ) &&
    (tenantAlertCreate.description ?? "").includes(
      "comma-folded bearer credentials is rejected",
    ),
  "Alert create must reject ambiguous or simultaneous credentials",
);

const resolvedResponse = (response) => {
  if (response?.$ref === undefined) return response;
  const prefix = "#/components/responses/";
  assert(
    response.$ref.startsWith(prefix),
    `unsupported response reference ${response.$ref}`,
  );
  return document.components.responses[response.$ref.slice(prefix.length)];
};
const problemSchemaRefs = (response) => {
  const schema =
    resolvedResponse(response)?.content?.["application/problem+json"]?.schema;
  if (schema?.$ref !== undefined) return [schema.$ref];
  return [...(schema?.oneOf ?? []), ...(schema?.anyOf ?? [])].map(
    (branch) => branch.$ref,
  );
};
const ldapProvidersPath = "/api/v1/tenants/{tenantId}/auth-providers";
const ldapProviderPath = `${ldapProvidersPath}/{providerId}`;
const ldapBindSecretPath = `${ldapProviderPath}/bind-secret`;
const ldapOperations = [
  [ldapProvidersPath, "get"],
  [ldapProvidersPath, "post"],
  [ldapProviderPath, "get"],
  [ldapProviderPath, "put"],
  [ldapProviderPath, "delete"],
  [ldapBindSecretPath, "put"],
  [ldapBindSecretPath, "delete"],
  [`${ldapProviderPath}/tests/connection`, "post"],
  [`${ldapProviderPath}/tests/bind`, "post"],
];
const ldapUpdate = operation(ldapProviderPath, "put");
const ldapCreate = operation(ldapProvidersPath, "post");
assert(
  document.paths[ldapProviderPath].patch === undefined,
  "LDAP provider update must not expose a partial PATCH ABI",
);
assert(
  ldapUpdate.requestBody?.required === true &&
    ldapUpdate.requestBody.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/TenantLDAPAuthProviderUpdateRequest",
  "LDAP provider update must atomically replace the complete mutable document",
);
assert(
  parameterRefs(ldapCreate).has(
    "#/components/parameters/LDAPProviderIdempotencyKey",
  ) && !parameterRefs(ldapCreate).has("#/components/parameters/IdempotencyKey"),
  "LDAP provider create must use Location-only replay semantics",
);
const ldapCreateResponse = ldapCreate.responses["201"];
assert(
  ldapCreateResponse.content === undefined &&
    ldapCreateResponse.headers?.ETag === undefined &&
    ldapCreateResponse.headers?.Location?.$ref ===
      "#/components/headers/ResourceLocation",
  "LDAP provider create must return only Location and no current representation or ETag",
);
const ldapUpdateResponse = ldapUpdate.responses["204"];
assert(
  ldapUpdate.responses["200"] === undefined &&
    ldapUpdateResponse.content === undefined &&
    ldapUpdateResponse.headers?.ETag?.$ref ===
      "#/components/headers/StrongETag",
  "LDAP provider replacement must return 204 with the new strong ETag",
);
const ldapUpdateSchema =
  document.components.schemas.TenantLDAPAuthProviderUpdateRequest;
exactValues(
  ldapUpdateSchema.required,
  [
    "key",
    "displayName",
    "description",
    "enabled",
    "configuration",
    "endpoints",
  ],
  "LDAP provider update required fields must remain exact",
);
exactValues(
  Object.keys(ldapUpdateSchema.properties),
  [
    "key",
    "displayName",
    "description",
    "enabled",
    "configuration",
    "endpoints",
  ],
  "LDAP provider update fields must remain mass-assignment closed",
);
const ldapConfiguration =
  document.components.schemas.TenantLDAPAuthProviderConfiguration;
assert(
  ldapConfiguration.required.length === 39 &&
    Object.keys(ldapConfiguration.properties).length === 39,
  "LDAP configuration must remain an exact 39-field document",
);
const ldapEndpoint = document.components.schemas.TenantLDAPAuthProviderEndpoint;
assert(
  ldapEndpoint.required.length === 7 &&
    Object.keys(ldapEndpoint.properties).length === 7,
  "LDAP endpoint must remain an exact 7-field document",
);
assert(
  document.components.schemas.TenantLDAPBindSecretWriteRequest.properties.secret
    .writeOnly === true,
  "LDAP bind secret must remain write-only",
);
const ldapDiagnostic =
  document.components.schemas.TenantLDAPAuthProviderDiagnostic;
const ldapDiagnosticBranches = ldapDiagnostic.oneOf;
assert(
  ldapDiagnosticBranches.length === 4 &&
    ldapDiagnosticBranches[0].properties.outcome.const === "success" &&
    ldapDiagnosticBranches[0].properties.category.const === "success" &&
    ldapDiagnosticBranches[0].properties.endpointPriority.type === "integer" &&
    ldapDiagnosticBranches[0].properties.stale.const === false &&
    ldapDiagnosticBranches[1].properties.outcome.const === "inconclusive" &&
    ldapDiagnosticBranches[1].properties.category.const ===
      "stale_configuration" &&
    ldapDiagnosticBranches[1].properties.stale.const === true &&
    Array.isArray(ldapDiagnosticBranches[1].properties.endpointPriority.type) &&
    ldapDiagnosticBranches[1].properties.endpointPriority.type.includes(
      "integer",
    ) &&
    ldapDiagnosticBranches[1].properties.endpointPriority.type.includes(
      "null",
    ) &&
    ldapDiagnosticBranches[2].properties.outcome.const === "failure" &&
    ldapDiagnosticBranches[2].properties.category.const === "cancelled" &&
    ldapDiagnosticBranches[2].properties.endpointPriority.type === "null" &&
    ldapDiagnosticBranches[2].properties.stale.const === false &&
    ldapDiagnosticBranches[3].properties.outcome.const === "failure" &&
    ldapDiagnosticBranches[3].properties.endpointPriority.type === "integer" &&
    ldapDiagnosticBranches[3].properties.stale.const === false,
  "LDAP diagnostic branches must remain non-contradictory and preserve bounded stale snapshot attribution",
);
for (const [path, method] of ldapOperations) {
  const value = operation(path, method);
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    assert(
      resolvedResponse(response)?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
      `${value.operationId} ${status} must emit Cache-Control: no-store`,
    );
    if (Number(status) < 400) continue;
    exactValues(
      problemSchemaRefs(response),
      ["#/components/schemas/Problem"],
      `${value.operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
}
for (const [path, method, operationId] of servicePrincipalAdminOperations) {
  const value = operation(path, method);
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) < 400) continue;
    const refs = problemSchemaRefs(response);
    assert(
      refs.length > 0 &&
        refs.every((reference) =>
          [
            "#/components/schemas/Problem",
            "#/components/schemas/OneTimeSecretAlreadyIssuedProblem",
          ].includes(reference),
        ),
      `${operationId} ${status} must use a bounded RFC 9457 Problem Detail`,
    );
  }
}
for (const [status, response] of Object.entries(
  tenantAlertCreate.responses ?? {},
)) {
  if (Number(status) < 400) continue;
  exactValues(
    problemSchemaRefs(response),
    ["#/components/schemas/Problem"],
    `createTenantAlert ${status} must use RFC 9457 Problem Details`,
  );
}
