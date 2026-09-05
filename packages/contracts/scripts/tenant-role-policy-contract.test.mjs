import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { validateMediaTypeExample } from "./api-example-support.mjs";

const document = JSON.parse(
  readFileSync(
    new URL(
      "../../../services/api/internal/contract/openapi.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const schemas = document.components.schemas;
const tuples = schemas.TenantPermissionKey.enum.flatMap((permissionKey) =>
  schemas.TenantAuthorizationScope.enum.map((scope) => ({
    permissionKey,
    scope,
  })),
);
const validate = (schema, value, kind = "response") =>
  validateMediaTypeExample(document, { schema }, kind, value);
const policy = (count) => ({
  permissions: tuples.slice(0, count),
  delegationCeiling: tuples.slice(0, count),
});

test("role responses separate stored policies from custom-role write policies", () => {
  assert.equal(
    schemas.TenantRole.properties.policy.$ref,
    "#/components/schemas/TenantRoleReadPolicy",
  );
  assert.equal(
    schemas.TenantRoleCreateRequest.properties.policy.$ref,
    "#/components/schemas/TenantRolePolicy",
  );
  assert.equal(
    document.paths["/api/v1/tenants/{tenantId}/roles/{roleId}/policy"].put
      .requestBody.content["application/json"].schema.$ref,
    "#/components/schemas/TenantRolePolicy",
  );
});

test("built-in role policy reads accept all 176 administrator tuples", () => {
  assert.equal(policy(176).permissions.length, 176);
  assert.equal(
    validate(schemas.TenantRole.properties.policy, policy(176)).valid,
    true,
  );
});

test("custom-role creation and replacement keep the 100-tuple write limit", () => {
  for (const schema of [
    schemas.TenantRoleCreateRequest.properties.policy,
    document.paths["/api/v1/tenants/{tenantId}/roles/{roleId}/policy"].put
      .requestBody.content["application/json"].schema,
  ]) {
    assert.equal(validate(schema, policy(100), "request").valid, true);
    for (const field of ["permissions", "delegationCeiling"]) {
      const oversized = { ...policy(100), [field]: tuples.slice(0, 101) };
      const result = validate(schema, oversized, "request");
      assert.equal(result.valid, false);
      assert.ok(
        result.errors.some(
          (error) =>
            error.keyword === "maxItems" && error.instancePath === `/${field}`,
        ),
      );
    }
  }
});

test("stored role and effective authority arrays remain bounded at 500 unique tuples", () => {
  for (const schemaName of ["TenantRoleReadPolicy", "TenantAuthority"]) {
    for (const field of ["permissions", "delegationCeiling"]) {
      const schema = schemas[schemaName].properties[field];
      assert.equal(schema.maxItems, 500);
      assert.equal(schema.uniqueItems, true);
      assert.equal(validate(schema, tuples.slice(0, 176)).valid, true);
      assert.equal(validate(schema, [tuples[0], tuples[0]]).valid, false);
      const result = validate(
        schema,
        Array.from(
          { length: 501 },
          (_, index) => tuples[index % tuples.length],
        ),
      );
      assert.equal(result.valid, false);
      assert.ok(
        result.errors.some(
          (error) => error.keyword === "maxItems" && error.params.limit === 500,
        ),
      );
    }
  }
});
