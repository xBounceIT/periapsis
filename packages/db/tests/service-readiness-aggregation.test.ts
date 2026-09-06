import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectedAPIRuntimeReadinessV52SourceHash,
  expectedWorkerRuntimeReadinessV52SourceHash,
} from "../src/admin/schema-compatibility-manifest.gen.js";

const root = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    root,
    "packages/db/migrations/0234_service_readiness_aggregation.sql",
  ),
  "utf8",
);
const cases = [
  {
    service: "api",
    hash: expectedAPIRuntimeReadinessV52SourceHash,
    size: 8,
    leaves: [
      "platform_local_account_runtime_schema_readiness_v1",
      "ticket_bulk_runtime_schema_readiness_v2",
      "ticket_export_runtime_schema_readiness_v2",
      "ticket_metadata_runtime_schema_readiness_v1",
    ],
    releaseSlots: 4,
  },
  {
    service: "worker",
    hash: expectedWorkerRuntimeReadinessV52SourceHash,
    size: 5,
    leaves: [
      "private_sla_system_principal_catalog_ready_v1",
      "sla_object_event_ingress_schema_readiness_v1",
      "ticket_bulk_runtime_schema_readiness_v2",
      "ticket_export_runtime_schema_readiness_v2",
    ],
    releaseSlots: 1,
  },
] as const;

describe("service readiness aggregation", () => {
  for (const { service, hash, size, leaves, releaseSlots } of cases) {
    const name = `${service}_runtime_schema_readiness_v52`;
    const definition = new RegExp(
      `CREATE FUNCTION app\\.${name}\\(\\)([\\s\\S]*?)AS \\$function\\$([\\s\\S]*?)\\$function\\$;([\\s\\S]*?)--> statement-breakpoint`,
      "u",
    ).exec(migration);

    it(`${service} has an exact source-attested, role-only stable boolean-array ABI`, () => {
      expect(definition).not.toBeNull();
      const declaration = definition![1]!.replace(/\s+/gu, " ").trim();
      expect(declaration).toBe(
        "RETURNS boolean[] LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,app",
      );
      expect(createHash("sha256").update(definition![2]!).digest("hex")).toBe(
        hash,
      );
      expect(definition![3]!.replace(/\s+/gu, " ").trim()).toBe(
        `ALTER FUNCTION app.${name}() OWNER TO periapsis_migrator; REVOKE ALL ON FUNCTION app.${name}() FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor; GRANT EXECUTE ON FUNCTION app.${name}() TO periapsis_migrator,periapsis_${service};`,
      );
    });

    it(`${service} evaluates the release exactly once and preserves every ordered live-data leaf`, () => {
      const body = definition![2]!;
      expect(
        [...body.matchAll(/app\.([a-z_0-9]+)\(\)/gu)].map((match) => match[1]),
      ).toEqual(["release_runtime_schema_readiness_v52", ...leaves]);
      expect(body).toContain(
        "release_ready := app.release_runtime_schema_readiness_v52();",
      );
      const returns = [
        ...body.matchAll(/RETURN ARRAY\[([\s\S]*?)\]::boolean\[\];/gu),
      ];
      expect(returns).toHaveLength(3);
      expect(returns[0]![1]!.split(",")).toEqual(
        Array<string>(size).fill("false"),
      );
      expect(returns[2]![1]).toBe(returns[0]![1]);
      expect(returns[1]![1]!.replace(/\s+/gu, "")).toBe(
        [
          ...Array<string>(releaseSlots).fill("true"),
          ...leaves.map((leaf) => `coalesce(app.${leaf}(),false)`),
        ].join(","),
      );
      expect(body).toContain("IF release_ready IS DISTINCT FROM true THEN");
      expect(body.replace(/\s+/gu, " ")).toContain(
        "WHEN undefined_table OR undefined_function OR insufficient_privilege OR invalid_schema_name OR cardinality_violation OR data_exception THEN",
      );
      expect(body).not.toMatch(
        /WHEN OTHERS|query_canceled|set_config|SET LOCAL|EXECUTE |INSERT |UPDATE |DELETE |CREATE |verify_identity_keyring/iu,
      );
    });

    it(`${service} stays inside the full transcript and has an independently attested serving call`, () => {
      const seal = readFileSync(
        resolve(root, "packages/db/migrations/0235_v52_compatibility.sql"),
        "utf8",
      );
      const exclusions =
        /self_excluded_function\(function_oid\) AS \(([\s\S]*?)\n\),/u.exec(
          seal,
        )?.[1];
      expect(exclusions).toBeDefined();
      expect(exclusions).not.toContain(name);
      const health = readFileSync(
        resolve(root, `services/${service}/internal/postgres/health.go`),
        "utf8",
      );
      expect(health).toContain(`app.${name}() AS array`);
      expect(health.replace(/\s+/gu, " ")).toContain(
        `'${service}_aggregate', 'app.${name}()', 'plpgsql', array['search_path=pg_catalog, public, app']::text[], 'boolean[]'`,
      );
      if (service === "worker") {
        expect(health).toContain(
          "app.verify_identity_keyring_v3($1::integer[], $2::bytea[], $3::integer)",
        );
      }
    });
  }
});
