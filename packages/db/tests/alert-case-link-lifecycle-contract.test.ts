import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const read = (path: string): string =>
  readFileSync(resolve(repositoryRoot, path), "utf8");
const schema = read("packages/db/src/schema/ticketing.ts");
const migration = read(
  "packages/db/migrations/0217_alert_case_link_lifecycle.sql",
);
const ticketingRepository = read(
  "services/api/internal/postgres/ticketing_repository.go",
);
const dfirRepository = read(
  "services/api/internal/postgres/dfir_repository.go",
);
const dfirWorkspace = read(
  "services/api/internal/postgres/dfir_repository_workspace.go",
);
const dfirCaseSubject = read(
  "services/api/internal/postgres/dfir_repository_case_subject.go",
);
const dfirAttachmentMapping = read(
  "services/api/internal/postgres/dfir_repository_mapping.go",
);

function functionBody(name: string): string {
  const marker = `CREATE FUNCTION app.${name}`;
  const start = migration.indexOf(marker);
  if (start < 0) throw new Error(`missing lifecycle function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated lifecycle function ${name}`);
  return migration.slice(start, end);
}

describe("Alert Case link lifecycle contract", () => {
  it("models immutable tenant-scoped retractions against one exact link tuple", () => {
    expect(schema).toContain('"alert_case_link_retractions"');
    expect(schema).toContain('unique("alert_case_links_identity_key").on(');
    expect(schema).toContain(
      'name: "alert_case_link_retractions_link_identity_fk"',
    );
    expect(migration).toContain(
      "REFERENCES public.alert_case_links(tenant_id, id, alert_id, case_id)",
    );
    expect(migration).toContain(
      "ALTER TABLE public.alert_case_link_retractions FORCE ROW LEVEL SECURITY",
    );
    expect(migration).toContain(
      "CREATE TRIGGER alert_case_link_retractions_immutable_v1",
    );
    expect(migration).toContain("app.guard_ticketing_append_only_v1()");
  });

  it("commits a two-aggregate CAS only after live authority and pair locks", () => {
    const body = functionBody("commit_tenant_alert_case_unlink_v1");
    const authority = body.indexOf(
      "PERFORM app.lock_current_tenant_authorization_state()",
    );
    const alertLock = body.indexOf("FROM public.alerts AS alert", authority);
    const caseLock = body.indexOf("FROM public.cases AS case_row", alertLock);
    const linkLock = body.indexOf(
      "FROM public.alert_case_links AS link",
      caseLock,
    );
    const retraction = body.indexOf(
      "INSERT INTO public.alert_case_link_retractions",
      linkLock,
    );
    expect(authority).toBeGreaterThan(0);
    expect(alertLock).toBeGreaterThan(authority);
    expect(caseLock).toBeGreaterThan(alertLock);
    expect(linkLock).toBeGreaterThan(caseLock);
    expect(retraction).toBeGreaterThan(linkLock);
    expect(body.match(/FOR UPDATE/g)).toHaveLength(3);
    expect(body).toContain("'alert.escalate'");
    expect(body).toContain("'case.update'");
    expect(body).toContain("alert.version = p_expected_alert_version");
    expect(body).toContain("case_row.version = p_expected_case_version");
    expect(body).toContain("'ticket.unlink'");
    expect(body.match(/private_append_ticket_side_effects_v1/g)).toHaveLength(
      2,
    );
    expect(body).not.toMatch(
      /(?:UPDATE|DELETE\s+FROM)\s+public\.alert_case_links/i,
    );
  });

  it("reauthorizes exact replays and makes one retraction terminal", () => {
    const replay = functionBody("lookup_tenant_alert_case_unlink_replay_v1");
    for (const invariant of [
      "app.lock_current_tenant_authorization_state()",
      "app.current_tenant_membership_id()",
      "'alert.escalate'",
      "'case.update'",
      "request_digest IS DISTINCT FROM p_request_digest",
      "result_metadata IS DISTINCT FROM jsonb_build_object",
      "source_alert.version < retraction.result_alert_version",
      "target_case.version < retraction.result_case_version",
    ]) {
      expect(replay).toContain(invariant);
    }
    expect(migration).toContain(
      "CONSTRAINT alert_case_link_retractions_pair_key\n    UNIQUE (tenant_id, alert_id, case_id)",
    );
    expect(migration).toContain("Alert/Case link retraction is terminal");
  });

  it("removes retracted links from every live projection but preserves copies", () => {
    expect(ticketingRepository).toContain(
      "FROM public.alert_case_link_retractions AS retraction",
    );
    expect(dfirRepository).toContain(
      "resolveDFIRCaseSubject(ctx, tx, tenantID, caseUUID, subject)",
    );
    const alertSubject = dfirCaseSubject.slice(
      dfirCaseSubject.indexOf("case kernel.EntityAlert:"),
      dfirCaseSubject.indexOf(
        "\n\tdefault:",
        dfirCaseSubject.indexOf("case kernel.EntityAlert:"),
      ),
    );
    expect(alertSubject).toContain(
      "link.tenant_id = $1 AND link.case_id = $2 AND link.alert_id = $3",
    );
    expect(alertSubject).toMatch(
      /AND NOT EXISTS \([\s\S]*?FROM public\.alert_case_link_retractions AS retraction/,
    );
    expect(alertSubject).toContain(
      "retraction.tenant_id = link.tenant_id AND retraction.link_id = link.id",
    );
    expect(dfirWorkspace).toContain(
      "FROM public.alert_case_link_retractions AS retraction",
    );
    expect(dfirWorkspace).toContain(
      "FROM public.dfir_attachment_case_links AS copied",
    );
    expect(dfirAttachmentMapping).toContain(
      "resolveDFIRCaseSubject(ctx, tx, tenantID, rootID, subject)",
    );
    expect(dfirAttachmentMapping).toContain(
      "link.tenant_id = $1 AND link.attachment_id = $2 AND link.case_id = $3",
    );
    const belongs = migration.slice(
      migration.indexOf(
        "CREATE OR REPLACE FUNCTION app.private_dfir_resource_belongs_to_case_v1",
      ),
      migration.indexOf("$function$;", migration.indexOf("CREATE OR REPLACE")),
    );
    expect(belongs).toContain("alert_case_link_retractions AS retraction");
    expect(belongs).toContain("dfir_attachment_case_links AS copied");
  });
});
